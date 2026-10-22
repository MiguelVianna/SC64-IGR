#!/usr/bin/env python3
"""Gera a candidata IGR V21 R2 para N64FlashcartMenu 0.3.5 (L + R + START).

Uso: python -I build_igr.py <menu_original.n64> <saida.n64> [--diag | --bt-no-igr]

O que faz (patch binario, sem recompilar o menu):
  1. Descomprime o segmento principal (LZ4) do ELF do menu.
  2. Patches no codigo do menu (boot()/cheats_install inline):
     - 0x8002910C: desvio p/ STUB (instala o motor mesmo sem cheats, se houver Expansion Pak,
       e copia o bloco IGR para 0x807C0000).
     - 0x80029BC0: o motor termina em "j 0x807C0000" (IGR) em vez de "j 0x80000120".
     - 0x800A9F08 / 0x800AA094: inicio do heap 0x800DAC48 -> 0x800DF800 (STUB/cave).
     - Mantem CIC-6101 v16/perfis v17; v20 amplia o mecanismo WatchLo para outra organizacao de compilador.
  3. STUB + bloco IGR vao num segmento ELF novo em 0x800DAD00.
  4. Recomprime (LZ4), remonta o ELF e a TOC (move o .sym se precisar).
O bloco IGR roda dentro do jogo, a cada excecao, usando so k0/k1.
"""
import hashlib
import os
import struct
import sys

# Allow the documented isolated invocation (-I) to load this sibling library.
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

# ---------------------------------------------------------------- montador minimo
REG = {n: i for i, n in enumerate(
    "zero at v0 v1 a0 a1 a2 a3 t0 t1 t2 t3 t4 t5 t6 t7 s0 s1 s2 s3 s4 s5 s6 s7 t8 t9 k0 k1 gp sp fp ra".split())}


class Asm:
    def __init__(self, base):
        self.base = base
        self.items = []  # (kind, payload)
        self.labels = {}

    def here(self):
        return self.base + 4 * len(self.items)

    def label(self, name):
        assert name not in self.labels, name
        self.labels[name] = self.here()

    def word(self, w):
        self.items.append(("w", w & 0xFFFFFFFF))

    def i(self, op, rs, rt, imm):
        self.word((op << 26) | (REG[rs] << 21) | (REG[rt] << 16) | (imm & 0xFFFF))

    def r(self, rs, rt, rd, sa, fn):
        self.word((REG[rs] << 21) | (REG[rt] << 16) | (REG[rd] << 11) | (sa << 6) | fn)

    # instrucoes
    def nop(self): self.word(0)
    def lui(self, rt, imm): self.i(0x0F, "zero", rt, imm)
    def addiu(self, rt, rs, imm): self.i(0x09, rs, rt, imm)
    def ori(self, rt, rs, imm): self.i(0x0D, rs, rt, imm)
    def andi(self, rt, rs, imm): self.i(0x0C, rs, rt, imm)
    def xori(self, rt, rs, imm): self.i(0x0E, rs, rt, imm)
    def sltiu(self, rt, rs, imm): self.i(0x0B, rs, rt, imm)
    def lw(self, rt, off, rs): self.i(0x23, rs, rt, off)
    def sw(self, rt, off, rs): self.i(0x2B, rs, rt, off)
    def srl(self, rd, rt, sa): self.r("zero", rt, rd, sa, 0x02)
    def sll(self, rd, rt, sa): self.r("zero", rt, rd, sa, 0x00)
    def or_(self, rd, rs, rt): self.r(rs, rt, rd, 0, 0x25)
    def and_(self, rd, rs, rt): self.r(rs, rt, rd, 0, 0x24)
    def addu(self, rd, rs, rt): self.r(rs, rt, rd, 0, 0x21)
    def subu(self, rd, rs, rt): self.r(rs, rt, rd, 0, 0x23)
    def sltu(self, rd, rs, rt): self.r(rs, rt, rd, 0, 0x2B)

    def lw_l(self, rt, lab, rs): self.items.append(("m", (0x23, rs, rt, lab)))   # offset = lab - base
    def sw_l(self, rt, lab, rs): self.items.append(("m", (0x2B, rs, rt, lab)))
    def ld_l(self, rt, lab, rs): self.items.append(("m", (0x37, rs, rt, lab)))   # 64 bits
    def sd_l(self, rt, lab, rs): self.items.append(("m", (0x3F, rs, rt, lab)))
    def jal(self, target): self.items.append(("jal", target))
    def cache_l(self, op, lab, rs): self.items.append(("mc", (op, rs, lab)))
    def jr(self, rs): self.r(rs, "zero", "zero", 0, 0x08)
    def cache(self, op, off, rs): self.word((0x2F << 26) | (REG[rs] << 21) | (op << 16) | (off & 0xFFFF))
    def mtc0(self, rt, rd): self.word(0x40800000 | (REG[rt] << 16) | (rd << 11))
    def ctc1(self, rt, fs): self.word(0x44C00000 | (REG[rt] << 16) | (fs << 11))

    def li(self, rt, val):
        val &= 0xFFFFFFFF
        if val < 0x10000:
            self.ori(rt, "zero", val)
        else:
            self.lui(rt, val >> 16)
            if val & 0xFFFF:
                self.ori(rt, rt, val & 0xFFFF)

    def j(self, target):
        self.items.append(("j", target))

    def beq(self, rs, rt, lab): self.items.append(("b", (0x04, rs, rt, lab)))
    def bne(self, rs, rt, lab): self.items.append(("b", (0x05, rs, rt, lab)))

    def build(self):
        out = []
        for idx, (k, p) in enumerate(self.items):
            pc = self.base + 4 * idx
            if k == "w":
                out.append(p)
            elif k in ("j", "jal"):
                t = self.labels[p] if isinstance(p, str) else p
                assert (t & 0xF0000000) == (pc & 0xF0000000) and t % 4 == 0
                out.append(((0x02 if k == "j" else 0x03) << 26) | ((t >> 2) & 0x03FFFFFF))
            elif k == "mc":
                op, rs, lab = p
                off = self.labels[lab] - self.base
                assert 0 <= off < 0x8000
                out.append((0x2F << 26) | (REG[rs] << 21) | (op << 16) | off)
            elif k == "m":
                op, rs, rt, lab = p
                off = self.labels[lab] - self.base
                assert 0 <= off < 0x8000
                out.append((op << 26) | (REG[rs] << 21) | (REG[rt] << 16) | off)
            else:
                op, rs, rt, lab = p
                off = (self.labels[lab] - (pc + 4)) >> 2
                assert -0x8000 <= off < 0x8000
                out.append((op << 26) | (REG[rs] << 21) | (REG[rt] << 16) | (off & 0xFFFF))
        return b"".join(struct.pack(">I", w) for w in out)


# ---------------------------------------------------------------- constantes
IMG_BASE = 0x80000400
IGR_ADDR = 0x807C0000          # bloco IGR (perto do motor de cheats padrao 0x807C5C00)
CAVE = 0x800DAD00              # segmento novo (apos o bss 0x800DAC48)
HEAP_START = 0x800DF800        # V21 R2: +2 KiB own cave; menu heap only
IGR_THRESH = 100               # quadros (VI) com L+R+START (~1,7 s NTSC, ~2 s PAL)
IGR_RELEASE = 20               # quadros seguidos SEM o combo para zerar a contagem (~1/3 s)
PAINT_DELAY = 37500000         # diag: ~0,8 s por cor (Count = 46,875 MHz)
ADDR_PATCHER_JR = (0x80029D18, 0x80029D20)   # lui v0,0x0120 / addiu v0,v0,8 -> "jr t1" final do patcher
# v16: the stock 0.3.5 CIC-6101 case checks IPL3+0x748, but the uploaded US
# Star Fox boot has jr t1 at +0x770. Reuse the existing guarded +0x770 case.
# All IGR runtime bytes, addresses and other CIC table entries stay as in v15.
ADDR_CIC6101_CASE = 0x800ACB1C
CIC6101_CASE_OLD = 0x800295D4
CIC6101_CASE_FIXED = 0x80029A28
# v5/v6 tinham um scanner que trocava "mtc0 WatchLo" por nop: removido (nao ajudava o RE2, que
# desliga o WatchLo ANTES de instalar os vetores). v8: "prep" desvia o modelo de excecao da libultra.
USE_PREP = True                # v10: prep so para PREP_IDS (v8 aplicava a todos os nao-Rare)
# jogos que desligam o WatchLo antes dos vetores (motor nunca entra): RE2 (confirmado no codigo),
# Star Fox 64 e Chameleon Twist (sem motor nos testes; codigos CL/CT por garantia).
PREP_IDS = ("RE", "FX", "CL", "CT", "O7")   # v10 HW: Chameleon Twist passou a funcionar; O7 = TWINE
RDPBUF_LEN = 0x108             # 64 NOPs (completam comando pela metade) + SYNC_FULL
# jogos da Rare (codigo de 2 letras no cabecalho 0x3C): conferem o proprio codigo -> sem prep
RARE_IDS = ("GE", "BK", "B7", "DY", "FU", "DO", "JF", "PD", "BC", "KI")

ADDR_HOOK = 0x8002910C         # beq v0,zero,0x80029308 (cheat_list == NULL)
ADDR_CONT = 0x80029114         # segue o caminho original (tabela de CIC)
ADDR_NOCHEATS = 0x80029308     # caminho "sem cheats"
ADDR_ENGINE_J = 0x80029BC0     # addiu t0,t0,0x48 (forma "j 0x80000120")
ADDR_SBRK = (0x800A9F08, 0x800AA094)   # addiu v0,v0,0xAC48 (end = 0x800DAC48)


def build_igr_block_v1():
    """v1 (2026-10-20) - FALHOU no N64: RE2/Star Fox/DKR nao detectam, 007/ISS/Banjo tela preta.
    Mantida so como referencia; o gerador usa build_igr_block (v2)."""
    a = Asm(IGR_ADDR)
    # --- checagem, executada a cada excecao do jogo
    a.lui("k0", 0xA480)
    a.lw("k0", 0x0018, "k0")          # SI_STATUS
    a.andi("k0", "k0", 0x0003)        # DMA/IO ocupado?
    a.bne("k0", "zero", "out")
    a.lui("k1", 0xBFC0)               # (delay)
    a.lw("k0", 0x07C0, "k1")          # PIF RAM canal 0: FF 01 04 01 (leitura do controle libultra, sem erro)
    a.lui("k1", 0xFF01)
    a.ori("k1", "k1", 0x0401)
    a.bne("k0", "k1", "out")
    a.lui("k1", 0xBFC0)               # (delay)
    a.lw("k0", 0x07C4, "k1")          # botoes(16) | X | Y
    a.srl("k0", "k0", 16)
    a.andi("k1", "k0", 0x0070)        # bit 0x40 sempre 0 num controle real (rejeita 0xFFFF)
    a.xori("k1", "k1", 0x0030)        # L (0x20) e R (0x10)
    a.bne("k1", "zero", "miss")
    a.andi("k1", "k0", 0x1080)        # (delay) START (0x1000) ou RST (0x80, L+R+START no controle)
    a.beq("k1", "zero", "miss")
    a.lui("k0", 0xA430)               # (delay)
    a.lw("k0", 0x0008, "k0")          # MI_INTR
    a.andi("k0", "k0", 0x0008)        # conta 1x por quadro (interrupcao de VI pendente)
    a.beq("k0", "zero", "out")
    a.lui("k0", IGR_ADDR >> 16)       # (delay)
    cnt_fix = len(a.items)            # lw k1,CNT(k0) - offset preenchido depois
    a.word(0)
    a.addiu("k1", "k1", 1)
    cnt_fix2 = len(a.items)           # sw k1,CNT(k0)
    a.word(0)
    a.sltiu("k1", "k1", IGR_THRESH)
    a.bne("k1", "zero", "out")
    a.nop()
    a.j("reboot")
    a.nop()
    a.label("miss")
    a.lui("k0", IGR_ADDR >> 16)
    cnt_fix3 = len(a.items)           # sw zero,CNT(k0)
    a.word(0)
    a.label("out")
    a.j(0x80000120)                   # handler do jogo (realocado pelo motor)
    a.nop()

    # --- reinicio pelo bootloader do SC64 (equivale ao RESET do console)
    a.label("reboot")
    a.mtc0("zero", 18)                # WatchLo = 0
    a.lui("t0", 0x3400)               # CU1|CU0|FR, sem EXL/IE
    a.mtc0("t0", 12)
    a.nop()
    a.lui("t0", 0xA430)
    a.ori("t1", "zero", 0x0555)
    a.sw("t1", 0x000C, "t0")          # MI_MASK: desliga todas
    a.lui("t0", 0xA460)               # PI
    pi_wait_n = [0]

    def pi_wait():
        lab = "piw%d" % pi_wait_n[0]
        pi_wait_n[0] += 1
        a.label(lab)
        a.lw("t1", 0x0010, "t0")
        a.andi("t1", "t1", 0x0003)
        a.bne("t1", "zero", lab)
        a.nop()

    pi_wait()
    # RSP: halt + limpa estados (como boot.c)
    a.lui("t2", 0xA404)
    a.li("t1", 0x00AAAAAE)            # CLR_SIG0..7|CLR_INTR_BREAK|CLR_SSTEP|CLR_INTR|CLR_BROKE|SET_HALT
    a.sw("t1", 0x0010, "t2")
    a.sw("zero", 0x001C, "t2")        # SEMAPHORE
    a.lui("t3", 0xA408)
    a.sw("zero", 0x0000, "t3")        # SP_PC
    a.label("spdma")
    a.lw("t1", 0x0018, "t2")          # SP_DMA_BUSY
    a.bne("t1", "zero", "spdma")
    a.nop()
    a.ori("t1", "zero", 0x0003)
    a.sw("t1", 0x0010, "t0")          # PI: reset + clr intr
    # VI apagado (como boot.c)
    a.lui("t2", 0xA440)
    for off in range(0x00, 0x38, 4):
        if off == 0x0C:
            a.ori("t1", "zero", 0x03FF)
            a.sw("t1", off, "t2")
        else:
            a.sw("zero", off, "t2")
    a.lui("t2", 0xA450)
    a.sw("zero", 0x0000, "t2")        # AI_DRAM_ADDR
    a.sw("zero", 0x0004, "t2")        # AI_LEN
    # SC64: destrava, BOOT_MODE=0 (menu), BOOTLOADER_SWITCH=1, trava
    a.lui("t3", 0xBFFF)
    for val in (0x00000000, 0x5F554E4C, 0x4F434B5F):
        pi_wait()
        a.li("t1", val)
        a.sw("t1", 0x0010, "t3")      # KEY
    pi_wait()
    a.lw("t1", 0x000C, "t3")          # IDENTIFIER
    a.li("t4", 0x53437632)            # "SCv2"
    a.bne("t1", "t4", "nosc64")
    a.nop()
    cmd_n = [0]

    def sc64_cfg(cfg_id, value):
        pi_wait()
        a.ori("t1", "zero", cfg_id)
        a.sw("t1", 0x0004, "t3")      # DATA0
        pi_wait()
        a.ori("t1", "zero", value)
        a.sw("t1", 0x0008, "t3")      # DATA1
        pi_wait()
        a.ori("t1", "zero", 0x43)     # 'C' = CONFIG_SET
        a.sw("t1", 0x0000, "t3")      # SCR
        lab = "cmdw%d" % cmd_n[0]
        cmd_n[0] += 1
        pi_wait()
        a.label(lab)
        a.lw("t1", 0x0000, "t3")
        a.lui("t4", 0x8000)
        a.r("t1", "t4", "t1", 0, 0x24)  # and t1,t1,t4 (CMD_BUSY)
        a.bne("t1", "zero", lab)
        a.nop()

    sc64_cfg(5, 0)                    # BOOT_MODE = menu
    sc64_cfg(0, 1)                    # BOOTLOADER_SWITCH = 1
    pi_wait()
    a.li("t1", 0xFFFFFFFF)
    a.sw("t1", 0x0010, "t3")          # KEY = trava (estado de reset)
    a.label("nosc64")
    pi_wait()
    # PI DOM1 lento, depois o do cabecalho (como boot.c)
    for off, val in ((0x14, 0xFF), (0x18, 0xFF), (0x1C, 0x0F), (0x20, 0x03)):
        a.ori("t1", "zero", val)
        a.sw("t1", off, "t0")
    a.lui("t3", 0xB000)
    a.lw("t5", 0x0000, "t3")
    a.sw("t5", 0x0014, "t0")
    a.srl("t1", "t5", 8)
    a.sw("t1", 0x0018, "t0")
    a.srl("t1", "t5", 16)
    a.sw("t1", 0x001C, "t0")
    a.srl("t1", "t5", 20)
    a.sw("t1", 0x0020, "t0")
    # RDP em modo XBUS: espera esvaziar (como boot.c)
    a.lui("t2", 0xA410)
    a.lw("t1", 0x000C, "t2")
    a.andi("t1", "t1", 0x0001)
    a.beq("t1", "zero", "noxbus")
    a.nop()
    a.label("xbusw")
    a.lw("t1", 0x000C, "t2")
    a.andi("t1", "t1", 0x0020)
    a.bne("t1", "zero", "xbusw")
    a.nop()
    a.label("noxbus")
    # IPL3 do bootloader -> DMEM
    a.addiu("t3", "t3", 0x0040)       # 0xB0000040
    a.lui("t4", 0xA400)
    a.addiu("t4", "t4", 0x0040)
    a.lui("t5", 0xA400)
    a.addiu("t5", "t5", 0x1000)
    a.label("ipl3cp")
    a.lw("t1", 0x0000, "t3")
    a.sw("t1", 0x0000, "t4")
    a.addiu("t3", "t3", 4)
    a.addiu("t4", "t4", 4)
    a.bne("t4", "t5", "ipl3cp")
    a.nop()
    # registros de boot (como reboot.S), reset_type = NMI (igual ao botao RESET)
    a.lui("t0", 0x8000)
    a.lw("s4", 0x0300, "t0")          # osTvType do jogo
    a.andi("s4", "s4", 0x0003)
    a.ori("s3", "zero", 0)            # boot device = ROM
    a.ori("s5", "zero", 1)            # NMI
    a.ori("s6", "zero", 0x3F)         # seed 6102 (bootloader)
    a.li("ra", 0xA4001554)
    a.ori("s7", "zero", 6)            # PAL
    a.beq("s4", "zero", "regs")
    a.ori("t1", "zero", 1)            # (delay)
    a.li("ra", 0xA4001554)
    a.ori("s7", "zero", 4)            # MPAL
    a.bne("s4", "t1", "regs")
    a.nop()
    a.li("ra", 0xA4001550)
    a.ori("s7", "zero", 1)            # NTSC
    a.label("regs")
    a.ctc1("zero", 31)
    a.li("sp", 0xA4001FF0)
    for rn in ("at", "v0", "v1", "a0", "a1", "a2", "a3", "t0", "t1", "t4", "t5", "t6", "t7",
               "s0", "s1", "s2", "t8", "t9", "k0", "k1", "gp", "fp"):
        a.ori(rn, "zero", 0)
    a.ori("t2", "zero", 0x40)
    a.li("t3", 0xA4000040)
    a.jr("t3")
    a.nop()
    # dados
    while (a.here() & 0xF) != 0:
        a.word(0)
    a.label("CNT")
    a.word(0)
    a.word(0)
    a.word(0)
    a.word(0)
    code = bytearray(a.build())
    cnt_off = a.labels["CNT"] - IGR_ADDR
    assert cnt_off < 0x8000
    for idx, w in ((cnt_fix, 0x8F5B0000), (cnt_fix2, 0xAF5B0000), (cnt_fix3, 0xAF400000)):
        # lw k1,CNT(k0) / sw k1,CNT(k0) / sw zero,CNT(k0)
        struct.pack_into(">I", code, 4 * idx, w | cnt_off)
    return bytes(code)


# cores de diagnostico pintadas no framebuffer do jogo (RGBA5551 par, RGBA8888)
COR_BRANCO = (0xFFFFFFFF, 0xFFFFFFFF)     # combo detectado (antes de mexer em qualquer coisa)
COR_CIANO = (0x07FF07FF, 0x00FFFFFF)      # RDP parado
COR_VERMELHO = (0xF801F801, 0xFF0000FF)   # RSP/PI parados, interrupcoes limpas
COR_AMARELO = (0xFFC1FFC1, 0xFFFF00FF)    # SC64 destravado e identificado
COR_VERDE = (0x07C107C1, 0x00FF00FF)      # SC64 aceitou BOOT_MODE e BOOTLOADER_SWITCH
COR_MAGENTA = (0xF83FF83F, 0xFF00FFFF)    # SC64 nao respondeu / erro de comando
COR_AZUL = (0x003F003F, 0x0000FFFF)       # IPL3 do bootloader copiado, saltando


def build_igr_block(debug=False):
    """v6. Bloco copiado para IGR_ADDR. debug=True: quadradinho de estado + cores lentas.

    Checagem (a cada excecao do jogo, so k0/k1):
      - se a PIF RAM tem uma RESPOSTA valida do controle 1 (cabecalho FF010401 e bit 0x40 = 0),
        guarda os botoes em LAST (jogos que ja deixam o proximo pedido 0xFFFF na PIF RAM
        nao zeram mais o contador);
      - 1x por quadro (VI pendente) avalia LAST: L+R+(START ou RST) -> CNT++, senao CNT = 0.
    Reinicio: para RDP/RSP, limpa interrupcoes pendentes, mantem o video ligado e pinta
    cores de diagnostico; esperas com limite.
    """
    a = Asm(IGR_ADDR)
    # ---------------- entrada A (fim do motor de cheats). Se o modelo de excecao do jogo foi
    # desviado para a entrada B (TPLFLAG), a checagem acontece la: aqui so segue para o jogo.
    a.lui("k0", IGR_ADDR >> 16)
    a.lw_l("k0", "TPLFLAG", "k0")
    a.beq("k0", "zero", "entryB")
    a.nop()
    a.j(0x80000120)
    a.nop()
    # ---------------- entrada B (modelo de excecao do jogo desviado) / checagem
    a.label("entryB")
    a.lui("k0", 0xA480)
    a.lw("k0", 0x0018, "k0")          # SI_STATUS
    a.andi("k0", "k0", 0x0003)        # DMA/IO ocupado?
    a.bne("k0", "zero", "vi")
    a.lui("k1", 0xBFC0)               # (delay)
    a.lw("k0", 0x07C0, "k1")          # canal 0: FF 01 04 01
    a.lui("k1", 0xFF01)
    a.ori("k1", "k1", 0x0401)
    a.bne("k0", "k1", "vi")
    a.lui("k1", 0xBFC0)               # (delay)
    a.lw("k0", 0x07C4, "k1")
    a.srl("k0", "k0", 16)             # botoes
    a.andi("k1", "k0", 0x0040)        # 1 = pedido ainda nao respondido (0xFFFF)
    a.bne("k1", "zero", "vi")
    a.lui("k1", IGR_ADDR >> 16)       # (delay)
    a.sw_l("k0", "LAST", "k1")
    a.label("vi")
    a.lui("k0", 0xA430)
    a.lw("k0", 0x0008, "k0")          # MI_INTR
    a.andi("k0", "k0", 0x0008)        # VI pendente -> 1x por quadro
    a.beq("k0", "zero", "out")
    a.lui("k0", IGR_ADDR >> 16)       # (delay)
    # salva t0..t5 em 64 bits (sw/lw corrompia jogos com contas de 64 bits: DKR 1.1 travava)
    for k, rn in enumerate(("t0", "t1", "t2", "t3", "t4", "t5")):
        a.sd_l(rn, "SAVE%d" % k, "k0")
    a.lw_l("t0", "LAST", "k0")
    a.andi("t1", "t0", 0x0070)
    a.xori("t1", "t1", 0x0030)        # L e R, bit 0x40 = 0
    a.bne("t1", "zero", "miss")
    a.andi("t1", "t0", 0x1080)        # (delay) START ou RST
    a.beq("t1", "zero", "miss")
    a.nop()
    a.sw_l("zero", "MISSRUN", "k0")   # combo: HIT++, zera a sequencia de falhas
    a.lw_l("t1", "HIT", "k0")
    a.addiu("t1", "t1", 1)
    a.sw_l("t1", "HIT", "k0")
    a.sltiu("t1", "t1", IGR_THRESH)
    a.bne("t1", "zero", "mark")
    a.nop()
    a.j("reboot")                     # nao precisa devolver registros
    a.nop()
    a.label("miss")                   # sem combo: so zera HIT apos IGR_RELEASE quadros seguidos
    a.lw_l("t1", "MISSRUN", "k0")
    a.addiu("t1", "t1", 1)
    a.sw_l("t1", "MISSRUN", "k0")
    a.sltiu("t1", "t1", IGR_RELEASE)
    a.bne("t1", "zero", "mark")
    a.nop()
    a.sw_l("zero", "HIT", "k0")
    a.label("mark")
    if debug:
        # quadradinho no canto: vermelho = motor roda mas nunca viu o controle;
        # amarelo = le o controle; ciano = L+R; verde = L+R+START (contando)
        a.li("t4", 0xF801F801); a.li("t5", 0xFF0000FF)
        a.ori("t1", "zero", 0x0040)
        a.beq("t0", "t1", "picked")
        a.nop()
        a.li("t4", 0xFFC1FFC1); a.li("t5", 0xFFFF00FF)
        a.andi("t1", "t0", 0x0030)
        a.xori("t1", "t1", 0x0030)
        a.bne("t1", "zero", "picked")
        a.nop()
        a.li("t4", 0x07FF07FF); a.li("t5", 0x00FFFFFF)
        a.andi("t1", "t0", 0x1080)
        a.beq("t1", "zero", "picked")
        a.nop()
        a.li("t4", 0x07C107C1); a.li("t5", 0x00FF00FF)
        a.label("picked")
        a.lui("k1", 0xA440)
        a.lw("t1", 0x0000, "k1")      # VI_CTRL
        a.andi("t1", "t1", 0x0003)
        a.lw("t2", 0x0004, "k1")      # VI_ORIGIN
        a.li("t3", 0x00FFFFFC)
        a.and_("t2", "t2", "t3")
        a.beq("t2", "zero", "restore")
        a.lui("t3", 0xA000)
        a.or_("t2", "t2", "t3")
        a.lw("t3", 0x0008, "k1")      # VI_WIDTH
        a.andi("t3", "t3", 0x0FFF)
        a.beq("t3", "zero", "restore")
        a.ori("k1", "zero", 2)
        a.beq("t1", "k1", "d16")
        a.ori("k1", "zero", 3)
        a.bne("t1", "k1", "restore")
        a.nop()
        a.sll("t3", "t3", 2)          # 32 bits: bytes por linha
        a.beq("zero", "zero", "dstart")
        a.or_("t4", "t5", "zero")     # (delay) cor 32
        a.label("d16")
        a.sll("t3", "t3", 1)
        a.label("dstart")
        a.sll("k1", "t3", 5)
        a.addu("t2", "t2", "k1")
        a.sll("k1", "t3", 3)
        a.addu("t2", "t2", "k1")      # linha 40 (fora da borda/overscan de 007 e jogos PAL)
        a.addiu("t2", "t2", 160)      # um pouco para a direita
        a.ori("t1", "zero", 10)       # 10 linhas
        a.label("drow")
        for off in range(0, 32, 4):
            a.sw("t4", off, "t2")
        a.addu("t2", "t2", "t3")
        a.addiu("t1", "t1", -1)
        a.bne("t1", "zero", "drow")
        a.nop()
    a.label("restore")
    a.lui("k0", IGR_ADDR >> 16)
    for k, rn in enumerate(("t0", "t1", "t2", "t3", "t4", "t5")):
        a.ld_l(rn, "SAVE%d" % k, "k0")
    a.label("out")
    a.lui("k0", IGR_ADDR >> 16)
    a.lw_l("k1", "TPLFLAG", "k0")
    a.beq("k1", "zero", "tailA")
    a.nop()
    a.lw_l("k0", "ORIG", "k0")        # entrada B: handler original do jogo
    a.jr("k0")
    a.nop()
    a.label("tailA")
    a.j(0x80000120)                   # entrada A: handler do jogo (realocado pelo motor)
    a.nop()

    # ---------------- reinicio
    n = [0]

    def lab(p):
        n[0] += 1
        return "%s%d" % (p, n[0])

    def wait_clear(base, off, mask_hi, mask_lo, tries=0x40000):
        """espera (base+off) & mask == 0, com limite de tentativas (t9)."""
        l_loop, l_done = lab("w"), lab("wd")
        a.li("t9", tries)
        a.li("t4", (mask_hi << 16) | mask_lo)
        a.label(l_loop)
        a.lw("t1", off, base)
        a.and_("t1", "t1", "t4")
        a.beq("t1", "zero", l_done)
        a.addiu("t9", "t9", -1)       # (delay)
        a.bne("t9", "zero", l_loop)
        a.nop()
        a.label(l_done)

    def paint_call(cor):
        a.li("a0", cor[0])
        a.li("a1", cor[1])
        a.jal("paint")
        a.nop()

    a.label("reboot")
    a.mtc0("zero", 18)                # WatchLo = 0
    a.lui("t0", 0x3400)               # CU1|CU0|FR, sem EXL/IE
    a.mtc0("t0", 12)
    a.nop()
    a.lui("t0", 0xA430)
    a.ori("t1", "zero", 0x0555)
    a.sw("t1", 0x000C, "t0")          # MI_MASK: desliga todas
    paint_call(COR_BRANCO)
    # RSP: halt primeiro (para de alimentar o RDP) + limpa estados (como boot.c)
    a.lui("t2", 0xA404)
    a.li("t1", 0x00AAAAAE)
    a.sw("t1", 0x0010, "t2")
    a.sw("zero", 0x001C, "t2")        # SEMAPHORE
    wait_clear("t2", 0x0018, 0x0000, 0x0001)   # SP_DMA_BUSY
    a.lui("t3", 0xA408)
    a.sw("zero", 0x0000, "t3")        # SP_PC
    # RDP: deixa terminar o que ja recebeu (o RSP so publica comandos inteiros).
    # v3 cortava com END = CURRENT e podia deixar um comando pela metade -> menu: "RSP CRASH rspq".
    a.lui("t2", 0xA410)
    wait_clear("t2", 0x000C, 0x0000, 0x0170, tries=0x100000)   # DPC_STATUS: pipe/cmd/dma busy
    a.ori("t1", "zero", 0x0001)
    a.sw("t1", 0x000C, "t2")          # DPC_STATUS: clr XBUS (menu usa RDRAM)
    paint_call(COR_CIANO)
    # PI: espera e reseta
    a.lui("t0", 0xA460)
    wait_clear("t0", 0x0010, 0x0000, 0x0003)
    a.ori("t1", "zero", 0x0003)
    a.sw("t1", 0x0010, "t0")          # PI reset + clr intr
    # limpa interrupcoes pendentes do jogo
    a.lui("t2", 0xA480)
    a.sw("zero", 0x0018, "t2")        # SI_STATUS (clr intr)
    a.lui("t2", 0xA450)
    a.sw("zero", 0x0000, "t2")        # AI_DRAM_ADDR
    a.sw("zero", 0x0004, "t2")        # AI_LEN
    a.sw("zero", 0x000C, "t2")        # AI_STATUS (clr intr)
    a.lui("t2", 0xA430)
    a.ori("t1", "zero", 0x0800)
    a.sw("t1", 0x0000, "t2")          # MI_MODE: clr DP intr
    a.lui("t2", 0xA440)
    a.lw("t1", 0x0010, "t2")
    a.sw("t1", 0x0010, "t2")          # VI_CURRENT: clr VI intr (video continua ligado)
    paint_call(COR_VERMELHO)
    # SC64: destrava
    a.lui("t0", 0xA460)
    a.lui("t3", 0xBFFF)
    for val in (0x00000000, 0x5F554E4C, 0x4F434B5F):
        wait_clear("t0", 0x0010, 0x0000, 0x0003)
        a.li("t1", val)
        a.sw("t1", 0x0010, "t3")      # KEY
    wait_clear("t0", 0x0010, 0x0000, 0x0003)
    a.lw("t1", 0x000C, "t3")          # IDENTIFIER
    a.li("t4", 0x53437632)            # "SCv2"
    a.bne("t1", "t4", "sc64err")
    a.nop()
    paint_call(COR_AMARELO)
    a.lui("t0", 0xA460)
    a.lui("t3", 0xBFFF)

    def sc64_cfg(cfg_id, value):
        wait_clear("t0", 0x0010, 0x0000, 0x0003)
        a.ori("t1", "zero", cfg_id)
        a.sw("t1", 0x0004, "t3")      # DATA0
        wait_clear("t0", 0x0010, 0x0000, 0x0003)
        a.ori("t1", "zero", value)
        a.sw("t1", 0x0008, "t3")      # DATA1
        wait_clear("t0", 0x0010, 0x0000, 0x0003)
        a.ori("t1", "zero", 0x43)     # 'C' = CONFIG_SET
        a.sw("t1", 0x0000, "t3")      # SCR
        wait_clear("t0", 0x0010, 0x0000, 0x0003)
        wait_clear("t3", 0x0000, 0x8000, 0x0000, tries=0x100000)   # CMD_BUSY
        a.lw("t1", 0x0000, "t3")
        a.lui("t4", 0xC000)           # ainda ocupado (tempo esgotado) ou CMD_ERROR
        a.and_("t1", "t1", "t4")
        a.bne("t1", "zero", "sc64err")
        a.nop()

    sc64_cfg(5, 0)                    # BOOT_MODE = menu
    sc64_cfg(0, 1)                    # BOOTLOADER_SWITCH = 1
    paint_call(COR_VERDE)
    a.lui("t0", 0xA460)
    a.lui("t3", 0xBFFF)
    wait_clear("t0", 0x0010, 0x0000, 0x0003)
    a.li("t1", 0xFFFFFFFF)
    a.sw("t1", 0x0010, "t3")          # KEY = trava (estado de reset)
    a.j("pitiming")
    a.nop()
    a.label("sc64err")
    paint_call(COR_MAGENTA)
    a.label("pitiming")
    a.lui("t0", 0xA460)
    wait_clear("t0", 0x0010, 0x0000, 0x0003)
    # PI DOM1 lento, depois o do cabecalho (como boot.c)
    for off, val in ((0x14, 0xFF), (0x18, 0xFF), (0x1C, 0x0F), (0x20, 0x03)):
        a.ori("t1", "zero", val)
        a.sw("t1", off, "t0")
    a.lui("t3", 0xB000)
    a.lw("t5", 0x0000, "t3")
    a.sw("t5", 0x0014, "t0")
    a.srl("t1", "t5", 8)
    a.sw("t1", 0x0018, "t0")
    a.srl("t1", "t5", 16)
    a.sw("t1", 0x001C, "t0")
    a.srl("t1", "t5", 20)
    a.sw("t1", 0x0020, "t0")
    # IPL3 do bootloader -> DMEM
    a.lui("t3", 0xB000)
    a.addiu("t3", "t3", 0x0040)
    a.lui("t4", 0xA400)
    a.addiu("t4", "t4", 0x0040)
    a.lui("t5", 0xA400)
    a.addiu("t5", "t5", 0x1000)
    a.label("ipl3cp")
    a.lw("t1", 0x0000, "t3")
    a.sw("t1", 0x0000, "t4")
    a.addiu("t3", "t3", 4)
    a.addiu("t4", "t4", 4)
    a.bne("t4", "t5", "ipl3cp")
    a.nop()
    paint_call(COR_AZUL)
    # registros de boot (como reboot.S), reset_type = NMI (igual ao botao RESET)
    a.lui("t0", 0x8000)
    a.lw("s4", 0x0300, "t0")          # osTvType do jogo
    a.andi("s4", "s4", 0x0003)
    a.ori("s3", "zero", 0)
    a.ori("s5", "zero", 1)
    a.ori("s6", "zero", 0x3F)
    a.li("ra", 0xA4001554)
    a.ori("s7", "zero", 6)            # PAL
    a.beq("s4", "zero", "regs")
    a.ori("t1", "zero", 1)            # (delay)
    a.li("ra", 0xA4001554)
    a.ori("s7", "zero", 4)            # MPAL
    a.bne("s4", "t1", "regs")
    a.nop()
    a.li("ra", 0xA4001550)
    a.ori("s7", "zero", 1)            # NTSC
    a.label("regs")
    a.ctc1("zero", 31)
    a.li("sp", 0xA4001FF0)
    for rn in ("at", "v0", "v1", "a0", "a1", "a2", "a3", "t0", "t1", "t4", "t5", "t6", "t7",
               "s0", "s1", "s2", "t8", "t9", "k0", "k1", "gp", "fp"):
        a.ori(rn, "zero", 0)
    a.ori("t2", "zero", 0x40)
    a.li("t3", 0xA4000040)
    a.jr("t3")
    a.nop()

    # ---------------- paint(a0 = cor 16 bits em par, a1 = cor 32 bits): pinta o framebuffer exibido
    # usa t6, t7, t8, t9, v0, v1
    a.label("paint")
    a.lui("t6", 0xA440)
    a.lw("t7", 0x0000, "t6")          # VI_CTRL
    a.andi("t7", "t7", 0x0003)
    a.ori("t8", "zero", 2)
    a.beq("t7", "t8", "p16")
    a.or_("v0", "a0", "zero")         # (delay) cor 16
    a.ori("t8", "zero", 3)
    a.bne("t7", "t8", "pret")
    a.or_("v0", "a1", "zero")         # (delay) cor 32
    a.lw("t9", 0x0008, "t6")          # VI_WIDTH
    a.andi("t9", "t9", 0x0FFF)
    a.sll("t9", "t9", 2)              # bytes por linha (32 bits)
    a.j("prows")
    a.nop()
    a.label("p16")
    a.lw("t9", 0x0008, "t6")
    a.andi("t9", "t9", 0x0FFF)
    a.sll("t9", "t9", 1)              # bytes por linha (16 bits)
    a.label("prows")
    a.sll("t8", "t9", 8)
    a.sll("t9", "t9", 4)
    a.subu("t9", "t8", "t9")          # * 240 linhas
    a.beq("t9", "zero", "pret")
    a.nop()
    a.li("t8", 0x0012C000)            # limite 640x480x4
    a.sltu("v1", "t8", "t9")
    a.bne("v1", "zero", "pret")
    a.nop()
    a.lw("t7", 0x0004, "t6")          # VI_ORIGIN
    a.li("t8", 0x00FFFFFC)
    a.and_("t7", "t7", "t8")
    a.lui("t8", 0xA000)
    a.or_("t7", "t7", "t8")           # KSEG1
    a.addu("t8", "t7", "t9")
    a.lui("v1", 0xA080)
    a.sltu("v1", "v1", "t8")          # nao passa de 8 MB
    a.bne("v1", "zero", "pret")
    a.nop()
    a.label("ploop")
    a.sw("v0", 0x0000, "t7")
    a.addiu("t7", "t7", 4)
    a.sltu("v1", "t7", "t8")
    a.bne("v1", "zero", "ploop")
    a.nop()
    a.label("pret")
    if debug:
        # segura a cor ~0,8 s
        a.word(0x40024800)            # mfc0 v0, Count
        a.li("v1", PAINT_DELAY)
        a.label("pdly")
        a.word(0x40194800)            # mfc0 t9, Count
        a.subu("t9", "t9", "v0")
        a.sltu("t9", "t9", "v1")
        a.bne("t9", "zero", "pdly")
        a.nop()
    a.jr("ra")
    a.nop()

    # ---------------- prep: roda no fim do patcher do motor (no lugar de "jr t1"), antes do jogo.
    # Jogos como o RE2 desligam o WatchLo ANTES de instalar os vetores de excecao, entao o motor
    # nunca entra. A libultra copia um modelo "lui k0,X / addiu k0,k0,Y / jr k0 / nop" para
    # 0x80000000/080/100/180: desviamos esse modelo para a entrada B (que segue para X:Y).
    # Jogos da Rare (conferem o proprio codigo) ficam de fora: neles o caminho do motor funciona.
    entry_b = a.labels["entryB"]
    assert (entry_b >> 16) == (IGR_ADDR >> 16) and (entry_b & 0xFFFF) < 0x8000
    a.label("prep")
    a.lui("t3", 0xA460)
    a.label("pr_pi")
    a.lw("t4", 0x0010, "t3")          # PI ocioso
    a.andi("t4", "t4", 0x0003)
    a.bne("t4", "zero", "pr_pi")
    a.nop()
    a.lui("t3", 0xB000)
    a.lw("t4", 0x003C, "t3")          # codigo do jogo no cabecalho (2 letras)
    a.srl("t4", "t4", 16)
    for code in RARE_IDS:
        a.ori("t5", "zero", (ord(code[0]) << 8) | ord(code[1]))
        a.beq("t4", "t5", "pr_done")
        a.nop()
    a.or_("t3", "t1", "zero")         # procura no 1 MB carregado a partir do entry point
    a.lui("t4", 0x0010)
    a.addu("t4", "t3", "t4")
    a.li("t5", 0x03400008)            # jr k0
    a.lui("t6", 0xFFFF)
    a.lui("t7", 0x3C1A)               # lui k0,
    a.lui("t8", 0x275A)               # addiu k0,k0,
    a.or_("t9", "zero", "zero")       # endereco do modelo achado
    a.label("pr_loop")
    a.lw("k0", 8, "t3")
    a.bne("k0", "t5", "pr_next")
    a.nop()
    a.lw("k0", 12, "t3")
    a.bne("k0", "zero", "pr_next")
    a.nop()
    a.lw("k0", 0, "t3")
    a.and_("k1", "k0", "t6")
    a.bne("k1", "t7", "pr_next")
    a.nop()
    a.lw("k0", 4, "t3")
    a.and_("k1", "k0", "t6")
    a.bne("k1", "t8", "pr_next")
    a.nop()
    a.bne("t9", "zero", "pr_done")    # mais de um modelo: nao mexe
    a.nop()
    a.or_("t9", "t3", "zero")
    a.label("pr_next")
    a.addiu("t3", "t3", 4)
    a.bne("t3", "t4", "pr_loop")
    a.nop()
    a.beq("t9", "zero", "pr_done")
    a.nop()
    # ORIG = (hi << 16) + sext(lo)
    a.lw("k0", 0, "t9")
    a.sll("k0", "k0", 16)
    a.lw("k1", 4, "t9")
    a.sll("k1", "k1", 16)
    a.r("zero", "k1", "k1", 16, 0x03)  # sra k1, k1, 16
    a.addu("k0", "k0", "k1")
    a.lui("k1", IGR_ADDR >> 16)
    a.sw_l("k0", "ORIG", "k1")
    a.ori("k0", "zero", 1)
    a.sw_l("k0", "TPLFLAG", "k1")
    a.cache_l(0x19, "TPLFLAG", "k1")  # HIT_WRITE_BACK_D (TPLFLAG e ORIG na mesma linha)
    # modelo -> lui k0,hi(entryB) / addiu k0,k0,lo(entryB)
    a.li("k0", 0x3C1A0000 | (entry_b >> 16))
    a.sw("k0", 0, "t9")
    a.li("k0", 0x275A0000 | (entry_b & 0xFFFF))
    a.sw("k0", 4, "t9")
    for off in (0, 4):
        a.cache(0x19, off, "t9")      # HIT_WRITE_BACK_D
        a.cache(0x10, off, "t9")      # HIT_INVALIDATE_I
    a.label("pr_done")
    a.jr("t1")                        # entry point do jogo (como o patcher original)
    a.nop()

    # ---------------- dados
    while (a.here() & 0xF) != 0:
        a.word(0)
    a.label("HIT")
    a.word(0)
    a.label("MISSRUN")
    a.word(0)
    a.label("LAST")
    a.word(0x0040)                    # 0x40 = nunca viu resposta valida do controle
    a.word(0)
    a.label("TPLFLAG")                # 1 = modelo de excecao do jogo desviado p/ entrada B
    a.word(0)
    a.label("ORIG")                   # handler original do jogo (do modelo)
    a.word(0)
    a.word(0)
    a.word(0)
    assert (a.here() & 0x7) == 0
    for k in range(6):
        a.label("SAVE%d" % k)         # 8 bytes cada (sd/ld)
        a.word(0)
        a.word(0)
    while (a.here() & 0xF) != 0:
        a.word(0)
    return a.build(), a.labels


def build_igr_block_v9(debug=False):
    """v9 = deteccao da v4 (so k0/k1, nenhum registrador do jogo) + contagem tolerante (k0/k1)
    + reinicio limpo: espera o RSP terminar a tarefa, desentala o RDP (NOPs + SYNC_FULL),
    espera o SI, limpa TLB/Config, interrupcoes. Sem scanner, sem prep, sem quadradinho.
    debug=True: cores do reinicio ficam ~0,8 s cada.
    v10: + entrada B / prep (desvio do modelo de excecao) so para os jogos em PREP_IDS."""
    a = Asm(IGR_ADDR)
    # ---------------- entrada A (fim do motor). Com o modelo desviado (TPLFLAG) a checagem
    # acontece na entrada B; aqui so segue para o handler realocado.
    a.lui("k0", IGR_ADDR >> 16)
    a.lw_l("k0", "TPLFLAG", "k0")
    a.beq("k0", "zero", "entryB")
    a.nop()
    a.j(0x80000120)
    a.nop()
    # ---------------- entrada B / checagem (a cada excecao do jogo) - so k0/k1
    a.label("entryB")
    a.lui("k0", 0xA480)
    a.lw("k0", 0x0018, "k0")          # SI_STATUS
    a.andi("k0", "k0", 0x0003)        # DMA/IO ocupado?
    a.bne("k0", "zero", "vi")
    a.lui("k1", 0xBFC0)               # (delay)
    a.lw("k0", 0x07C0, "k1")          # canal 0: FF 01 04 01
    a.lui("k1", 0xFF01)
    a.ori("k1", "k1", 0x0401)
    a.bne("k0", "k1", "vi")
    a.lui("k1", 0xBFC0)               # (delay)
    a.lw("k0", 0x07C4, "k1")
    a.srl("k0", "k0", 16)             # botoes
    a.andi("k1", "k0", 0x0040)        # 1 = pedido ainda nao respondido (0xFFFF)
    a.bne("k1", "zero", "vi")
    a.lui("k1", IGR_ADDR >> 16)       # (delay)
    a.sw_l("k0", "LAST", "k1")
    a.label("vi")
    a.lui("k0", 0xA430)
    a.lw("k0", 0x0008, "k0")          # MI_INTR
    a.andi("k0", "k0", 0x0008)        # VI pendente -> 1x por quadro
    a.beq("k0", "zero", "out")
    a.lui("k0", IGR_ADDR >> 16)       # (delay)
    if debug:
        # marcador so com k0/k1 (v11): faixa 16x8 na linha ~40 do framebuffer exibido.
        # vermelho = IGR roda mas nunca leu o controle; amarelo = le o controle; ciano = L+R
        a.lui("k0", 0xA440)
        a.lw("k0", 0x0004, "k0")      # VI_ORIGIN
        a.lui("k1", 0x00FF)
        a.ori("k1", "k1", 0xFFFC)
        a.and_("k0", "k0", "k1")
        a.beq("k0", "zero", "mk_end")
        a.lui("k1", 0xA000)           # (delay)
        a.or_("k0", "k0", "k1")
        a.ori("k1", "zero", 40 * 640 + 160)
        a.addu("k0", "k0", "k1")      # linha 40 (320 px, 16 bits) + um pouco a direita
        a.lui("k1", IGR_ADDR >> 16)
        a.lw_l("k1", "LAST", "k1")
        a.xori("k1", "k1", 0x0040)
        a.beq("k1", "zero", "mk_red")
        a.lui("k1", IGR_ADDR >> 16)   # (delay)
        a.lw_l("k1", "LAST", "k1")
        a.andi("k1", "k1", 0x0030)
        a.xori("k1", "k1", 0x0030)
        a.bne("k1", "zero", "mk_yel")
        a.nop()
        a.li("k1", 0x07FF07FF)        # ciano
        a.beq("zero", "zero", "mk_draw")
        a.nop()
        a.label("mk_red")
        a.li("k1", 0xF801F801)
        a.beq("zero", "zero", "mk_draw")
        a.nop()
        a.label("mk_yel")
        a.li("k1", 0xFFC1FFC1)
        a.label("mk_draw")
        for row in range(8):
            for col in range(0, 32, 4):
                a.sw("k1", col, "k0")
            if row < 7:
                a.addiu("k0", "k0", 640)
        a.label("mk_end")
        a.lui("k0", IGR_ADDR >> 16)
    a.lw_l("k1", "LAST", "k0")
    a.andi("k1", "k1", 0x0070)
    a.xori("k1", "k1", 0x0030)        # L e R, bit 0x40 = 0
    a.bne("k1", "zero", "miss")
    a.lw_l("k1", "LAST", "k0")        # (delay)
    a.andi("k1", "k1", 0x1080)        # START ou RST
    a.beq("k1", "zero", "miss")
    a.nop()
    a.sw_l("zero", "MISSRUN", "k0")
    a.lw_l("k1", "HIT", "k0")
    a.addiu("k1", "k1", 1)
    a.sw_l("k1", "HIT", "k0")
    a.sltiu("k1", "k1", IGR_THRESH)
    a.bne("k1", "zero", "out")
    a.nop()
    a.j("reboot")
    a.nop()
    a.label("miss")                   # so zera HIT apos IGR_RELEASE quadros seguidos sem o combo
    a.lw_l("k1", "MISSRUN", "k0")
    a.addiu("k1", "k1", 1)
    a.sw_l("k1", "MISSRUN", "k0")
    a.sltiu("k1", "k1", IGR_RELEASE)
    a.bne("k1", "zero", "out")
    a.nop()
    a.sw_l("zero", "HIT", "k0")
    a.label("out")
    a.lui("k0", IGR_ADDR >> 16)
    a.lw_l("k1", "TPLFLAG", "k0")
    a.beq("k1", "zero", "tailA")
    a.nop()
    a.lw_l("k0", "ORIG", "k0")        # entrada B: handler original do jogo
    a.jr("k0")
    a.nop()
    a.label("tailA")
    a.j(0x80000120)                   # entrada A: handler do jogo (realocado pelo motor)
    a.nop()

    # ---------------- prep (fim do patcher, antes do jogo; t1 = entry point). So jogos em PREP_IDS:
    # eles desligam o WatchLo antes de instalar os vetores (RE2 confirmado). Desvia o modelo
    # libultra "lui k0,X / addiu k0,k0,Y / jr k0 / nop" (unico no 1 MB) para a entrada B.
    entry_b = a.labels["entryB"]
    assert (entry_b >> 16) == (IGR_ADDR >> 16) and (entry_b & 0xFFFF) < 0x8000
    a.label("prep")
    a.lui("t3", 0xA460)
    a.label("pr_pi")
    a.lw("t4", 0x0010, "t3")          # PI ocioso
    a.andi("t4", "t4", 0x0003)
    a.bne("t4", "zero", "pr_pi")
    a.nop()
    a.lui("t3", 0xB000)
    a.lw("t4", 0x003C, "t3")          # codigo do jogo (2 letras) no cabecalho
    a.srl("t4", "t4", 16)
    for code in PREP_IDS:
        a.ori("t5", "zero", (ord(code[0]) << 8) | ord(code[1]))
        a.beq("t4", "t5", "pr_go")
        a.nop()
    a.j("pr_done")
    a.nop()
    a.label("pr_go")
    a.or_("t3", "t1", "zero")
    a.lui("t4", 0x0010)
    a.addu("t4", "t3", "t4")
    a.li("t5", 0x03400008)            # jr k0
    a.lui("t6", 0xFFFF)
    a.lui("t7", 0x3C1A)               # lui k0,
    a.lui("t8", 0x275A)               # addiu k0,k0,
    a.or_("t9", "zero", "zero")
    a.label("pr_loop")
    a.lw("k0", 8, "t3")
    a.bne("k0", "t5", "pr_next")
    a.nop()
    a.lw("k0", 12, "t3")
    a.bne("k0", "zero", "pr_next")
    a.nop()
    a.lw("k0", 0, "t3")
    a.and_("k1", "k0", "t6")
    a.bne("k1", "t7", "pr_next")
    a.nop()
    a.lw("k0", 4, "t3")
    a.and_("k1", "k0", "t6")
    a.bne("k1", "t8", "pr_next")
    a.nop()
    a.bne("t9", "zero", "pr_done")    # mais de um modelo: nao mexe
    a.nop()
    a.or_("t9", "t3", "zero")
    a.label("pr_next")
    a.addiu("t3", "t3", 4)
    a.bne("t3", "t4", "pr_loop")
    a.nop()
    a.beq("t9", "zero", "pr_done")
    a.nop()
    a.lw("k0", 0, "t9")               # ORIG = (hi << 16) + sext(lo)
    a.sll("k0", "k0", 16)
    a.lw("k1", 4, "t9")
    a.sll("k1", "k1", 16)
    a.r("zero", "k1", "k1", 16, 0x03)  # sra k1, k1, 16
    a.addu("k0", "k0", "k1")
    a.lui("k1", IGR_ADDR >> 16)
    a.sw_l("k0", "ORIG", "k1")
    a.ori("k0", "zero", 1)
    a.sw_l("k0", "TPLFLAG", "k1")
    a.cache_l(0x19, "TPLFLAG", "k1")  # HIT_WRITE_BACK_D (TPLFLAG e ORIG na mesma linha)
    a.li("k0", 0x3C1A0000 | (entry_b >> 16))
    a.sw("k0", 0, "t9")
    a.li("k0", 0x275A0000 | (entry_b & 0xFFFF))
    a.sw("k0", 4, "t9")
    for off in (0, 4):
        a.cache(0x19, off, "t9")      # HIT_WRITE_BACK_D
        a.cache(0x10, off, "t9")      # HIT_INVALIDATE_I
    a.label("pr_done")
    a.jr("t1")
    a.nop()

    # ---------------- reinicio
    n = [0]

    def lab(p):
        n[0] += 1
        return "%s%d" % (p, n[0])

    def wait_mask(base, off, mask, want_zero=True, tries=0x40000):
        """espera ((base+off) & mask) == 0 (ou != 0), com limite de tentativas (t9)."""
        l_loop, l_done = lab("w"), lab("wd")
        a.li("t9", tries)
        a.li("t4", mask)
        a.label(l_loop)
        a.lw("t1", off, base)
        a.and_("t1", "t1", "t4")
        (a.beq if want_zero else a.bne)("t1", "zero", l_done)
        a.addiu("t9", "t9", -1)       # (delay)
        a.bne("t9", "zero", l_loop)
        a.nop()
        a.label(l_done)

    def paint_call(cor):
        a.li("a0", cor[0])
        a.li("a1", cor[1])
        a.jal("paint")
        a.nop()

    a.label("reboot")
    a.mtc0("zero", 18)                # WatchLo = 0
    a.lui("t0", 0x3400)               # CU1|CU0|FR, sem EXL/IE
    a.mtc0("t0", 12)
    a.nop()
    a.lui("t0", 0xA430)
    a.ori("t1", "zero", 0x0555)
    a.sw("t1", 0x000C, "t0")          # MI_MASK: desliga todas
    paint_call(COR_BRANCO)
    # SI: termina a transacao do controle em andamento
    a.lui("t2", 0xA480)
    wait_mask("t2", 0x0018, 0x0003)
    # RSP: deixa terminar a tarefa atual (como no PRE-NMI do RESET), depois halt
    a.lui("t2", 0xA404)
    wait_mask("t2", 0x0010, 0x0001, want_zero=False, tries=0x100000)   # SP_STATUS.HALT
    a.li("t1", 0x00AAAAAE)            # SET_HALT + limpa sinais/broke/intr/sstep
    a.sw("t1", 0x0010, "t2")
    a.sw("zero", 0x001C, "t2")        # SEMAPHORE
    wait_mask("t2", 0x0018, 0x0001)   # SP_DMA_BUSY
    a.lui("t3", 0xA408)
    a.sw("zero", 0x0000, "t3")        # SP_PC
    # RDP: modo RDRAM, sem freeze/flush; espera; depois desentala com NOPs + SYNC_FULL
    a.lui("t2", 0xA410)
    a.ori("t1", "zero", 0x0015)       # clr XBUS | clr FREEZE | clr FLUSH
    a.sw("t1", 0x000C, "t2")
    wait_mask("t2", 0x000C, 0x0170, tries=0x100000)   # pipe/cmd/dma busy
    a.lui("t3", 0x00FF)
    a.ori("t3", "t3", 0xFFFF)
    a.lui("t5", IGR_ADDR >> 16)
    a.addiu("t5", "t5", 0)            # fixado: RDPBUF
    rdpbuf_fix = len(a.items) - 1
    a.and_("t5", "t5", "t3")          # endereco fisico
    a.sw("t5", 0x0000, "t2")          # DPC_START
    a.addiu("t5", "t5", RDPBUF_LEN)
    a.sw("t5", 0x0004, "t2")          # DPC_END
    wait_mask("t2", 0x000C, 0x0170, tries=0x100000)
    paint_call(COR_CIANO)
    # PI: espera e reseta
    a.lui("t0", 0xA460)
    wait_mask("t0", 0x0010, 0x0003)
    a.ori("t1", "zero", 0x0003)
    a.sw("t1", 0x0010, "t0")          # PI reset + clr intr
    # limpa interrupcoes pendentes
    a.lui("t2", 0xA480)
    a.sw("zero", 0x0018, "t2")        # SI clr intr
    a.lui("t2", 0xA450)
    a.sw("zero", 0x0000, "t2")        # AI_DRAM_ADDR
    a.sw("zero", 0x0004, "t2")        # AI_LEN
    a.sw("zero", 0x000C, "t2")        # AI clr intr
    a.lui("t2", 0xA430)
    a.ori("t1", "zero", 0x0800)
    a.sw("t1", 0x0000, "t2")          # MI_MODE: clr DP intr
    a.lui("t2", 0xA440)
    a.lw("t1", 0x0010, "t2")
    a.sw("t1", 0x0010, "t2")          # VI clr intr
    # CPU: TLB vazia (32 entradas em kseg0, nunca casam) e Config padrao do boot
    a.mtc0("zero", 2)                 # EntryLo0
    a.mtc0("zero", 3)                 # EntryLo1
    a.mtc0("zero", 5)                 # PageMask
    a.ori("t3", "zero", 0)
    a.lui("t5", 0x8000)
    a.label("tlb")
    a.mtc0("t3", 0)                   # Index
    a.mtc0("t5", 10)                  # EntryHi
    a.nop()
    a.word(0x42000002)                # tlbwi
    a.nop()
    a.addiu("t3", "t3", 1)
    a.lui("t1", 0x0000)
    a.ori("t1", "t1", 0x2000)
    a.addu("t5", "t5", "t1")
    a.sltiu("t1", "t3", 32)
    a.bne("t1", "zero", "tlb")
    a.nop()
    a.mtc0("zero", 10)                # EntryHi = 0 (ASID 0)
    a.li("t1", 0x0006E463)
    a.mtc0("t1", 16)                  # Config
    a.nop()
    paint_call(COR_VERMELHO)
    # SC64: destrava
    a.lui("t0", 0xA460)
    a.lui("t3", 0xBFFF)
    for val in (0x00000000, 0x5F554E4C, 0x4F434B5F):
        wait_mask("t0", 0x0010, 0x0003)
        a.li("t1", val)
        a.sw("t1", 0x0010, "t3")      # KEY
    wait_mask("t0", 0x0010, 0x0003)
    a.lw("t1", 0x000C, "t3")          # IDENTIFIER
    a.li("t4", 0x53437632)            # "SCv2"
    a.bne("t1", "t4", "sc64err")
    a.nop()
    paint_call(COR_AMARELO)
    a.lui("t0", 0xA460)
    a.lui("t3", 0xBFFF)

    def sc64_cfg(cfg_id, value):
        wait_mask("t0", 0x0010, 0x0003)
        a.ori("t1", "zero", cfg_id)
        a.sw("t1", 0x0004, "t3")      # DATA0
        wait_mask("t0", 0x0010, 0x0003)
        a.ori("t1", "zero", value)
        a.sw("t1", 0x0008, "t3")      # DATA1
        wait_mask("t0", 0x0010, 0x0003)
        a.ori("t1", "zero", 0x43)     # 'C' = CONFIG_SET
        a.sw("t1", 0x0000, "t3")      # SCR
        wait_mask("t0", 0x0010, 0x0003)
        wait_mask("t3", 0x0000, 0x80000000, tries=0x100000)   # CMD_BUSY
        a.lw("t1", 0x0000, "t3")
        a.lui("t4", 0xC000)           # ainda ocupado ou CMD_ERROR
        a.and_("t1", "t1", "t4")
        a.bne("t1", "zero", "sc64err")
        a.nop()

    sc64_cfg(5, 0)                    # BOOT_MODE = menu
    sc64_cfg(0, 1)                    # BOOTLOADER_SWITCH = 1
    paint_call(COR_VERDE)
    a.lui("t0", 0xA460)
    a.lui("t3", 0xBFFF)
    wait_mask("t0", 0x0010, 0x0003)
    a.li("t1", 0xFFFFFFFF)
    a.sw("t1", 0x0010, "t3")          # KEY = trava (estado de reset)
    a.j("pitiming")
    a.nop()
    a.label("sc64err")
    paint_call(COR_MAGENTA)
    a.label("pitiming")
    a.lui("t0", 0xA460)
    wait_mask("t0", 0x0010, 0x0003)
    for off, val in ((0x14, 0xFF), (0x18, 0xFF), (0x1C, 0x0F), (0x20, 0x03)):
        a.ori("t1", "zero", val)
        a.sw("t1", off, "t0")
    a.lui("t3", 0xB000)
    a.lw("t5", 0x0000, "t3")
    a.sw("t5", 0x0014, "t0")
    a.srl("t1", "t5", 8)
    a.sw("t1", 0x0018, "t0")
    a.srl("t1", "t5", 16)
    a.sw("t1", 0x001C, "t0")
    a.srl("t1", "t5", 20)
    a.sw("t1", 0x0020, "t0")
    # IPL3 do bootloader -> DMEM
    a.lui("t3", 0xB000)
    a.addiu("t3", "t3", 0x0040)
    a.lui("t4", 0xA400)
    a.addiu("t4", "t4", 0x0040)
    a.lui("t5", 0xA400)
    a.addiu("t5", "t5", 0x1000)
    a.label("ipl3cp")
    a.lw("t1", 0x0000, "t3")
    a.sw("t1", 0x0000, "t4")
    a.addiu("t3", "t3", 4)
    a.addiu("t4", "t4", 4)
    a.bne("t4", "t5", "ipl3cp")
    a.nop()
    paint_call(COR_AZUL)
    # registros de boot (como reboot.S), reset_type = NMI (igual ao botao RESET)
    a.lui("t0", 0x8000)
    a.lw("s4", 0x0300, "t0")          # osTvType do jogo
    a.andi("s4", "s4", 0x0003)
    a.ori("s3", "zero", 0)
    a.ori("s5", "zero", 1)
    a.ori("s6", "zero", 0x3F)
    a.li("ra", 0xA4001554)
    a.ori("s7", "zero", 6)            # PAL
    a.beq("s4", "zero", "regs")
    a.ori("t1", "zero", 1)            # (delay)
    a.li("ra", 0xA4001554)
    a.ori("s7", "zero", 4)            # MPAL
    a.bne("s4", "t1", "regs")
    a.nop()
    a.li("ra", 0xA4001550)
    a.ori("s7", "zero", 1)            # NTSC
    a.label("regs")
    a.ctc1("zero", 31)
    a.li("sp", 0xA4001FF0)
    for rn in ("at", "v0", "v1", "a0", "a1", "a2", "a3", "t0", "t1", "t4", "t5", "t6", "t7",
               "s0", "s1", "s2", "t8", "t9", "k0", "k1", "gp", "fp"):
        a.ori(rn, "zero", 0)
    a.ori("t2", "zero", 0x40)
    a.li("t3", 0xA4000040)
    a.jr("t3")
    a.nop()

    # ---------------- paint(a0 = cor 16 bits em par, a1 = cor 32 bits): pinta o framebuffer exibido
    a.label("paint")
    a.lui("t6", 0xA440)
    a.lw("t7", 0x0000, "t6")          # VI_CTRL
    a.andi("t7", "t7", 0x0003)
    a.ori("t8", "zero", 2)
    a.beq("t7", "t8", "p16")
    a.or_("v0", "a0", "zero")         # (delay) cor 16
    a.ori("t8", "zero", 3)
    a.bne("t7", "t8", "pret")
    a.or_("v0", "a1", "zero")         # (delay) cor 32
    a.lw("t9", 0x0008, "t6")
    a.andi("t9", "t9", 0x0FFF)
    a.sll("t9", "t9", 2)
    a.j("prows")
    a.nop()
    a.label("p16")
    a.lw("t9", 0x0008, "t6")
    a.andi("t9", "t9", 0x0FFF)
    a.sll("t9", "t9", 1)
    a.label("prows")
    a.sll("t8", "t9", 8)
    a.sll("t9", "t9", 4)
    a.subu("t9", "t8", "t9")          # * 240 linhas
    a.beq("t9", "zero", "pret")
    a.nop()
    a.li("t8", 0x0012C000)
    a.sltu("v1", "t8", "t9")
    a.bne("v1", "zero", "pret")
    a.nop()
    a.lw("t7", 0x0004, "t6")          # VI_ORIGIN
    a.li("t8", 0x00FFFFFC)
    a.and_("t7", "t7", "t8")
    a.lui("t8", 0xA000)
    a.or_("t7", "t7", "t8")
    a.addu("t8", "t7", "t9")
    a.lui("v1", 0xA080)
    a.sltu("v1", "v1", "t8")
    a.bne("v1", "zero", "pret")
    a.nop()
    a.label("ploop")
    a.sw("v0", 0x0000, "t7")
    a.addiu("t7", "t7", 4)
    a.sltu("v1", "t7", "t8")
    a.bne("v1", "zero", "ploop")
    a.nop()
    a.label("pret")
    if debug:
        a.word(0x40024800)            # mfc0 v0, Count
        a.li("v1", PAINT_DELAY)
        a.label("pdly")
        a.word(0x40194800)            # mfc0 t9, Count
        a.subu("t9", "t9", "v0")
        a.sltu("t9", "t9", "v1")
        a.bne("t9", "zero", "pdly")
        a.nop()
    a.jr("ra")
    a.nop()

    # ---------------- dados
    while (a.here() & 0xF) != 0:
        a.word(0)
    a.label("HIT")
    a.word(0)
    a.label("MISSRUN")
    a.word(0)
    a.label("LAST")
    a.word(0x0040)                    # 0x40 = nunca viu resposta valida do controle
    a.word(0)
    a.label("TPLFLAG")                # 1 = modelo de excecao desviado p/ entrada B (prep)
    a.word(0)
    a.label("ORIG")                   # handler original do jogo
    a.word(0)
    a.word(0)
    a.word(0)
    a.label("RDPBUF")                 # NOPs (zeros) completam comando pela metade; depois SYNC_FULL
    for _ in range(RDPBUF_LEN // 4 - 2):
        a.word(0)
    a.word(0x29000000)
    a.word(0x00000000)
    code = bytearray(a.build())
    rb = a.labels["RDPBUF"]
    assert rb % 8 == 0 and (rb >> 16) == (IGR_ADDR >> 16)
    w = struct.unpack_from(">I", code, 4 * rdpbuf_fix)[0]
    struct.pack_into(">I", code, 4 * rdpbuf_fix, (w & 0xFFFF0000) | (rb & 0xFFFF))
    assert (rb & 0xFFFF) < 0x8000
    return bytes(code), a.labels


# v14: perfis restritos às revisões US fornecidas pelo usuário. O bloco v13 acima
# permanece byte a byte: RE2/Rare/outros voltam ao prep original. Não usar um
# scanner genérico para alterar jogos desconhecidos.
COMPAT_PROFILES = (
    {"name": "TWINE US", "header": 0x4F374500,
     "crc": (0x033F4C13, 0x319EE7A7), "template": 0x800A71C0,
     "handler": 0x800A71D0, "heap_lui": 0x800005EC},
    {"name": "Battle for Naboo US", "header": 0x4E414500,
     "crc": (0x3D02989B, 0xD4A381E2), "template": 0x8003FF00,
     "handler": 0x4003FF10, "heap_lui": None},
    {"name": "Ocarina of Time US 1.2", "header": 0x5A4C4502,
     "crc": (0x693BA2AE, 0xB7F14E9F), "template": 0x800025F0,
     "handler": 0x80002600, "heap_lui": None, "memsize_call": 0x800004D4},
)


def build_igr_block_v14(debug=False):
    """Acrescenta despacho v14 ao bloco v13 sem deslocar suas rotinas/dados.

    Reserva [807C0000,80800000) do heap dos três perfis. O TWINE usa fim
    explícito 80800000 e memset; Naboo deriva a arena/VM de osMemSize;
    Ocarina recebe o tamanho reservado no call site de osGetMemSize.
    Os perfis recebem entrada B direta e WatchLo desligado após todas as guardas:
    o Naboo copia o vetor 180 antes de instalar seu próprio wrapper de TLB.
    Outros títulos/revisões seguem exatamente o prep v13.
    """
    old, labels = build_igr_block_v9(debug)
    a = Asm(IGR_ADDR + len(old))
    a.label("compat_memsize")
    a.lui("v0", 0x007C)
    a.jr("ra")
    a.nop()
    a.label("compat_dispatch")
    a.lui("t3", 0xA460)
    a.label("compat_pi")
    a.lw("t4", 0x10, "t3")
    a.andi("t4", "t4", 3)
    a.bne("t4", "zero", "compat_pi")
    a.nop()
    a.lui("t3", 0xB000)
    a.lw("t4", 0x3C, "t3")
    for i, profile in enumerate(COMPAT_PROFILES):
        a.li("t5", profile["header"])
        a.beq("t4", "t5", "compat_%d" % i)
        a.nop()
    a.label("compat_fallback")
    a.j(labels["prep"])
    a.nop()

    for i, profile in enumerate(COMPAT_PROFILES):
        a.label("compat_%d" % i)
        # CRC do cabeçalho + entry point + opcodes relevantes: primeiro verifica
        # tudo, depois altera. Cabeçalho não substitui hash integral da ROM.
        for offset, expect in zip((0x10, 0x14), profile["crc"]):
            a.lw("t4", offset, "t3")
            a.li("t5", expect)
            a.bne("t4", "t5", "compat_fallback")
            a.nop()
        a.li("t5", 0x80000400)
        a.bne("t1", "t5", "compat_fallback")
        a.nop()
        template = profile["template"]
        handler = profile["handler"]
        hi = ((handler + 0x8000) >> 16) & 0xFFFF
        expected = (0x3C1A0000 | hi, 0x275A0000 | (handler & 0xFFFF),
                    0x03400008, 0)
        a.li("t6", template)
        for offset, expect in enumerate(expected):
            a.lw("t4", offset * 4, "t6")
            a.li("t5", expect)
            a.bne("t4", "t5", "compat_fallback")
            a.nop()
        if profile.get("memsize_call") is not None:
            a.li("t7", profile["memsize_call"])
            a.lw("t4", 0, "t7")
            a.li("t5", 0x0C001014)  # jal osGetMemSize, exact US 1.2
            a.bne("t4", "t5", "compat_fallback")
            a.nop()
            a.li("t4", 0x0C000000 | ((a.labels["compat_memsize"] >> 2) & 0x03FFFFFF))
            a.sw("t4", 0, "t7")
            a.cache(0x19, 0, "t7")
            a.cache(0x10, 0, "t7")
        if profile["heap_lui"] is not None:
            a.li("t7", profile["heap_lui"])
            a.lw("t4", 0, "t7")
            a.li("t5", 0x3C058080)  # lui a1,8080 no delay slot da chamada do heap
            a.bne("t4", "t5", "compat_fallback")
            a.nop()
            a.li("t4", 0x3C05807C)  # mesmo heap, fim antes de IGR/motor
            a.sw("t4", 0, "t7")
            a.cache(0x19, 0, "t7")
            a.cache(0x10, 0, "t7")
        else:
            # Naboo/Ocarina: todas as leituras nativas de osMemSize recebem a mesma
            # arena reduzida. O STUB v13 restaura 8 MiB para o próximo jogo.
            a.lui("t7", 0x8000)
            a.lui("t4", 0x007C)
            a.sw("t4", 0x0318, "t7")
            a.cache(0x19, 0x0318, "t7")
        a.lui("t7", IGR_ADDR >> 16)
        a.li("t4", handler)
        a.sw("t4", labels["ORIG"] - IGR_ADDR, "t7")
        a.ori("t4", "zero", 1)
        a.sw("t4", labels["TPLFLAG"] - IGR_ADDR, "t7")
        a.cache(0x19, labels["TPLFLAG"] - IGR_ADDR, "t7")
        entry = labels["entryB"]
        a.li("t4", 0x3C1A0000 | (entry >> 16))
        a.sw("t4", 0, "t6")
        a.li("t4", 0x275A0000 | (entry & 0xFFFF))
        a.sw("t4", 4, "t6")
        for offset in (0, 4):
            a.cache(0x19, offset, "t6")
            a.cache(0x10, offset, "t6")
        a.word(0x0000000F)  # sync
        a.mtc0("zero", 18) # WatchLo: osInitialize publica o template direto
        a.mtc0("zero", 19) # WatchHi
        for _ in range(3):
            a.nop()
        a.jr("t1")
        a.nop()
    labels = dict(labels, **a.labels)
    return old + a.build(), labels


# v15 appends profiles without changing the v14 block or its label addresses.
RE2_C169_CRC = (0x6A819001, 0x09473981)
STARFOX_US_CRC = (0xA7D015F8, 0x2289AA43)
RE2_FB_PATCHES = ((0x8004D1AC, 0x3C058076, 0x3C058072),
                  (0x8004D1B4, 0x3C06806D, 0x3C068069),
                  (0x8004D1BC, 0x3C048063, 0x3C04805F))


def build_igr_block_v15(debug=False):
    """Reserve IGR RAM for C169 and Star Fox US without reducing resolution.

    C169: patch LOW call after MAIN decompression, before creating its startup
    thread. Guarded late helper shifts all three full-size native buffers down
    256 KiB; native top-down arena follows the lower framebuffer boundary.
    Star Fox: native framebuffer allocation derives from osMemSize, so reserve
    the top 256 KiB by reporting 7.75 MiB only for this exact game revision.
    """
    old, labels = build_igr_block_v14(debug)
    a = Asm(IGR_ADDR + len(old))
    a.label("fox_sample")
    # Read the native osContGetReadData channel-0 result, not transient PIF RAM.
    # Exact producer: 80002BBC -> 80020444, a0=800D8ED0, stride 6 bytes.
    a.lui("k0", 0x800E)
    a.i(0x24, "k0", "k1", -0x712C)  # lbu errno at pad+4
    a.bne("k1", "zero", "fox_bad_pad")
    a.nop()
    a.i(0x25, "k0", "k1", -0x7130)  # lhu button
    a.beq("zero", "zero", "fox_store_pad")
    a.nop()
    a.label("fox_bad_pad")
    a.ori("k1", "zero", 0x40)
    a.label("fox_store_pad")
    a.lui("k0", IGR_ADDR >> 16)
    a.sw("k1", labels["LAST"] - IGR_ADDR, "k0")
    a.j(labels["vi"])
    a.nop()
    a.label("dispatch_v15")
    a.lui("t3", 0xA460)
    a.label("v15_pi")
    a.lw("t4", 0x10, "t3")
    a.andi("t4", "t4", 3)
    a.bne("t4", "zero", "v15_pi")
    a.nop()
    a.lui("t3", 0xB000)
    a.lw("t4", 0x3C, "t3")
    for header, target in ((0x52454501, "v15_re2"), (0x46584500, "v15_fox")):
        a.li("t5", header)
        a.beq("t4", "t5", target)
        a.nop()
    a.label("v15_fallback")
    a.j(labels["compat_dispatch"])
    a.nop()

    def guard(addr, expected, base="t6"):
        a.li(base, addr)
        a.lw("t4", 0, base)
        a.li("t5", expected)
        a.bne("t4", "t5", "v15_fallback")
        a.nop()

    def header_guard(crc, entry):
        for off, val in zip((0x10, 0x14), crc):
            a.lw("t4", off, "t3")
            a.li("t5", val)
            a.bne("t4", "t5", "v15_fallback")
            a.nop()
        a.li("t5", entry)
        a.bne("t1", "t5", "v15_fallback")
        a.nop()

    def direct_entry(template, handler, entry=None):
        a.lui("t7", IGR_ADDR >> 16)
        a.li("t4", handler)
        a.sw("t4", labels["ORIG"] - IGR_ADDR, "t7")
        a.ori("t4", "zero", 1)
        a.sw("t4", labels["TPLFLAG"] - IGR_ADDR, "t7")
        a.cache(0x19, labels["TPLFLAG"] - IGR_ADDR, "t7")
        a.li("t6", template)
        entry = labels["entryB"] if entry is None else entry
        for off, word in ((0, 0x3C1A0000 | (entry >> 16)),
                          (4, 0x275A0000 | (entry & 0xFFFF))):
            a.li("t4", word)
            a.sw("t4", off, "t6")
            a.cache(0x19, off, "t6")
            a.cache(0x10, off, "t6")
        a.word(0xF)  # sync
        a.mtc0("zero", 18)
        a.mtc0("zero", 19)
        for _ in range(3):
            a.nop()
        a.jr("t1")
        a.nop()

    a.label("v15_re2")
    header_guard(RE2_C169_CRC, 0x80000480)
    for off, word in enumerate((0x3C1A8000, 0x275A06D0, 0x03400008, 0)):
        guard(0x800006C0 + 4 * off, word)
    guard(0x80000698, 0x0C0134D1)  # jal 8004D344 after MAIN decode
    guard(0x8000069C, 0)
    # Fix the instruction constant after the late helper address is known.
    re2_jal_fix = len(a.items)
    a.lui("t4", 0)
    a.ori("t4", "t4", 0)
    a.li("t6", 0x80000698)
    a.sw("t4", 0, "t6")
    a.cache(0x19, 0, "t6")
    a.cache(0x10, 0, "t6")
    direct_entry(0x800006C0, 0x800006D0)

    a.label("v15_fox")
    header_guard(STARFOX_US_CRC, 0x80000400)
    for off, word in enumerate((0x3C1A8002, 0x275A5000, 0x03400008, 0)):
        guard(0x80024FF0 + 4 * off, word)
    guard(0x80002BBC, 0x0C008111)
    guard(0x80002BC0, 0x24848ED0)
    a.lui("t7", 0x8000)
    a.lui("t4", 0x007C)
    a.sw("t4", 0x0318, "t7")
    a.cache(0x19, 0x0318, "t7")
    direct_entry(0x80024FF0, 0x80025000, a.labels["fox_sample"])

    a.label("re2_after_main")
    # Validate all words before changing any of the three paired addresses.
    # Unsupported MAIN layout returns to the original startup without guessing.
    for addr, expected in ((0x8004D1AC, 0x3C058076), (0x8004D1B0, 0x34A5A000),
                           (0x8004D1B4, 0x3C06806D), (0x8004D1B8, 0x34C64000),
                           (0x8004D1BC, 0x3C048063), (0x8004D1C0, 0x3484E000),
                           (0x8004D1C8, 0x24020280), (0x8004D1D4, 0x240201E0)):
        a.li("t6", addr)
        a.lw("t4", 0, "t6")
        a.li("t5", expected)
        a.bne("t4", "t5", "re2_main_done")
        a.nop()
    for addr, expected, replacement in RE2_FB_PATCHES:
        a.li("t6", addr)
        a.li("t4", replacement)
        a.sw("t4", 0, "t6")
        a.cache(0x19, 0, "t6")
        a.cache(0x10, 0, "t6")
    a.word(0xF)
    a.label("re2_main_done")
    a.j(0x8004D344)  # tail-call: original RA/stack/arguments remain intact
    a.nop()
    raw = bytearray(a.build())
    jal = 0x0C000000 | ((a.labels["re2_after_main"] >> 2) & 0x03FFFFFF)
    for index, imm in ((re2_jal_fix, jal >> 16), (re2_jal_fix + 1, jal & 0xFFFF)):
        word = struct.unpack_from(">I", raw, 4 * index)[0]
        struct.pack_into(">I", raw, 4 * index, (word & 0xFFFF0000) | imm)
    labels = dict(labels, **a.labels)
    return old + bytes(raw), labels


def build_igr_block_v17(debug=False):
    """Append the compatibility library; preserve the complete v15/v16 prefix."""
    from compatibility import emit_runtime
    old, labels = build_igr_block_v15(debug)
    new, extra = emit_runtime(Asm, IGR_ADDR + len(old), labels, IGR_ADDR)
    assert len(old) + len(new) < 0x8000
    return old + new, dict(labels, **extra)


def build_igr_block_v18(debug=False, bt_no_igr=False):
    from compatibility import emit_runtime, profiles_v18
    from vaccines import emit_watchlo
    if debug and bt_no_igr:raise ValueError('Use one diagnostic mode at a time.')
    old,labels=build_igr_block_v17(debug)
    # Existing profiles retain their tested paths on all revisions/CRC mismatches.
    protected=[(p['header']>>16)&65535 for p in COMPAT_PROFILES]
    from compatibility import PROFILES
    protected += [(p['header']>>16)&65535 for p in PROFILES]+[0x5245,0x4658,0x584F]
    vaccine,vlabels=emit_watchlo(Asm,IGR_ADDR+len(old),labels,IGR_ADDR,protected)
    old+=vaccine;labels=dict(labels,**vlabels)
    data=Asm(IGR_ADDR+len(old));data.label('BOOTCHEATS');data.word(0)
    old+=data.build();labels=dict(labels,**data.labels)
    new,extra=emit_runtime(Asm,IGR_ADDR+len(old),labels,IGR_ADDR,
                          profiles=profiles_v18(bt_no_igr),version=18,previous='v18_vaccine_gate')
    assert len(old)+len(new)<0x5C00
    return old+new,dict(labels,**extra)


def build_igr_block_v19(debug=False, bt_no_igr=False):
    """Append code-based bootstrap recognition; preserve the entire V18 runtime."""
    from compatibility import PROFILES
    from vaccines import emit_watchlo
    old,labels=build_igr_block_v18(debug,bt_no_igr)
    protected=[(p['header']>>16)&65535 for p in COMPAT_PROFILES]
    protected += [(p['header']>>16)&65535 for p in PROFILES]+[0x5245,0x4658,0x584F]
    new,extra=emit_watchlo(Asm,IGR_ADDR+len(old),labels,IGR_ADDR,protected,extended=True)
    old+=new;labels=dict(labels,**extra)
    from late_loader import emit
    new,extra=emit(Asm,IGR_ADDR+len(old),labels,IGR_ADDR)
    assert len(old)+len(new)<0x5C00
    return old+new,dict(labels,**extra)


def build_igr_block_v20(debug=False, bt_no_igr=False):
    from vaccines_ido import emit
    from compatibility import PROFILES
    old,labels=build_igr_block_v19(debug,bt_no_igr)
    protected=[(p['header']>>16)&65535 for p in COMPAT_PROFILES]
    protected += [(p['header']>>16)&65535 for p in PROFILES]+[0x5245,0x4658,0x584F]
    protected += [int.from_bytes(x.encode(),'big') for x in RARE_IDS]
    new,extra=emit(Asm,IGR_ADDR+len(old),labels,IGR_ADDR,protected)
    from reset_quiesce import append
    raw,labels=append(Asm,old+new,dict(labels,**extra),IGR_ADDR)
    assert len(raw)<0x5C00
    return raw,labels


def build_igr_block_v21(debug=False, bt_no_igr=False):
    from reset_recovery import append
    raw,labels=build_igr_block_v20(debug,bt_no_igr)
    raw,labels=append(Asm,raw,labels,IGR_ADDR)
    assert len(raw)<0x5C00
    return raw,labels


build_igr_block_v21_original = build_igr_block_v21


def build_igr_block_v21r2(debug=False, bt_no_igr=False):
    """Revised V21 candidate; retain the original V21 builder as an oracle."""
    from arena_guards import emit
    from reset_handoff import append
    raw, labels = build_igr_block_v21_original(debug, bt_no_igr)
    new, extra = emit(Asm, IGR_ADDR + len(raw), labels)
    raw, labels = append(Asm, raw + new, dict(labels, **extra), IGR_ADDR)
    assert len(raw) < 0x5C00
    return raw, labels


def build_cave(igr_block,bootcheats_slot=None):
    """STUB chamado no lugar do 'beq v0,zero' + bloco IGR + lista vazia."""
    a = Asm(CAVE)
    # v0 = cheat_list, v1 = (s5 < 8) ja calculado no delay slot; nao tocar v0/v1/s*.
    # v12: tamanho da RAM pela variavel do proprio menu (libdragon __boot_memsize em 0x800CB19C,
    # mesma regra de is_memory_expanded() em 0x800627A0: >= 0x7C0000). Ate a v11 lia 0x80000318,
    # que so o JOGO preenche: no 1o jogo apos ligar o console estava zerado -> IGR nao instalava.
    a.lui("t0", 0x800D)
    a.lw("t1", -0x4E64, "t0")         # 0x800CB19C
    a.lui("t2", 0x007C)
    a.r("t1", "t2", "t2", 0, 0x2A)    # slt t2, t1, t2
    a.bne("t2", "zero", "noexp")
    a.nop()
    # v13: com o motor instalado o RI nao e resetado e o IPL3 do jogo pula a init da RDRAM, que e
    # quem grava osMemSize (0x80000318). A frio (1o jogo apos ligar) ficava 0 -> 007 tela preta,
    # Carmageddon nao abre, RE2 pula a abertura. Grava o tamanho real, como apos um reset.
    a.lui("t3", 0x8000)
    a.sw("t1", 0x0318, "t3")          # osMemSize = __boot_memsize do menu
    a.cache(0x19, 0x0318, "t3")       # HIT_WRITE_BACK_D (linha suja do menu nao sobrescreve)
    i_blk = len(a.items)
    a.lui("t0", 0)                    # fixado depois: endereco do bloco
    a.addiu("t0", "t0", 0)
    a.lui("t1", IGR_ADDR >> 16)
    i_size = len(a.items)
    a.addiu("t2", "t0", 0)            # fixado depois: t0 + tamanho
    a.label("cp")
    a.lw("t3", 0, "t0")
    a.sw("t3", 0, "t1")
    a.cache(0x19, 0, "t1")            # HIT_WRITE_BACK_D
    a.addiu("t0", "t0", 4)
    a.bne("t0", "t2", "cp")
    a.addiu("t1", "t1", 4)            # (delay)
    if bootcheats_slot is not None:
        # Preserve boot-cheat writes: the BattleTanx clear is skipped whenever
        # the caller supplied a cheat-list pointer. Store before substituting
        # our own empty list for the no-cheats case.
        a.li('t0',bootcheats_slot);a.sw('v0',0,'t0');a.cache(0x19,0,'t0')
    a.bne("v0", "zero", "cont")
    a.nop()
    i_empty = len(a.items)
    a.lui("v0", 0)                    # fixado depois: lista vazia
    a.addiu("v0", "v0", 0)
    a.label("cont")
    a.j(ADDR_CONT)
    a.nop()
    a.label("noexp")
    a.bne("v0", "zero", "cont")
    a.nop()
    a.j(ADDR_NOCHEATS)
    a.nop()
    while (a.here() & 0xF) != 0:
        a.nop()
    stub = bytearray(a.build())
    blk_addr = CAVE + len(stub)
    empty_addr = blk_addr + len(igr_block)

    def hilo(v):
        lo = v & 0xFFFF
        hi = ((v >> 16) + (1 if lo & 0x8000 else 0)) & 0xFFFF
        return hi, lo

    def fix(idx, imm):
        w = struct.unpack_from(">I", stub, 4 * idx)[0]
        struct.pack_into(">I", stub, 4 * idx, (w & 0xFFFF0000) | (imm & 0xFFFF))

    h, l = hilo(blk_addr)
    fix(i_blk, h); fix(i_blk + 1, l)
    assert len(igr_block) < 0x8000
    fix(i_size, len(igr_block))
    h, l = hilo(empty_addr)
    fix(i_empty, h); fix(i_empty + 1, l)
    return bytes(stub) + igr_block + b"\0" * 16


# ---------------------------------------------------------------- LZ4
def lz4_decompress(src):
    out = bytearray()
    i = 0
    while i < len(src):
        tok = src[i]; i += 1
        ll = tok >> 4
        if ll == 15:
            while True:
                b = src[i]; i += 1; ll += b
                if b != 255:
                    break
        out += src[i:i + ll]; i += ll
        if i >= len(src):
            break
        off = src[i] | (src[i + 1] << 8); i += 2
        ml = tok & 15
        if ml == 15:
            while True:
                b = src[i]; i += 1; ml += b
                if b != 255:
                    break
        ml += 4
        st = len(out) - off
        assert off > 0 and st >= 0
        for k in range(ml):
            out.append(out[st + k])
    return bytes(out)


def lz4_compress(data, max_chain=96):
    n = len(data)
    out = bytearray()
    head = {}
    prev = [-1] * n
    MFLIMIT = 12
    LASTLITERALS = 5

    def insert(p):
        if p + 4 <= n:
            k = data[p:p + 4]
            prev[p] = head.get(k, -1)
            head[k] = p

    def best(p):
        if p + MFLIMIT > n:
            return 0, 0
        k = data[p:p + 4]
        c = head.get(k, -1)
        bl, bo = 0, 0
        limit = n - LASTLITERALS
        tries = 0
        while c >= 0 and p - c <= 0xFFFF and tries < max_chain:
            if p - c < 2:                    # o stream original nunca usa offset 1
                c = prev[c]
                continue
            if data[c + bl] == data[p + bl] if p + bl < limit else False:
                l = 0
                while p + l < limit and data[c + l] == data[p + l]:
                    l += 1
                if l > bl:
                    bl, bo = l, p - c
            c = prev[c]
            tries += 1
        return (bl, bo) if bl >= 4 else (0, 0)

    def emit(lit, ml, off):
        ll = len(lit)
        tok = (min(ll, 15) << 4) | (min(ml - 4, 15) if ml else 0)
        out.append(tok)
        if ll >= 15:
            r = ll - 15
            while r >= 255:
                out.append(255); r -= 255
            out.append(r)
        out.extend(lit)
        if ml:
            out.append(off & 0xFF); out.append(off >> 8)
            if ml - 4 >= 15:
                r = ml - 4 - 15
                while r >= 255:
                    out.append(255); r -= 255
                out.append(r)

    ins = 0

    def upto(t):
        nonlocal ins
        while ins < t:
            insert(ins)
            ins += 1

    p = 0
    anchor = 0
    while p < n:
        upto(p)
        ml, off = best(p)
        if ml:
            upto(p + 1)
            ml2, off2 = best(p + 1)          # lazy de 1 passo
            if ml2 > ml + 1:
                p += 1
                ml, off = ml2, off2
            emit(data[anchor:p], ml, off)
            p += ml
            anchor = p
        else:
            p += 1
    emit(data[anchor:], 0, 0)
    return bytes(out)


def lz4_worst(src):
    out = 0; i = 0; w = -10 ** 9
    while i < len(src):
        tok = src[i]; i += 1; ll = tok >> 4
        if ll == 15:
            while True:
                b = src[i]; i += 1; ll += b
                if b != 255:
                    break
        i += ll; out += ll; w = max(w, out - i)
        if i >= len(src):
            break
        i += 2; ml = tok & 15
        if ml == 15:
            while True:
                b = src[i]; i += 1; ml += b
                if b != 255:
                    break
        out += ml + 4; w = max(w, out - i)
    return w


def inplace_vaddr(paddr, X, comp):
    L = len(comp)
    w = lz4_worst(comp)
    m = max(w - (X - L) + 1, 0) + (L >> 8) + 0x40
    v = paddr + X - L + m
    return (v + 7) & ~7


# ---------------------------------------------------------------- principal
def patch_word(img, addr, expect, new):
    o = addr - IMG_BASE
    cur = struct.unpack_from(">I", img, o)[0]
    assert cur == expect, "0x%08X: esperado %08X, achado %08X" % (addr, expect, cur)
    struct.pack_into(">I", img, o, new)


def main(src_path, dst_path, debug=False, bt_no_igr=False):
    if os.path.realpath(src_path) == os.path.realpath(dst_path):
        raise ValueError("Use uma saída separada; preserve o menu original.")
    rom = bytearray(open(src_path, "rb").read())
    if hashlib.sha1(rom).hexdigest() != "ea59de2a307c7671a37aea0cb17ad97975fcf618":
        raise ValueError("Entrada precisa ser N64FlashcartMenu 0.3.5 original (SHA1 EA59DE2A…).")
    E0 = 0x1E00
    toc = 0x1930
    assert rom[toc:toc + 4] == b"TOC0"
    ent_size, n_ent = struct.unpack_from(">HH", rom, toc + 12)
    entries = []
    for k in range(n_ent):
        o = toc + 16 + k * ent_size
        off, size = struct.unpack_from(">II", rom, o)
        name = rom[o + 8:o + ent_size].split(b"\0")[0].decode()
        entries.append([o, off, size, name])
    assert entries[0][1] == E0 and entries[0][3].endswith(".elf.stripped")
    elf = bytes(rom[E0:E0 + entries[0][2]])
    assert elf[:4] == b"\x7fELF"
    phoff, = struct.unpack_from(">I", elf, 28)
    phn, = struct.unpack_from(">H", elf, 44)
    assert phn == 3
    ph = [list(struct.unpack_from(">8I", elf, phoff + 32 * k)) for k in range(3)]
    # ph: type, offset, vaddr, paddr, filesz, memsz, flags, align
    dec, seg1, seg2 = ph
    assert dec[0] == 0x64E36341 and seg2[3] == IMG_BASE and seg2[6] & 0x1000
    img = bytearray(lz4_decompress(elf[seg2[1]:seg2[1] + seg2[4]]))
    print("segmento principal: %d bytes descomprimidos" % len(img))

    igr, igr_labels = build_igr_block_v21r2(debug,bt_no_igr)
    cave = build_cave(igr,igr_labels['BOOTCHEATS'])
    assert CAVE + len(cave) <= HEAP_START, hex(CAVE + len(cave))
    assert CAVE >= seg2[3] + seg2[5]
    print("STUB+IGR: %d bytes em 0x%08X..0x%08X" % (len(cave), CAVE, CAVE + len(cave)))

    patch_word(img, ADDR_HOOK, 0x1040007E, 0x08000000 | ((CAVE >> 2) & 0x03FFFFFF))
    patch_word(img, ADDR_CIC6101_CASE, CIC6101_CASE_OLD, CIC6101_CASE_FIXED)
    patch_word(img, ADDR_ENGINE_J, 0x25080048, 0x3C080000 | (((0x08000000 | ((IGR_ADDR >> 2) & 0x03FFFFFF)) >> 16)))
    assert (IGR_ADDR >> 2) & 0xFFFF == 0, "IGR_ADDR precisa ser multiplo de 0x40000"
    lo = HEAP_START & 0xFFFF
    assert (HEAP_START >> 16) + (1 if lo & 0x8000 else 0) == 0x800E
    for a in ADDR_SBRK:
        patch_word(img, a, 0x2442AC48, 0x24420000 | lo)
    if USE_PREP:
        # Despacho V21 R2 -> v20 -> v19 -> v18 -> v17 -> v15 -> v14 -> prep v13.
        j_scan = 0x08000000 | ((igr_labels["dispatch_v21r2"] >> 2) & 0x03FFFFFF)
        assert (j_scan & 0xFFFF) < 0x8000
        patch_word(img, ADDR_PATCHER_JR[0], 0x3C020120, 0x3C020000 | (j_scan >> 16))
        patch_word(img, ADDR_PATCHER_JR[1], 0x24420008, 0x24420000 | (j_scan & 0xFFFF))

    print("comprimindo (LZ4)...")
    comp2 = lz4_compress(bytes(img))
    assert lz4_decompress(comp2) == bytes(img), "LZ4 do principal nao confere"
    comp3 = lz4_compress(cave)
    assert lz4_decompress(comp3) == cave
    print("principal: original %d, novo %d bytes" % (seg2[4], len(comp2)))

    # monta o ELF novo: cabecalho + 4 PH + dados alinhados em 8
    hdr = bytearray(elf[:52])
    struct.pack_into(">H", hdr, 44, 4)
    body = bytearray()
    cur = 52 + 32 * 4

    def place(blob):
        nonlocal cur, body
        pad = (-cur) % 8
        body += b"\0" * pad
        cur += pad
        off = cur
        body += blob
        cur += len(blob)
        return off

    dec_data = elf[dec[1]:dec[1] + dec[4]]
    seg1_data = elf[seg1[1]:seg1[1] + seg1[4]]
    nd = list(dec); nd[1] = place(dec_data)
    n1 = list(seg1); n1[1] = place(seg1_data)
    n2 = list(seg2); n2[1] = place(comp2); n2[4] = len(comp2)
    n2[2] = inplace_vaddr(seg2[3], len(img), comp2)
    n3 = [1, place(comp3), inplace_vaddr(CAVE, len(cave), comp3), CAVE, len(comp3), len(cave), seg2[6], seg2[7]]
    phs = b"".join(struct.pack(">8I", *p) for p in (nd, n1, n2, n3))
    new_elf = bytes(hdr) + phs + bytes(body)
    assert len(hdr) + len(phs) == 52 + 128
    for p in (nd, n1, n2, n3):
        print("PH type=%08X off=%06X vaddr=%08X paddr=%08X filesz=%06X memsz=%06X flags=%X" % tuple(p[:7]))

    # ROM nova: ELF no mesmo lugar; .sym move p/ o fim se nao couber
    elf_size16 = (len(new_elf) + 15) & ~15
    sym = [e for e in entries if e[3].endswith(".sym")][0]
    others = [e for e in entries if e is not entries[0]]
    out = bytearray(rom)
    if E0 + elf_size16 > sym[1]:
        sym_data = bytes(rom[sym[1]:sym[1] + sym[2]])
        end = max(e[1] + e[2] for e in others)
        new_sym = max((end + 0xFFF) & ~0xFFF, len(rom))
        new_len = (new_sym + len(sym_data) + 0xFFFF) & ~0xFFFF
        out += b"\0" * (new_len - len(out))
        out[new_sym:new_sym + len(sym_data)] = sym_data
        struct.pack_into(">I", out, sym[0], new_sym)
        out[sym[1]:sym[1] + sym[2]] = b"\0" * sym[2]
        print(".sym movido de 0x%X para 0x%X" % (sym[1], new_sym))
        limit = min(e[1] for e in others if e is not sym)
    else:
        limit = sym[1]
    assert E0 + elf_size16 <= limit, "ELF novo nao cabe"
    out[E0:E0 + entries[0][2]] = b"\0" * entries[0][2]
    out[E0:E0 + len(new_elf)] = new_elf
    struct.pack_into(">I", out, entries[0][0] + 4, elf_size16)
    open(dst_path, "wb").write(out)
    print("gravado: %s (%d bytes)" % (dst_path, len(out)))


if __name__ == "__main__":
    main(sys.argv[1], sys.argv[2], "--diag" in sys.argv[3:],"--bt-no-igr" in sys.argv[3:])
