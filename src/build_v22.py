"""V22 = V21 (Codex, sc64menuV21 (2).n64) + porta "segura por padrao" antes do STUB.

A porta roda no boot do jogo (dentro de cheats_install, interrupcoes ja desligadas) e decide:
  - jogo na LISTA de exclusao (ID de 2 letras em 0xB000003C)  -> caminho original do menu
  - CIMA segurado no controle 1 (leitura joybus propria pelo SI) -> caminho original do menu
    (V22 usava Z; V23 L; V24 = mesma porta com direcional CIMA)
  - jogo na lista MEM4 (V25)                                   -> STUB da V21 com osMemSize = 4 MB
  - senao                                                      -> STUB da V21 (instala IGR)
"Caminho original" = cheat_list zerado + j 0x80029308: sem motor, sem bloco IGR em 0x807C0000,
clear_rdram/reset de RDRAM como no menu de fabrica (cheats tambem ficam de fora).

Unicas palavras mexidas fora da area nova: 0x800DAD00/04 do STUB (lui t0 / lw t1 -> j PORTA / nop).
Area nova: 0x800DF280..0x800DF800 (fim do segmento IGR da V21 .. inicio do heap 0x800DF800).
"""
import struct
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import build_igr as B

V21_SHA256 = "092540bb1e82d63e2e103339e797a6ab694021d29bf6542f810dc7f3ba627c40"
STUB = 0x800DAD00
STUB_AFTER_LW = 0x800DAD08     # apos "lui t0,0x800D / lw t1,-0x4E64(t0)"
ADDR_NOCHEATS = 0x80029308
HEAP_V21 = 0x800DF800
GATE = 0x800DF280

# IDs (bytes 0x3C..0x3D do cabecalho), todas as regioes. Jogos que nao abrem/travam com IGR.
EXCLUDE = {
    "ZS": "Zelda Majora's Mask",
    "DO": "Donkey Kong 64",
    "AM": "Army Men Sarge's Heroes",   # sonda a RAM sozinho (osGetMemSize): o truque de 4 MB nao engana
}
# V25 (experimental): IGR instalado, mas osMemSize = 4 MB, p/ o jogo nao usar 0x80400000+ (onde fica o IGR).
# Jogos que nao exigem Expansion Pak. CIMA segurado continua abrindo limpo.
MEM4 = {
    "TF": "Tony Hawk's Pro Skater",
    "TQ": "Tony Hawk's Pro Skater 2",
    "3T": "Tony Hawk's Pro Skater 3",
    "TE": "1080 Snowboarding",
    "B4": "Bassmasters 2000",
    "EP": "Star Wars Episode I Racer",
}
STUB_COPY = 0x800DAD24         # STUB da V21 apos gravar osMemSize (copia do bloco IGR em diante)
Z_MASK = 0x0800                # V24: direcional CIMA (V22 Z 0x2000 abre menu no emulador; V23 L 0x0020 tem funcao no menu)
SPIN = 0x00100000              # limite das esperas do SI (~1/4 s); estourou -> segue como a V21


def build_gate():
    a = B.Asm(GATE)
    # ---- ID do jogo (cartucho ja configurado no PI pelo boot)
    a.lui("t4", 0xB000)
    a.lw("t5", 0x3C, "t4")
    a.srl("t5", "t5", 16)
    a.lui("t6", 0)                    # fixado: LIST
    a.addiu("t6", "t6", 0)
    i_list = len(a.items) - 2
    a.addu("t3", "zero", "zero")      # t3 = 1 -> modo 4 MB (t0..t3 livres ate o STUB)
    a.label("lst")
    a.lw("t7", 0, "t6")               # (flag << 16) | ID
    a.beq("t7", "zero", "joy")
    a.andi("t2", "t7", 0xFFFF)        # (delay)
    a.bne("t2", "t5", "lst")
    a.addiu("t6", "t6", 4)            # (delay)
    a.srl("t3", "t7", 16)
    a.beq("t3", "zero", "skip")
    a.nop()
    # ---- controle 1 pelo joybus (bloco libultra FF010401)
    a.label("joy")
    a.lui("t4", 0xA480)               # SI
    a.lui("t8", SPIN >> 16)
    a.label("w0")
    a.lw("t5", 0x18, "t4")
    a.andi("t5", "t5", 3)
    a.beq("t5", "zero", "w0ok")
    a.addiu("t8", "t8", -1)
    a.bne("t8", "zero", "w0")
    a.nop()
    a.beq("zero", "zero", "pass")
    a.nop()
    a.label("w0ok")
    a.lui("t6", 0)                    # fixado: BUF (cached)
    a.addiu("t6", "t6", 0)
    i_buf = len(a.items) - 2
    for k in range(4):                # tira o buffer do cache D antes do DMA
        a.cache(0x15, 16 * k, "t6")   # HIT_WRITEBACK_INVALIDATE_D
    a.lui("t7", 0x2000)
    a.addu("t7", "t6", "t7")          # t7 = BUF | 0xA0000000 (sem cache)
    a.li("t9", 0xFF010401); a.sw("t9", 0x00, "t7")
    a.li("t9", 0xFFFFFFFF); a.sw("t9", 0x04, "t7")
    a.li("t9", 0xFE000000); a.sw("t9", 0x08, "t7")
    for off in range(0x0C, 0x3C, 4):
        a.sw("zero", off, "t7")
    a.li("t9", 0x00000001); a.sw("t9", 0x3C, "t7")
    a.lui("t9", 0x1FFF)
    a.ori("t9", "t9", 0xFFFF)
    a.r("t6", "t9", "t9", 0, 0x24)    # and t9, t6, t9 = endereco fisico
    a.lui("t5", 0x1FC0)
    a.ori("t5", "t5", 0x07C0)
    # escrita 64 B (executa os comandos)
    a.sw("t9", 0x00, "t4")
    a.sw("t5", 0x10, "t4")
    a.lui("t8", SPIN >> 16)
    a.label("w1")
    a.lw("t6", 0x18, "t4")
    a.andi("t6", "t6", 3)
    a.beq("t6", "zero", "w1ok")
    a.addiu("t8", "t8", -1)
    a.bne("t8", "zero", "w1")
    a.nop()
    a.beq("zero", "zero", "pass")
    a.nop()
    a.label("w1ok")
    a.sw("zero", 0x18, "t4")          # limpa interrupcao SI
    # leitura 64 B (respostas)
    a.sw("t9", 0x00, "t4")
    a.sw("t5", 0x04, "t4")
    a.lui("t8", SPIN >> 16)
    a.label("w2")
    a.lw("t6", 0x18, "t4")
    a.andi("t6", "t6", 3)
    a.beq("t6", "zero", "w2ok")
    a.addiu("t8", "t8", -1)
    a.bne("t8", "zero", "w2")
    a.nop()
    a.beq("zero", "zero", "pass")
    a.nop()
    a.label("w2ok")
    a.sw("zero", 0x18, "t4")
    a.lw("t5", 0x00, "t7")
    a.li("t9", 0xFF010401)            # controle presente e sem erro
    a.bne("t5", "t9", "pass")
    a.nop()
    a.lw("t5", 0x04, "t7")
    a.srl("t5", "t5", 16)
    a.andi("t5", "t5", Z_MASK)
    a.bne("t5", "zero", "skip")
    a.nop()
    # ---- segue para o STUB da V21 (refaz as 2 instrucoes trocadas)
    a.label("pass")
    a.lui("t0", 0x800D)
    a.bne("t3", "zero", "mem4")
    a.lw("t1", -0x4E64, "t0")         # (delay) __boot_memsize do menu
    a.j(STUB_AFTER_LW)
    a.nop()
    # ---- modo 4 MB: mesma regra de RAM do STUB, mas grava osMemSize = 0x400000
    a.label("mem4")
    a.lui("t2", 0x007C)
    a.r("t1", "t2", "t2", 0, 0x2A)    # slt t2, t1, t2
    a.bne("t2", "zero", "nomem")      # sem Expansion Pak: o STUB decide (sem IGR)
    a.nop()
    a.lui("t3", 0x8000)
    a.lui("t1", 0x0040)
    a.sw("t1", 0x0318, "t3")          # osMemSize = 4 MB
    a.cache(0x19, 0x0318, "t3")       # HIT_WRITE_BACK_D
    a.j(STUB_COPY)
    a.nop()
    a.label("nomem")
    a.j(STUB_AFTER_LW)
    a.nop()
    # ---- jogo limpo: como o menu de fabrica sem cheats
    a.label("skip")
    a.addu("v0", "zero", "zero")
    a.j(ADDR_NOCHEATS)
    a.nop()
    while (a.here() & 0xF) != 0:
        a.nop()
    code = bytearray(a.build())
    list_addr = GATE + len(code)
    ent = [(0, k) for k in EXCLUDE] + [(1, k) for k in MEM4]
    lst = b"".join(struct.pack(">I", (f << 16) | (ord(k[0]) << 8) | ord(k[1])) for f, k in ent) + b"\0" * 4
    buf_addr = (list_addr + len(lst) + 63) & ~63
    blob = code + lst + b"\0" * (buf_addr - list_addr - len(lst)) + b"\0" * 64

    def fix(idx, v):
        lo = v & 0xFFFF
        hi = ((v >> 16) + (1 if lo & 0x8000 else 0)) & 0xFFFF
        for j, imm in ((idx, hi), (idx + 1, lo)):
            w = struct.unpack_from(">I", blob, 4 * j)[0]
            struct.pack_into(">I", blob, 4 * j, (w & 0xFFFF0000) | imm)

    fix(i_list, list_addr)
    fix(i_buf, buf_addr)
    assert GATE + len(blob) <= HEAP_V21, hex(GATE + len(blob))
    return bytes(blob), list_addr, buf_addr


def main(src, dst):
    import hashlib
    rom = bytearray(open(src, "rb").read())
    assert hashlib.sha256(rom).hexdigest() == V21_SHA256, "nao e a V21 (2) esperada"
    E0, toc = 0x1E00, 0x1930
    es, n = struct.unpack_from(">HH", rom, toc + 12)
    ents = []
    for k in range(n):
        o = toc + 16 + k * es
        off, size = struct.unpack_from(">II", rom, o)
        ents.append([o, off, size, rom[o + 8:o + es].split(b"\0")[0].decode()])
    elf = bytes(rom[E0:E0 + ents[0][2]])
    phoff, = struct.unpack_from(">I", elf, 28)
    phn, = struct.unpack_from(">H", elf, 44)
    assert phn == 4
    ph = [list(struct.unpack_from(">8I", elf, phoff + 32 * k)) for k in range(4)]
    s4 = ph[3]
    assert s4[3] == STUB
    cave = bytearray(B.lz4_decompress(elf[s4[1]:s4[1] + s4[4]]))
    assert len(cave) == s4[5]
    assert struct.unpack_from(">II", cave, 0) == (0x3C08800D, 0x8D09B19C)
    assert STUB + len(cave) <= GATE

    gate, list_addr, buf_addr = build_gate()
    # 0x800DAD00 j PORTA / 0x800DAD04 nop (o lw original no delay usaria t0 do chamador -> excecao)
    struct.pack_into(">II", cave, 0, 0x08000000 | ((GATE >> 2) & 0x03FFFFFF), 0)
    cave += b"\0" * (GATE - STUB - len(cave))
    cave += gate
    print("porta: 0x%08X..0x%08X (lista 0x%08X, buffer 0x%08X)" % (GATE, STUB + len(cave), list_addr, buf_addr))

    comp = B.lz4_compress(bytes(cave))
    assert B.lz4_decompress(comp) == bytes(cave)
    hdr = bytearray(elf[:52])
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

    new_ph = []
    for p in ph[:3]:
        q = list(p); q[1] = place(elf[p[1]:p[1] + p[4]]); new_ph.append(q)
    q = list(s4); q[1] = place(comp); q[4] = len(comp); q[5] = len(cave)
    q[2] = B.inplace_vaddr(STUB, len(cave), comp)
    new_ph.append(q)
    new_elf = bytes(hdr) + b"".join(struct.pack(">8I", *p) for p in new_ph) + bytes(body)
    for p in new_ph:
        print("PH type=%08X off=%06X vaddr=%08X paddr=%08X filesz=%06X memsz=%06X" % tuple(p[:6]))
    size16 = (len(new_elf) + 15) & ~15
    assert E0 + size16 <= min(e[1] for e in ents[1:]), "ELF novo nao cabe"
    rom[E0:E0 + ents[0][2]] = b"\0" * ents[0][2]
    rom[E0:E0 + len(new_elf)] = new_elf
    struct.pack_into(">I", rom, ents[0][0] + 4, size16)
    open(dst, "wb").write(rom)
    print("gravado:", dst, hashlib.sha256(rom).hexdigest())


if __name__ == "__main__":
    main(sys.argv[1], sys.argv[2])
