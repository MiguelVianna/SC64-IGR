"""1080 D3 diagnostic, separate from the hardware approved three-game menu.
Exact NTEA00/CRC selection at reset. CPU draws in the existing 1080 reserve.
No assertion of physical display, mapper correctness or a repaired return.
Derived from the archived D2 screen; the archive remains unchanged.
"""
import struct
import build_igr as B
import build_bassmasters_candidate as Bass

BASE_BUILDER = lambda unused: Bass.runtime()
MENU_HEAP = 0x800E0800
FRAMEBUFFER = 0xA07D0000
SAVE_REGS = tuple(r for r in B.REG if r not in ('zero','k0','k1'))
REGISTERS = (0xA4040010,0xA4040018,0xA410000C,0xA4100000,
             0xA4100004,0xA4100008,0xA4600010,0xA4080000)
FIELDS = ('SP_STATUS','SP_DMA_BUSY','DP_STATUS','DP_START','DP_END','DP_CURRENT','PI_STATUS','SP_PC')
# Own hexadecimal font and progressive presets, previously reviewed in D1.
# D1's suspended runtime/builder is not executed or resumed.
GLYPHS = ('111101101101111','010110010010111','111001111100111','111001111001111',
          '101101111001001','111100111001111','111100111101111','111001001001001',
          '111101111101111','111101111001111','111101111101101','110101110101110',
          '111100100100111','110101101101110','111100110100111','111100110100100')
VI_PRESETS = (
 (0x0404233A,0x271,0x00150C69,0x0C6F0C6E,0x00800300,0x005F0239,0x0009026B),
 (0x03E52239,0x20D,0x00000C15,0x0C150C15,0x006C02EC,0x002501FF,0x000E0204),
 (0x04651E39,0x20D,0x00040C11,0x0C190C1A,0x006C02EC,0x002501FF,0x000E0204))
STAGES = {B.COR_BRANCO[0]:1,0xD202:2,B.COR_CIANO[0]:4,
          B.COR_VERMELHO[0]:5,B.COR_AMARELO[0]:6,B.COR_VERDE[0]:7,
          B.COR_AZUL[0]:8,B.COR_MAGENTA[0]:15}


def build_runtime(debug=False, bt_no_igr=False, *, base_builder=None, banner=0xD321, stages=None):
    assert not debug and not bt_no_igr, 'D2 has one distinct diagnostic output'
    stages=STAGES if stages is None else stages
    raw, labels = (base_builder or BASE_BUILDER)(False); data=bytearray(raw)
    a=B.Asm(B.IGR_ADDR+len(raw));fix=[]
    def addr(reg,label):
        a.lui(reg,0xA07C);fix.append((len(a.items),reg,label));a.word(0)
    # Select once before reset; cart header may change after bootloader switch.
    a.label('d3_reset_gate');addr('k1','d3_enabled');a.sw('zero',0,'k1')
    a.lui('k0',0xB000)
    for off,value in ((0x3c,0x54454100),(0x10,0x1FBAF161),(0x14,0x2C1C54F1)):
        a.lw('t0',off,'k0');a.li('t1',value)
        a.bne('t0','t1','d3_reset_original');a.nop()
    a.ori('k0','zero',1);a.sw('k0',0,'k1')
    a.label('d3_reset_original')
    a.word(0x3C08A440);a.word(0xAD000000)
    a.j(labels['r2_reboot']+8);a.nop()
    a.label('d3_paint_gate');addr('k1','d3_enabled');a.lw('k0',0,'k1')
    a.bne('k0','zero','d2_paint');a.nop();a.jr('ra');a.nop()
    a.label('d2_paint');addr('k1','d2_saved')
    for i,r in enumerate(SAVE_REGS):a.i(0x3F,'k1',r,8*i)
    a.ori('t1','zero',0xEE)
    for color,stage in stages.items():
        a.li('t0',color);a.beq('a0','t0','d2_stage_'+str(stage));a.nop()
    a.j('d2_selected');a.nop()
    for stage in stages.values():
        a.label('d2_stage_'+str(stage));a.ori('t1','zero',stage);a.j('d2_selected');a.nop()
    a.label('d2_selected');addr('t0','d2_phase');a.sw('t1',0,'t0')
    addr('t0','d2_snapshot')
    for i,register in enumerate(REGISTERS):
        a.li('t1',register);a.lw('t2',0,'t1');a.sw('t2',4*i,'t0')
    # Two native scratch values help identify failed SC64 identifier/command
    # checks without making extra reads of the locked flashcart registers.
    addr('t1','d2_saved')
    for i,r in enumerate(('t1','t4')):
        a.lw('t2',8*SAVE_REGS.index(r)+4,'t1');a.sw('t2',32+4*i,'t0')
    a.jal('d2_render');a.nop()
    addr('t0','d2_phase');a.lw('t0',0,'t0');a.ori('t1','zero',15)
    a.beq('t0','t1','d2_stopped');a.nop()
    a.jal('d2_pause');a.nop()
    addr('k1','d2_saved')
    for i,r in enumerate(SAVE_REGS):a.i(0x37,'k1',r,8*i)
    a.jr('ra');a.nop()
    a.label('d2_stopped');a.j('d2_stopped');a.nop()
    # A short observation pause makes stages readable on a physical TV. It
    # changes timing, so a successful diagnostic alone is never called a fix.
    a.label('d2_pause');a.word(0x40024800);a.li('v1',11718750)
    a.label('d2_pause_loop');a.word(0x40194800);a.subu('t9','t9','v0')
    a.sltu('t9','t9','v1');a.bne('t9','zero','d2_pause_loop');a.nop()
    a.jr('ra');a.nop()

    # Observe whether the native RSP wait ended naturally before SET_HALT.
    lo=labels['reboot']-B.IGR_ADDR;hi=labels['paint']-B.IGR_ADDR
    needle=struct.pack('>II',0x3C0900AA,0x3529AAAE);at=data.find(needle,lo,hi)
    assert at>=0 and data.find(needle,at+4,hi)<0
    a.label('d3_rsp_gate');addr('k1','d3_enabled');a.lw('k0',0,'k1')
    a.bne('k0','zero','d2_rsp_wait_done');a.nop()
    a.word(0x3C0900AA);a.word(0x3529AAAE);a.j(B.IGR_ADDR+at+8);a.nop()
    a.label('d2_rsp_wait_done');a.ori('a0','zero',0xD202)
    a.jal(a.labels['d2_paint']);a.nop()
    a.word(0x3C0900AA);a.word(0x3529AAAE);a.j(B.IGR_ADDR+at+8);a.nop()

    a.label('d2_render')
    a.li('t0',FRAMEBUFFER);a.li('t1',FRAMEBUFFER+320*240*2);a.li('t2',0x00010001)
    a.label('d2_clear');a.sw('t2',0,'t0');a.addiu('t0','t0',4)
    a.bne('t0','t1','d2_clear');a.nop()
    # The renderer calls hex, so preserve its return in a private word.
    addr('t0','d2_render_ra');a.sw('ra',0,'t0')
    addr('t0','d2_phase');a.lw('a0',0,'t0');a.lui('t1',banner);a.or_('a0','a0','t1')
    a.li('a1',FRAMEBUFFER+16*640+24*2);a.jal('d2_hex');a.nop()
    addr('s0','d2_snapshot');a.ori('s1','zero',0)
    a.label('d2_row');a.lw('a0',0,'s0')
    a.sll('t0','s1',13);a.sll('t1','s1',11);a.addu('t0','t0','t1')
    a.li('a1',FRAMEBUFFER+48*640+24*2);a.addu('a1','a1','t0')
    a.jal('d2_hex');a.nop();a.addiu('s0','s0',4);a.addiu('s1','s1',1)
    a.sltiu('t0','s1',10);a.bne('t0','zero','d2_row');a.nop()
    a.lui('t0',0x8000);a.lw('t1',0x300,'t0');a.sltiu('t2','t1',3)
    a.bne('t2','zero','d2_tv_valid');a.nop();a.ori('t1','zero',1)
    a.label('d2_tv_valid');a.sll('t1','t1',5);addr('t0','d2_vi');a.addu('t0','t0','t1')
    a.lui('t1',0xA440);a.sw('zero',0,'t1')
    a.li('t2',FRAMEBUFFER&0xFFFFFF);a.sw('t2',4,'t1');a.ori('t2','zero',320);a.sw('t2',8,'t1')
    for i in range(7):a.lw('t2',4*i,'t0');a.sw('t2',20+4*i,'t1')
    a.ori('t2','zero',0x200);a.sw('t2',48,'t1');a.ori('t2','zero',0x400);a.sw('t2',52,'t1')
    a.word(0xF);a.ori('t2','zero',0x3202);a.sw('t2',0,'t1');a.word(0xF)
    addr('t0','d2_render_ra');a.lw('ra',0,'t0');a.jr('ra');a.nop()

    a.label('d2_hex');a.ori('t9','zero',8);a.li('t5',0xFFFFFFFF)
    a.label('d2_digit');a.srl('t0','a0',28);a.sll('t0','t0',2);addr('t1','d2_font')
    a.addu('t1','t1','t0');a.lw('t3',0,'t1');a.ori('t4','zero',0x4000)
    a.ori('t1','zero',5);a.or_('t6','a1','zero')
    a.label('d2_glyph_row');a.ori('t7','zero',3)
    a.label('d2_glyph_col');a.and_('t8','t3','t4');a.beq('t8','zero','d2_pixel_skip');a.nop()
    a.sw('t5',0,'t6');a.sw('t5',640,'t6')
    a.label('d2_pixel_skip');a.srl('t4','t4',1);a.addiu('t6','t6',4);a.addiu('t7','t7',-1)
    a.bne('t7','zero','d2_glyph_col');a.nop();a.addiu('t6','t6',1268);a.addiu('t1','t1',-1)
    a.bne('t1','zero','d2_glyph_row');a.nop();a.addiu('a1','a1',16);a.sll('a0','a0',4)
    a.addiu('t9','t9',-1);a.bne('t9','zero','d2_digit');a.nop();a.jr('ra');a.nop()

    while a.here()%8:a.nop()
    a.label('d2_saved')
    for _ in range(2*len(SAVE_REGS)):a.word(0)
    a.label('d3_enabled');a.word(0)
    a.label('d2_phase');a.word(0)
    a.label('d2_snapshot')
    for _ in range(10):a.word(0)
    a.label('d2_render_ra');a.word(0)
    a.label('d2_font')
    for g in GLYPHS:a.word(int(g,2))
    a.label('d2_vi')
    for preset in VI_PRESETS:
        for value in (*preset,0):a.word(value)
    for i,r,label in fix:
        offset=a.labels[label]-B.IGR_ADDR;assert 0<=offset<0x8000
        a.items[i]=('w',0x34000000|(B.REG[r]<<21)|(B.REG[r]<<16)|offset)
    for offset,target in ((labels['paint']-B.IGR_ADDR,a.labels['d3_paint_gate']),
                          (at,a.labels['d3_rsp_gate']),
                          (labels['r2_reboot']-B.IGR_ADDR,a.labels['d3_reset_gate'])):
        struct.pack_into('>II',data,offset,0x08000000|((target>>2)&0x3FFFFFF),0)
    block=bytes(data)+a.build();assert len(block)<0x5C00
    return block,dict(labels,**a.labels)


def build_menu(original,output):
    import build_three_games_candidate as C
    return C.main(original,output,runtime_builder=build_runtime)

if __name__=='__main__':
    import sys
    build_menu(*sys.argv[1:])
