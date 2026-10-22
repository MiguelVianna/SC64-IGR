"""1080 D4 experiment: single bounded filler attempt for isolated CMD_BUSY.

Evidence: physical D3 photo C0, SP halted/DMA idle, CURRENT==END. This does not
prove a partial command. Keep full idle requirement after own list; never
continue into PI/SC64 if recovery fails. No normal-game startup changes.
"""
import struct
import build_igr as B
import build_bassmasters_candidate as Bass
import return_diagnostic_1080 as D
from build_dk_tag_candidate import EXTRA
from reserved_runtime import MM,DK
DK_MEM8=dict(DK,restore_memsize=0x800000)
PROFILES=(MM,DK_MEM8)
SAVE_REGS=D.SAVE_REGS
FRAMEBUFFER=D.FRAMEBUFFER
REGISTERS=D.REGISTERS
GLYPHS=D.GLYPHS
VI_PRESETS=D.VI_PRESETS
STAGES=dict(D.STAGES)
STAGES[0xd403]=3

def recovery_runtime(unused=False):
 raw,l=Bass.runtime();data=bytearray(raw);a=B.Asm(B.IGR_ADDR+len(raw))
 # Hook only the failure of the pre-filler recovery. Final failure remains
 # terminal, so this queue submission cannot be retried indefinitely.
 old=0x08000000|((l['rdp_unrecovered']>>2)&0x3ffffff)
 sites=[i for i in range(l['r2_rdp_recover']-B.IGR_ADDR,l['r2_rdp_before_pi']-B.IGR_ADDR,4) if struct.unpack_from('>I',data,i)[0]==old]
 assert len(sites)==1
 target=l['rdp_switch_after_idle']+20
 assert struct.unpack_from('>III',data,target-B.IGR_ADDR)==(0x34090001,0xad49000c,0xf)
 a.label('d4_cmd_only_recovery')
 a.lui('t0',0xb000)
 for off,value in ((0x3c,0x54454100),(0x10,0x1fbaf161),(0x14,0x2c1c54f1)):
  a.lw('t1',off,'t0');a.li('t3',value);a.bne('t1','t3','d4_reject');a.nop()
 # Report the attempted mechanism, then validate again after display pause.
 a.ori('a0','zero',0xd403);a.jal(l['paint']);a.nop()
 a.lui('t0',0xa404);a.lw('t1',0x10,'t0');a.andi('t3','t1',1)
 a.beq('t3','zero','d4_reject');a.nop();a.andi('t3','t1',0xc)
 a.bne('t3','zero','d4_reject');a.nop();a.lw('t1',0x18,'t0')
 a.bne('t1','zero','d4_reject');a.nop()
 a.lui('t2',0xa410);a.lw('t1',0xc,'t2');a.ori('t0','zero',0xc0)
 a.bne('t1','t0','d4_reject');a.nop()
 a.lw('t3',0,'t2');a.lw('t4',4,'t2');a.lw('t5',8,'t2')
 a.bne('t4','t5','d4_reject');a.nop()
 a.or_('t0','t3','t4');a.andi('t0','t0',7);a.bne('t0','zero','d4_reject');a.nop()
 a.beq('t3','zero','d4_reject');a.nop()
 a.sltu('t0','t3','t4');a.beq('t0','zero','d4_reject');a.nop()
 a.lui('t0',0x40);a.sltu('t0','t4','t0');a.beq('t0','zero','d4_reject');a.nop()
 # Two samples: no source switch/START/END if the snapshot changed.
 a.lw('t1',0xc,'t2');a.ori('t0','zero',0xc0);a.bne('t1','t0','d4_reject');a.nop()
 for off,reg in ((0,'t3'),(4,'t4'),(8,'t5')):
  a.lw('t1',off,'t2');a.bne('t1',reg,'d4_reject');a.nop()
 a.label('d4_submit_once');a.j(target);a.nop()
 a.label('d4_reject');a.j(l['rdp_unrecovered']);a.nop()
 struct.pack_into('>I',data,sites[0],0x08000000|((a.labels['d4_cmd_only_recovery']>>2)&0x3ffffff))
 return bytes(data)+a.build(),dict(l,**a.labels)

def build_runtime(debug=False,bt_no_igr=False):
 return D.build_runtime(debug,bt_no_igr,base_builder=recovery_runtime,banner=0xd421,stages=STAGES)

def cave():
 import build_three_games_candidate as C
 return C.cave(build_runtime,EXTRA,PROFILES)

def main(src,dst):
 import build_three_games_candidate as C
 return C.main(src,dst,build_runtime,EXTRA,PROFILES)
if __name__=='__main__':
 import sys
 main(*sys.argv[1:])
