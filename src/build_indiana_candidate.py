"""Exact Indiana US binding: preserve native VM exception chain and cap arena."""
import struct
import build_igr as B
import build_three_games_candidate as C
import return_quiet_1080 as Q
HEADER=(0x494a4500,0xaf9dcc15,0x1a723d88)
GUARDS=((0x80000400,0x3c1d803f),(0x80000404,0x37bdfff0),
 (0x800008e4,0x3c1a8000),(0x800008e8,0x375a0ae0),
 (0x800008ec,0x03400008),(0x800008f0,0),
 (0x80000958,0xad2a0000),(0x800009a4,0xad0a0000),
 (0x80036130,0x8c440318),(0x8003648c,0x8c440318),
 (0x8003c6c0,0x3c1a4004),(0x8003c6c4,0x275ac6d0),
 (0x8003c6c8,0x03400008),(0x8003c6cc,0))

def runtime():
 raw,l=Q.build_runtime();data=bytearray(raw);a=B.Asm(B.IGR_ADDR+len(raw))
 a.label('indiana_dispatch');a.lui('t3',0xb000)
 for off,w in zip((0x3c,0x10,0x14),HEADER):
  a.lw('t4',off,'t3');a.li('t5',w);a.bne('t4','t5','indiana_fallback');a.nop()
 a.li('t5',0x80000400);a.bne('t1','t5','indiana_reject');a.nop()
 for addr,w in GUARDS:
  a.li('t6',addr);a.lw('t4',0,'t6');a.li('t5',w);a.bne('t4','t5','indiana_reject');a.nop()
 # Native libultra template must remain original: VM saves it at80000B48.
 # Only the VM's own later template is diverted. WatchLo would intercept the
 # intermediate vector copy and corrupt this chain, so turn it off first.
 a.mtc0('zero',18);a.nop()
 def patch(addr,w):
  a.li('t6',addr);a.li('t4',w);a.sw('t4',0,'t6');a.cache(0x19,0,'t6');a.word(0xf);a.cache(0x10,0,'t6');a.word(0xf)
 patch(0x80000318,0x7c0000)
 patch(l['ORIG'],0x80000ae0);patch(l['TPLFLAG'],1)
 eb=l['entryB'];patch(0x800008e4,0x3c1a0000|(eb>>16));patch(0x800008e8,0x375a0000|(eb&65535))
 a.jr('t1');a.nop()
 a.label('indiana_reject');a.mtc0('zero',18);a.nop();a.jr('t1');a.nop()
 a.label('indiana_fallback');a.j(l['bass_probe_guard']);a.nop()
 site=l['r2_reboot']-B.IGR_ADDR-8
 assert struct.unpack_from('>II',data,site)==(0x08000000|((l['bass_probe_guard']>>2)&0x3ffffff),0)
 struct.pack_into('>I',data,site,0x08000000|((a.labels['indiana_dispatch']>>2)&0x3ffffff))
 return bytes(data)+a.build(),dict(l,**a.labels)

def cave():return C.cave(runtime,Q.EXTRA,Q.PROFILES,common_headers=(HEADER,))
def main(src,dst):return C.main(src,dst,cave_builder=cave)
if __name__=='__main__':
 import sys
 main(*sys.argv[1:])
