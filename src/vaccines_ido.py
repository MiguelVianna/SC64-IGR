"""Additional compiler layout for the guarded native WatchLo/vector recipe.

No game ID/CRC selects this recipe. Follow BSS -> main -> osInitialize,
verify the setter, all four vector copies and all four template pointers.
Existing protected families retain their released paths.
"""
import struct
from vaccines import SETTER
PUBLISH=(
0x3C080000,0x25080000,0x8D010000,0x3C198000,0x3C0D0000,0xAF210000,0x8D0B0004,0x25AD0000,
0x3C0C8000,0xAF2B0004,0x8D010008,0x358C0080,0x3C090000,0xAF210008,0x8D0B000C,0x25290000,
0x3C0A8000,0xAF2B000C,0x8DA10000,0x354A0100,0x3C0E0000,0xAD810000,0x8DB80004,0x25CE0000,
0x3C0F8000,0xAD980004,0x8DA10008,0x35EF0180,0x3C048000,0xAD810008,0x8DB8000C,0x24050190,
0xAD98000C,0x8D210000,0xAD410000,0x8D2B0004,0xAD4B0004,0x8D210008,0xAD410008,0x8D2B000C,
0xAD4B000C,0x8DC10000,0xADE10000,0x8DD80004,0xADF80004,0x8DC10008,0xADE10008,0x8DD8000C,
0x0C000000,0xADF8000C)
MASKS=tuple(0xFFFF0000 if i in (0,1,4,7,12,15,20,23) else 0xFC000000 if i==48 else 0xFFFFFFFF for i in range(50))
BOOT_HI={0:0x3C08,4:0x3C09,8:0x2508,12:0x3529,36:0x3C0A,40:0x3C1D,44:0x254A,52:0x27BD}
BOOT_FIXED={16:0x2129FFF8,20:0xAD000000,24:0xAD000004,28:0x1520FFFC,32:0x21080008,48:0x01400008}

def recognize(data,entry):
 w=lambda x:struct.unpack_from('>I',data,x-entry)[0]
 end=entry+len(data)
 def valid(p,n):return p%4==0 and entry<=p<=end-n
 def pointer(p,hi,lo):
  low=w(p+lo)&65535;return ((w(p+hi)&65535)<<16)+(low if low<32768 else low-65536)
 if any(w(entry+o)>>16!=v for o,v in BOOT_HI.items()) or any(w(entry+o)!=v for o,v in BOOT_FIXED.items()):return None
 main=pointer(entry,36,44)
 if not valid(main,16) or w(main)!=0x27BDFFE0 or w(main+4)!=0xAFBF001C or w(main+8)>>26!=3 or w(main+12):return None
 init=0x80000000|((w(main+8)&0x3FFFFFF)<<2)
 if not valid(init,0x17C) or tuple(w(init+x) for x in (0,4,8))!=(0x27BDFFC8,0xAFBF001C,0x240E0001):return None
 call=init+0x3C;pub=call+0x78
 if w(call)>>26!=3 or w(call+4)!=0x3C040490:return None
 setter=0x80000000|((w(call)&0x3FFFFFF)<<2)
 if not valid(setter,16) or tuple(w(setter+4*i) for i in range(4))!=SETTER:return None
 if any(w(pub+4*i)&m!=v&m for i,(v,m) in enumerate(zip(PUBLISH,MASKS))):return None
 template=pointer(pub,0,4)
 if not valid(template,16) or any(pointer(pub,hi,lo)!=template for hi,lo in ((16,28),(48,60),(80,92))):return None
 if w(template)>>16!=0x3C1A or w(template+4)>>16!=0x275A or w(template+8)!=0x03400008 or w(template+12):return None
 handler=pointer(template,0,4)
 if not valid(handler,4):return None
 return dict(main=main,init=init,call=call,setter=setter,publisher=pub,template=template,handler=handler)

def emit(Asm,start,labels,igr_addr,protected):
 a=Asm(start);a.label('ido_table')
 for word,mask in zip(PUBLISH,MASKS):a.word(word);a.word(mask)
 a.label('dispatch_v20')
 a.lui('t3',0xA460);a.label('ido_pi');a.lw('t4',0x10,'t3');a.andi('t4','t4',3);a.bne('t4','zero','ido_pi');a.nop()
 a.lui('t3',0xB000);a.lw('t4',0x3C,'t3');a.srl('t4','t4',16)
 for code in sorted(set(protected)):
  a.ori('t6','zero',code);a.beq('t4','t6','ido_fallback');a.nop()
 a.lui('t5',0x10);a.addu('t5','t5','t1')
 def eq(reg,off,value,high=False):
  a.lw('k0',off,reg)
  if high:a.srl('k0','k0',16)
  a.li('k1',value);a.bne('k0','k1','ido_fallback');a.nop()
 def bounds(reg,n):
  a.sltu('k0',reg,'t1');a.bne('k0','zero','ido_fallback');a.nop()
  a.addiu('k1',reg,n);a.sltu('k0','t5','k1');a.bne('k0','zero','ido_fallback');a.nop()
  a.andi('k0',reg,3);a.bne('k0','zero','ido_fallback');a.nop()
 def pointer(dst,base,hi,lo):
  a.lw(dst,hi,base);a.sll(dst,dst,16);a.lw('k1',lo,base);a.sll('k1','k1',16);a.r('zero','k1','k1',16,3);a.addu(dst,dst,'k1')
 def target(dst,base,off):
  a.lw(dst,off,base);a.srl('k0',dst,26);a.ori('k1','zero',3);a.bne('k0','k1','ido_fallback');a.nop()
  a.sll(dst,dst,6);a.srl(dst,dst,4);a.lui('k0',0x8000);a.or_(dst,dst,'k0')
 for off,val in BOOT_HI.items():eq('t1',off,val,True)
 for off,val in BOOT_FIXED.items():eq('t1',off,val)
 pointer('t4','t1',36,44);bounds('t4',16)
 eq('t4',0,0x27BDFFE0);eq('t4',4,0xAFBF001C);eq('t4',12,0)
 target('t6','t4',8);bounds('t6',0x17C)
 for off,val in ((0,0x27BDFFC8),(4,0xAFBF001C),(8,0x240E0001),(0x40,0x3C040490)):eq('t6',off,val)
 target('t7','t6',0x3C);bounds('t7',16)
 for i,word in enumerate(SETTER):eq('t7',4*i,word)
 a.addiu('t4','t6',0xB4)
 pointer('t8','t4',0,4);bounds('t8',16)
 for hi,lo in ((16,28),(48,60),(80,92)):
  pointer('t9','t4',hi,lo);a.bne('t9','t8','ido_fallback');a.nop()
 a.li('t6',a.labels['ido_table']);a.ori('t7','zero',50)
 a.label('ido_publish_word');a.lw('k0',0,'t4');a.lw('k1',4,'t6');a.and_('k0','k0','k1');a.lw('t9',0,'t6');a.and_('t9','t9','k1')
 a.bne('k0','t9','ido_fallback');a.nop();a.addiu('t4','t4',4);a.addiu('t6','t6',8);a.addiu('t7','t7',-1);a.bne('t7','zero','ido_publish_word');a.nop()
 eq('t8',0,0x3C1A,True);eq('t8',4,0x275A,True);eq('t8',8,0x03400008);eq('t8',12,0)
 pointer('t7','t8',0,4);bounds('t7',4)
 a.lui('t6',igr_addr>>16);a.sw('t7',labels['ORIG']-igr_addr,'t6');a.ori('t7','zero',1);a.sw('t7',labels['TPLFLAG']-igr_addr,'t6');a.cache(0x19,labels['TPLFLAG']-igr_addr,'t6')
 for off,word in ((0,0x3C1A0000|(((labels['entryB']+0x8000)>>16)&65535)),(4,0x275A0000|(labels['entryB']&65535))):
  a.li('t7',word);a.sw('t7',off,'t8');a.cache(0x19,off,'t8');a.cache(0x10,off,'t8')
 a.word(0xF);a.mtc0('zero',18);a.mtc0('zero',19)
 for _ in range(3):a.nop()
 a.jr('t1');a.nop()
 a.label('ido_fallback');a.j(labels['dispatch_v19']);a.nop()
 return a.build(),a.labels
