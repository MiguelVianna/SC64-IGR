"""Guarded relocation-loader and arena recipe, independent of title/CIC/CRC.

Recognize the BEEF/DEAD boot family and whole unique instruction sequences.
The relocation-proof LUI/JR bridge runs after decoding and before native entry.
Only the two allocator consumers of osMemSize are capped; capability stays 8 MiB.
User cheats retain the previous path (the bridge's reserved slot may be in use).
"""
# (expected, mask); variable linked addresses are checked separately for the stub.
def pattern(words, variable=()):
 return tuple((w,0xFFFF0000 if i in variable else 0xFFFFFFFF) for i,w in enumerate(words))
LOADER=pattern([
 0x3C088000,0x8D080000,0x3C098000,0x8D290000,0x3C0A8000,0x8D4A0000,0x3C0B8000,0x8D6B0000,
 0x8D0D0000,0xAD4D0000,0x25080004,0x2529FFFC,0x1520FFFB,0x254A0004,
 0x3C048000,0,0x24050200,0xBC800000,0x24840020,0x20A5FFFF,0x14A0FFFC,0,
 0x01600008,0],range(8))
HEAP=pattern([
 0x27BDFFD8,0x3C028000,0x8C420318,0x3C038000,0xAFBF0024,0xAFB40020,
 0xAFB3001C,0xAFB20018,0xAFB10014,0xAFB00010,0x00431025,0x2454FF00])
RESOURCE=pattern([
 0x3C028010,0x3C098000,0x3C0E800E,0x3C0F800E,0x3C080040,0x3C0D800E,
 0x8C420000,0x8DC70000,0x8DE30000,0x00021100,0x00E30018,0x8D230318,
 0x00481021,0x00621823,0xADA30000,0x00003812,0x00C71004,0x00471021,
 0x00C21004,0x00621823,0x006A1821],(0,2,3,5,6,7,8,14))

def matches(data,entry,p):
 import struct
 return [entry+o for o in range(0,len(data)-4*len(p)+1,4)
         if all(struct.unpack_from('>I',data,o+4*i)[0]&mask==w&mask for i,(w,mask) in enumerate(p))]

def loader(data,entry):
 import struct
 hits=matches(data,entry,LOADER)
 if len(hits)!=1:return None
 addr=hits[0];w=lambda off:struct.unpack_from('>I',data,addr-entry+off)[0]
 for i in range(4):
  hi=w(i*8)&65535;lo=w(i*8+4)&65535;lo=lo if lo<32768 else lo-65536
  if (hi<<16)+lo!=addr+0x60+4*i:return None
 return addr

def emit(Asm,start,labels,igr_addr):
 a=Asm(start)
 a.label('late_heap_slot');a.word(0)
 for name,p in (('loader',LOADER),('heap',HEAP),('resource',RESOURCE)):
  a.label('late_table_'+name)
  for word,mask in p:a.word(word);a.word(mask)
 def scan(name):
  a.or_('a0','t1','zero');a.lui('a1',0x10);a.addu('a1','a1','a0')
  a.li('a2',a.labels['late_table_'+name]);a.ori('a3','zero',len(globals()[name.upper()]))
  a.jal('late_scan');a.nop()
 def storeword(reg,offset,word):
  a.li('k0',word);a.sw('k0',offset,reg);a.cache(0x19,offset,reg);a.cache(0x10,offset,reg)
 a.label('late_dispatch')
 # This recipe belongs to the verified BEEF/DEAD startup family.
 for off,word in ((0,0x3C08BEEF),(4,0x3508DEAD)):
  a.lw('t0',off,'t1');a.li('t2',word);a.bne('t0','t2','late_fallback');a.nop()
 a.li('t0',labels['BOOTCHEATS']);a.lw('t0',0,'t0');a.bne('t0','zero','late_fallback');a.nop()
 scan('loader');a.beq('v0','zero','late_fallback');a.nop()
 # Validate all four native parameter loads are linked to this very stub.
 for i in range(4):
  a.lw('t0',8*i,'v0');a.sll('t0','t0',16)
  a.lw('t2',8*i+4,'v0');a.sll('t2','t2',16);a.r('zero','t2','t2',16,3)
  a.addu('t0','t0','t2');a.addiu('t2','v0',0x60+4*i)
  a.bne('t0','t2','late_fallback');a.nop()
 # The native relocator adjusts J/JAL and LUI+LW/ORI, but leaves LUI+JR alone.
 # Use 64-KiB aligned bridge in the already reserved quarter MiB.
 a.lui('t0',0x807D)
 bridge_fix=len(a.items)
 a.lui('k0',0x0800);a.ori('k0','k0',0)
 a.sw('k0',0,'t0');a.cache(0x19,0,'t0');a.cache(0x10,0,'t0')
 storeword('t0',4,0)
 storeword('v0',0x54,0x3C1A807D);storeword('v0',0x58,0x03400008)
 a.word(0xF)
 a.label('late_fallback');a.j(labels['dispatch_v19']);a.nop()
 a.label('late_after_decode')
 a.or_('t1','t3','zero')
 scan('heap');a.beq('v0','zero','late_native');a.nop()
 a.li('t0',a.labels['late_heap_slot']);a.sw('v0',0,'t0')
 scan('resource');a.beq('v0','zero','late_native');a.nop()
 # Both complete sequences must exist uniquely before either is changed.
 a.li('t0',a.labels['late_heap_slot']);a.lw('t0',0,'t0')
 storeword('t0',8,0x3C02007C);storeword('v0',0x2C,0x3C03007C)
 a.word(0xF);a.j(labels['dispatch_v19']);a.nop()
 a.label('late_native');a.jr('t1');a.nop()
 # Leaf, unique pattern scan: v0=single address or 0. t1 is preserved.
 a.label('late_scan');a.or_('v0','zero','zero');a.sll('t2','a3',2);a.subu('a1','a1','t2')
 a.label('late_candidate');a.or_('t4','a0','zero');a.or_('t5','a2','zero');a.or_('t6','a3','zero')
 a.label('late_word');a.lw('t7',0,'t4');a.lw('t8',0,'t5');a.lw('t9',4,'t5')
 a.r('t7','t9','t7',0,0x24);a.r('t8','t9','t8',0,0x24)
 a.bne('t7','t8','late_next');a.nop()
 a.addiu('t4','t4',4);a.addiu('t5','t5',8);a.addiu('t6','t6',-1)
 a.bne('t6','zero','late_word');a.nop()
 a.bne('v0','zero','late_ambiguous');a.nop();a.or_('v0','a0','zero')
 a.label('late_next');a.addiu('a0','a0',4);a.r('a1','a0','t2',0,0x2B)
 a.beq('t2','zero','late_candidate');a.nop();a.jr('ra');a.nop()
 a.label('late_ambiguous');a.or_('v0','zero','zero');a.jr('ra');a.nop()
 raw=bytearray(a.build())
 # Locate the placeholder LI k0, 0x08000000 (LUI/ORI) emitted for bridge.
 import struct
 needle=struct.pack('>II',0x3C1A0800,0x375A0000)
 pos=bridge_fix*4;assert raw[pos:pos+8]==needle
 jump=0x08000000|((a.labels['late_after_decode']>>2)&0x3FFFFFF)
 struct.pack_into('>II',raw,pos,0x3C1A0000|(jump>>16),0x375A0000|(jump&65535))
 extra=dict(a.labels);extra['dispatch_v19']=a.labels['late_dispatch']
 return bytes(raw),extra
