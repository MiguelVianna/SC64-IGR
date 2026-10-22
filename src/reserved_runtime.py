"""Experimental direct exception IGR in an explicitly reserved game heap slice.

No ROM data embedded. The installer verifies all binding words before patching.
This module is an experiment, not a console-compatible menu release.
"""
import struct
import build_igr as B

MM=dict(key='majora',base=0x80770000,end=0x80780000,entry=0x80080000,
        preamble=0x80088b00,handler=0x80088b10,
        zero=0x80089630,small=0x800896ac,
        zero_words=(0x28a1000c,0x1420001d,0x00041823,0x30630003),
        heap=0x800865f8,heap_words=(0x27bdffe8,0xafbf0014),heap_end=0x80780000,
        preamble_words=(0x3c1a8009,0x275a8b10,0x03400008,0))

DK=dict(key='dk64',base=0x805f0000,end=0x805fae00,entry=0x80000400,
        preamble=0x800090a0,handler=0x800090b0,
        zero=0x800051c0,small=0x8000523c,
        zero_words=(0x28a1000c,0x1420001d,0x00041823,0x30630003),
        heap=None,heap_words=(),heap_end=0x805fae00,
        preamble_words=(0x3c1a8001,0x275a90b0,0x03400008,0),
        late_hook=0x80000764,late_words=(0x3c028001,0x2442dcc4),
        late_guards=((0x80610510,0x3c0d805f),(0x80610518,0x35adae00),
                     (0x8061051c,0x01aa1823)))

def build(profile=MM):
 p=profile;previous=B.IGR_ADDR
 try:
  B.IGR_ADDR=p['base'];raw,l=B.build_igr_block_v21r2()
 finally:B.IGR_ADDR=previous
 a=B.Asm(p['base']+len(raw))
 # Tail trampoline for the first two replaced instructions in libultra bzero.
 # Replays branch plus its original delay slot, preserving its short-size path.
 a.label('reserved_zero_native')
 a.word(p['zero_words'][0])
 a.beq('at','zero','zero_large');a.word(p['zero_words'][2])
 a.j(p['small']);a.nop();a.label('zero_large')
 a.j(p['zero']+12);a.nop()
 a.label('reserved_zero')
 # Unsigned interval [a0,a0+a1); only KSEG0 calls crossing the reservation split.
 a.addu('t0','a0','a1');a.li('t1',p['base']);a.li('t2',p['end'])
 a.sltu('t3','a0','t2');a.beq('t3','zero','zero_tail');a.nop()
 a.sltu('t3','t1','t0');a.beq('t3','zero','zero_tail');a.nop()
 a.sltu('t3','t0','a0');a.bne('t3','zero','zero_tail');a.nop()
 a.addiu('sp','sp',-32);a.sw('ra',28,'sp');a.sw('a0',16,'sp');a.sw('t0',20,'sp')
 a.sltu('t3','a0','t1');a.beq('t3','zero','zero_second');a.nop()
 a.subu('a1','t1','a0');a.jal('reserved_zero_native');a.nop()
 a.label('zero_second')
 a.lw('t0',20,'sp');a.li('t2',p['end']);a.sltu('t3','t2','t0')
 a.beq('t3','zero','zero_return');a.nop()
 a.or_('a0','t2','zero');a.subu('a1','t0','t2');a.jal('reserved_zero_native');a.nop()
 a.label('zero_return');a.lw('ra',28,'sp');a.addiu('sp','sp',32);a.jr('ra');a.nop()
 a.label('zero_tail');a.j('reserved_zero_native');a.nop()
 if p['heap'] is not None:
  a.label('reserved_heap')
  a.addu('t0','a0','a1');a.li('t1',p['heap_end'])
  a.bne('t0','t1','heap_native');a.nop()
  a.li('t1',p['base']);a.sltu('t2','a0','t1');a.beq('t2','zero','heap_native');a.nop()
  a.subu('a1','t1','a0')
  a.label('heap_native')
  for word in p['heap_words']:a.word(word)
  a.j(p['heap']+8);a.nop()
 def patch(addr,word):
  a.li('t6',addr);a.li('t4',word);a.sw('t4',0,'t6')
  a.cache(0x19,0,'t6');a.word(0xf);a.cache(0x10,0,'t6');a.word(0xf)
 if p.get('late_hook'):
  a.label('reserved_after_load')
  for addr,w in p['late_guards']:
   a.li('t6',addr);a.lw('t4',0,'t6');a.li('t5',w)
   a.bne('t4','t5','late_reject');a.nop()
  patch(0x80610518,0x35ad0000) # keep LUI805f, lower ceiling from805fae00 to805f0000
  a.j('late_resume');a.nop()
  a.label('late_reject')
  for addr,words in [(p['zero'],p['zero_words'][:2]),(p['late_hook'],p['late_words'])]:
   for i,w in enumerate(words):patch(addr+4*i,w)
  # Remove our source and already copied vector hooks on a late mismatch.
  for at in (p['preamble'],0x80000000,0x80000080,0x80000100,0x80000180):
   for i,w in enumerate(p['preamble_words'][:2]):patch(at+4*i,w)
  a.label('late_resume')
  for w in p['late_words']:a.word(w)
  a.j(p['late_hook']+8);a.nop()
 # All installer guards come first, so mismatch leaves game instructions intact.
 a.label('reserved_install');a.mtc0('zero',18);a.nop();a.or_('t9','t1','zero')
 def guard(addr,w):
  a.li('t6',addr);a.lw('t4',0,'t6');a.li('t5',w)
  a.bne('t4','t5','install_reject');a.nop()
 for base,words in [(p['zero'],p['zero_words']),(p['heap'],p['heap_words']),(p['preamble'],p['preamble_words'])]+([(p['late_hook'],p['late_words'])] if p.get('late_hook') else []):
  for i,w in enumerate(words):guard(base+4*i,w)
 if p.get('restore_memsize'):
  # Router has already required eight real megabytes. Publish game metadata
  # after native IPL3/cheat bootstrap, before the game's Expansion Pak check.
  # Do not bypass the game comparison or advertise 8MB on the clean 4MB path.
  patch(0x80000318,p['restore_memsize'])
 for at,target in [(p['zero'],a.labels['reserved_zero'])]+([(p['heap'],a.labels['reserved_heap'])] if p['heap'] is not None else [])+([(p['late_hook'],a.labels['reserved_after_load'])] if p.get('late_hook') else []):
  patch(at,0x08000000|((target>>2)&0x3ffffff));patch(at+4,0)
 patch(l['ORIG'],p['handler']);patch(l['TPLFLAG'],1)
 eb=l['entryB'];patch(p['preamble'],0x3c1a0000|(eb>>16));patch(p['preamble']+4,0x275a0000|(eb&65535))
 a.mtc0('zero',18);a.word(0xf)
 a.label('install_reject');a.jr('t9');a.nop()
 code=raw+a.build();assert len(code)<p['end']-p['base']
 return code,dict(l,**a.labels)
