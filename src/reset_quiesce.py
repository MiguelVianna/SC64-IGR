"""Order reset shutdown by RDP state, independent of cartridge identity.

Release FREEZE/FLUSH before waiting for the RSP, preserve the command source
until drain, include pending START/END bits, and never enqueue the own filler
on an already busy queue. A pre-existing hardware lock is not recoverable here.
"""
import struct

def append(Asm,raw,labels,igr_addr):
 data=bytearray(raw);start=labels['reboot']-igr_addr;end=labels['paint']-igr_addr
 def locate(*words):
  needle=struct.pack('>%dI'%len(words),*words);at=data.find(needle,start,end)
  assert at>=0 and data.find(needle,at+4,end)<0,tuple(hex(x) for x in words)
  return at
 si=locate(0x3C0AA480,0x3C190004)
 rdp=locate(0x3C0AA410,0x34090015)
 mask=locate(0x3C0B00FF,0x356BFFFF)
 pi=data.find(struct.pack('>I',0x3C08A460),mask,end);assert pi>mask
 waits=[i for i in range(rdp,pi,4) if struct.unpack_from('>I',data,i)[0]==0x340C0170];assert len(waits)==2
 a=Asm(igr_addr+len(raw));a.label('rdp_release_before_rsp')
 a.lui('t2',0xA410);a.ori('t1','zero',0x14);a.sw('t1',12,'t2');a.word(0xF)
 a.lui('t2',0xA480);a.lui('t9',4);a.j(igr_addr+si+8);a.nop()
 a.label('rdp_switch_after_idle')
 a.lui('t2',0xA410);a.lw('t1',12,'t2');a.andi('t1','t1',0x770)
 a.bne('t1','zero','rdp_skip_busy_filler');a.nop()
 a.ori('t1','zero',1);a.sw('t1',12,'t2');a.word(0xF)
 a.lui('t3',0xFF);a.ori('t3','t3',0xFFFF);a.j(igr_addr+mask+8);a.nop()
 a.label('rdp_skip_busy_filler');a.j(igr_addr+pi);a.nop()
 patches={si:0x08000000|((a.labels['rdp_release_before_rsp']>>2)&0x3FFFFFF),si+4:0,
          rdp+4:0x34090014,mask:0x08000000|((a.labels['rdp_switch_after_idle']>>2)&0x3FFFFFF),mask+4:0}
 patches.update({i:0x340C0770 for i in waits})
 for at,word in patches.items():struct.pack_into('>I',data,at,word)
 extra=dict(a.labels,reset_pi_stage=igr_addr+pi)
 extra.update({'rdp_patch_%d'%i:igr_addr+at for i,at in enumerate(sorted(patches))})
 return bytes(data)+a.build(),dict(labels,**extra)
