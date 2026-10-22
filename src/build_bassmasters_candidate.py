"""Experimental V25-derived guarded Bassmasters RAM probe fix.

Private output only. Does not establish full SC64 return or physical compatibility.
Keeps V25 lists, UP escape and heap; relocates gate within the existing cave.
"""
from pathlib import Path
import hashlib,struct,sys
import build_igr as B
import build_v22 as V
V25_SHA256='c229645cdb9e2b707e1891fc28206e6f5442caf3d134f0ae94face49aaa756ed'
SIGNATURE=(0x3c040040,0x3c080010,0x3c09007f,0x3529ffff)

def runtime():
 raw,labels=B.build_igr_block_v21r2();a=B.Asm(B.IGR_ADDR+len(raw))
 a.label('bass_probe_guard')
 def guard(addr,value):
  a.li('t6',addr);a.lw('t4',0,'t6');a.li('t5',value)
  a.bne('t4','t5','bass_fallback');a.nop()
 # Require the exact received revision, native entry, 4MB mode and all opcodes.
 for addr,value in ((0xb000003c,0x42344500),(0xb0000010,0xbcfaccaa),(0xb0000014,0xb814d8ef),(0x80000318,0x400000)):
  guard(addr,value)
 a.li('t5',0x80000400);a.bne('t1','t5','bass_fallback');a.nop()
 for i,value in enumerate(SIGNATURE):guard(0x8005e370+4*i,value)
 a.li('t6',0x8005e378);a.li('t4',0x3c09003f);a.sw('t4',0,'t6')
 a.cache(0x19,0,'t6');a.word(0xf);a.cache(0x10,0,'t6');a.word(0xf)
 a.label('bass_fallback');a.j(labels['dispatch_v20']);a.nop()
 # Replace only the final fallback of the existing R2 dispatcher. Its other
 # routes and labels remain fixed, including the two arena vaccines.
 data=bytearray(raw);site=labels['r2_reboot']-B.IGR_ADDR-8
 expect=(0x08000000|((labels['dispatch_v20']>>2)&0x3ffffff),0)
 assert struct.unpack_from('>II',data,site)==expect
 struct.pack_into('>II',data,site,0x08000000|((a.labels['bass_probe_guard']>>2)&0x3ffffff),0)
 return bytes(data)+a.build(),dict(labels,**a.labels)

def main(src,dst):
 src=Path(src);dst=Path(dst)
 if src.resolve()==dst.resolve():raise ValueError('Preserve input; use a separate output.')
 before=hashlib.sha256(src.read_bytes()).hexdigest();assert before==V25_SHA256
 rom=bytearray(src.read_bytes());es,n=struct.unpack_from('>HH',rom,0x193c)
 entries=[struct.unpack_from('>II',rom,0x1940+k*es) for k in range(n)]
 off,size=entries[0];elf=rom[off:off+size];pho=struct.unpack_from('>I',elf,28)[0]
 ph=[list(struct.unpack_from('>8I',elf,pho+32*k)) for k in range(4)]
 # Verify the complete V25 source reconstruction before rebuilding its runtime.
 oldraw,oldlabels=B.build_igr_block_v21r2()
 expected=bytearray(B.build_cave(oldraw,oldlabels['BOOTCHEATS']))
 oldgate,_,_=V.build_gate()
 struct.pack_into('>II',expected,0,0x08000000|((V.GATE>>2)&0x3ffffff),0)
 expected+=b'\0'*(V.GATE-B.CAVE-len(expected));expected+=oldgate
 assert B.lz4_decompress(elf[ph[3][1]:ph[3][1]+ph[3][4]])==expected, 'V25 source reconstruction mismatch'
 raw,labels=runtime();cave=bytearray(B.build_cave(raw,labels['BOOTCHEATS']))
 oldgate=V.GATE
 try:
  V.GATE=0x800df480 # 512-byte expansion allowance; no heap movement.
  gate,_,_=V.build_gate()
  assert B.CAVE+len(cave)<=V.GATE
  struct.pack_into('>II',cave,0,0x08000000|((V.GATE>>2)&0x3ffffff),0)
  cave+=b'\0'*(V.GATE-B.CAVE-len(cave));cave+=gate
  assert B.CAVE+len(cave)<=V.HEAP_V21
 finally:V.GATE=oldgate
 comp=B.lz4_compress(bytes(cave));assert B.lz4_decompress(comp)==cave
 body=bytearray(elf[:pho+4*32]);newph=[]
 for k,p in enumerate(ph):
  q=list(p);blob=comp if k==3 else elf[p[1]:p[1]+p[4]]
  body+=b'\0'*((-len(body))%8);q[1]=len(body);body+=blob
  if k==3:q[4]=len(comp);q[5]=len(cave);q[2]=B.inplace_vaddr(B.CAVE,len(cave),comp)
  newph.append(q)
 for k,p in enumerate(newph):struct.pack_into('>8I',body,pho+32*k,*p)
 newsize=(len(body)+15)&~15;assert off+newsize<=min(e[0] for e in entries[1:])
 rom[off:off+size]=b'\0'*size;rom[off:off+len(body)]=body
 struct.pack_into('>I',rom,0x1944,newsize)
 dst.parent.mkdir(parents=True,exist_ok=True);dst.write_bytes(rom)
 assert hashlib.sha256(src.read_bytes()).hexdigest()==before
 print('candidate',hashlib.sha256(rom).hexdigest(),'runtime_bytes',len(raw),'cave_end',hex(B.CAVE+len(cave)))
if __name__=='__main__':main(*sys.argv[1:])
