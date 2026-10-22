"""One experimental V25-derived candidate: Bassmasters + reserved MM/DK IGR.

Strict V25 input. Private output only; no assertion of console compatibility.
"""
from pathlib import Path
import struct,hashlib,sys
import build_igr as B
import build_v22 as V
import build_bassmasters_candidate as Bass
from reserved_runtime import build as reserved,MM,DK

HEADERS={'majora':(0x5a534500,0x5354631c,0x03a2def0),
         'dk64':(0x444f4500,0xec58eabf,0xad7c7169)}

def cave(runtime_builder=None,extra_headers=None,profiles=None,common_headers=()):
 common,labels=(runtime_builder or Bass.runtime)();buf=bytearray(B.build_cave(common,labels['BOOTCHEATS']))
 source=B.CAVE+buf.find(common);assert source>=B.CAVE and buf.count(common)==1
 empty=source+len(common);oldlen=len(B.build_igr_block_v21r2()[0])
 metadata=[];bindings=[]
 def align(n=16):buf.extend(b'\0'*((-len(buf))%n))
 for cfg in (profiles or (MM,DK)):
  own,ownlabels=reserved(cfg);assert len(own)>oldlen
  # Only relocation differences and new helpers are duplicated in the menu.
  patches=[(i,struct.unpack_from('>I',own,i)[0]) for i in range(0,oldlen,4) if own[i:i+4]!=common[i:i+4]]
  proof=bytearray(common[:oldlen])+own[oldlen:]
  for pos,w in patches:struct.pack_into('>I',proof,pos,w)
  assert proof==own
  align();helper=B.CAVE+len(buf);buf+=own[oldlen:]
  align();table=B.CAVE+len(buf)
  for pos,w in patches:buf+=struct.pack('>II',pos,w)
  buf+=struct.pack('>II',0xffffffff,0)
  for header in [HEADERS[cfg['key']]]+list((extra_headers or {}).get(cfg['key'],())):
   align();record=B.CAVE+len(buf)
   words=(*header,cfg['base'],cfg['end'],helper,len(own)-oldlen,table,ownlabels['reserved_install'],cfg['entry'])
   buf+=struct.pack('>10I',*words);metadata.append(record)
  bindings.append(dict(game=cfg['key'],base=hex(cfg['base']),end=hex(cfg['end']),runtime_bytes=len(own),relocations=len(patches),installer=hex(ownlabels['reserved_install']),before_pi=hex(ownlabels['rdp_pi_ready'])))
 align();router=B.CAVE+len(buf);a=B.Asm(router)
 a.lui('t3',0xb000);a.lw('t4',0x3c,'t3')
 for index,record in enumerate(metadata):
  a.li('t8',record);a.lw('t5',0,'t8');a.bne('t4','t5','next_'+str(index));a.nop()
  a.lw('t5',0x10,'t3');a.lw('t6',4,'t8');a.bne('t5','t6','next_'+str(index));a.nop()
  a.lw('t5',0x14,'t3');a.lw('t6',8,'t8');a.bne('t5','t6','next_'+str(index));a.nop()
  a.j('special');a.nop();a.label('next_'+str(index))
 # Other revisions of ZS/DO stay excluded, not sent to the generic IGR.
 a.srl('t4','t4',16)
 for gid in (0x5a53,0x444f):
  a.ori('t5','zero',gid);a.beq('t4','t5','clean');a.nop()
 if common_headers:a.lw('t4',0x3c,'t3')
 for index,header in enumerate(common_headers):
  a.srl('t5','t4',16);a.ori('t6','zero',header[0]>>16)
  a.bne('t5','t6','common_next_'+str(index));a.nop()
  a.li('t5',header[0]);a.bne('t4','t5','clean');a.nop()
  for off,w in zip((0x10,0x14),header[1:]):
   a.lw('t5',off,'t3');a.li('t6',w);a.bne('t5','t6','clean');a.nop()
  a.j('common');a.nop();a.label('common_next_'+str(index))
 a.label('common')
 a.lui('t0',0x800d);a.lw('t1',-0x4e64,'t0');a.j(0x800dad08);a.nop()
 a.label('clean');a.or_('v0','zero','zero');a.j(B.ADDR_NOCHEATS);a.nop()
 a.label('special')
 a.lui('t5',0x0080);a.sltu('t6','t1','t5');a.bne('t6','zero','clean');a.nop()
 # Retain eight megabytes for these two Expansion Pak games.
 a.lui('t6',0x8000);a.sw('t5',0x318,'t6');a.cache(0x19,0x318,'t6');a.word(0xf)
 a.li('t3',source);a.lw('t4',12,'t8');a.addiu('t5','t3',oldlen)
 a.label('copy_shared')
 a.lw('t6',0,'t3');a.sw('t6',0,'t4');a.cache(0x19,0,'t4');a.cache(0x10,0,'t4')
 a.addiu('t3','t3',4);a.bne('t3','t5','copy_shared');a.addiu('t4','t4',4)
 a.lw('t3',20,'t8');a.lw('t5',24,'t8');a.addu('t5','t5','t3')
 a.label('copy_helpers')
 a.lw('t6',0,'t3');a.sw('t6',0,'t4');a.cache(0x19,0,'t4');a.cache(0x10,0,'t4')
 a.addiu('t3','t3',4);a.bne('t3','t5','copy_helpers');a.addiu('t4','t4',4)
 a.lw('t3',28,'t8');a.lw('t4',12,'t8');a.li('t7',0xffffffff)
 a.label('relocate')
 a.lw('t5',0,'t3');a.beq('t5','t7','relocated');a.nop()
 a.addu('t5','t5','t4');a.lw('t6',4,'t3');a.sw('t6',0,'t5');a.cache(0x19,0,'t5');a.cache(0x10,0,'t5')
 a.addiu('t3','t3',8);a.j('relocate');a.nop();a.label('relocated');a.word(0xf)
 # Native patcher still performs IPL3/cheat bootstrap. Its final jump now
 # enters the reserved native installer, which disables WatchLo before guards.
 a.lw('t4',32,'t8');a.srl('t4','t4',2);a.li('t5',0x03ffffff);a.and_('t4','t4','t5')
 a.lui('t5',0x0800);a.or_('t4','t4','t5')
 a.li('t5',0x8000);a.addu('t6','t4','t5');a.srl('t6','t6',16)
 a.lui('t5',0x3c02);a.or_('t6','t6','t5');a.li('t3',B.ADDR_PATCHER_JR[0]);a.sw('t6',0,'t3')
 a.cache(0x19,0,'t3');a.cache(0x10,0,'t3')
 a.andi('t6','t4',65535);a.lui('t5',0x2442);a.or_('t6','t6','t5');a.li('t3',B.ADDR_PATCHER_JR[1]);a.sw('t6',0,'t3')
 a.cache(0x19,0,'t3');a.cache(0x10,0,'t3');a.word(0xf)
 a.li('v0',empty);a.j(B.ADDR_CONT);a.nop()
 buf+=a.build();align(64);gate=B.CAVE+len(buf)
 saved=(V.GATE,V.STUB_AFTER_LW,V.EXCLUDE,V.HEAP_V21)
 try:
  V.GATE=gate;V.STUB_AFTER_LW=router;V.EXCLUDE={k:v for k,v in V.EXCLUDE.items() if k not in ('ZS','DO')};V.HEAP_V21=0x800e7000
  blob,_,_=V.build_gate()
 finally:V.GATE,V.STUB_AFTER_LW,V.EXCLUDE,V.HEAP_V21=saved
 struct.pack_into('>II',buf,0,0x08000000|((gate>>2)&0x3ffffff),0);buf+=blob
 heap=(B.CAVE+len(buf)+0x7ff)&~0x7ff
 assert ((heap+0x8000)>>16)==0x800e,hex(heap)
 return bytes(buf),heap,dict(gate=hex(gate),router=hex(router),source=hex(source),heap=hex(heap),cave_end=hex(B.CAVE+len(buf)),bindings=bindings)

def main(src,dst,runtime_builder=None,extra_headers=None,profiles=None,cave_builder=None):
 src=Path(src);dst=Path(dst)
 if src.resolve()==dst.resolve():raise ValueError('Preserve the V25 input; choose a separate output.')
 before=hashlib.sha256(src.read_bytes()).hexdigest();assert before==Bass.V25_SHA256
 rom=bytearray(src.read_bytes());es,n=struct.unpack_from('>HH',rom,0x193c)
 entries=[struct.unpack_from('>II',rom,0x1940+k*es) for k in range(n)];off,size=entries[0]
 elf=rom[off:off+size];pho=struct.unpack_from('>I',elf,28)[0];assert struct.unpack_from('>H',elf,44)[0]==4
 ph=[list(struct.unpack_from('>8I',elf,pho+32*k)) for k in range(4)]
 # Exact reconstruction of original V25 cave, prior to any modifications.
 old,labels=B.build_igr_block_v21r2();expected=bytearray(B.build_cave(old,labels['BOOTCHEATS']))
 gate,_,_=V.build_gate();struct.pack_into('>II',expected,0,0x08000000|((V.GATE>>2)&0x3ffffff),0)
 expected+=b'\0'*(V.GATE-B.CAVE-len(expected));expected+=gate
 assert B.lz4_decompress(elf[ph[3][1]:ph[3][1]+ph[3][4]])==expected
 newcave,heap,meta=(cave_builder() if cave_builder else cave(runtime_builder,extra_headers,profiles));mainseg=bytearray(B.lz4_decompress(elf[ph[2][1]:ph[2][1]+ph[2][4]]))
 for at in B.ADDR_SBRK:B.patch_word(mainseg,at,0x2442f800,0x24420000|(heap&65535))
 for at in (0x800a9efc,0x800aa090):assert struct.unpack_from('>I',mainseg,at-B.IMG_BASE)[0]==0x3c02800e
 blobs={2:B.lz4_compress(bytes(mainseg)),3:B.lz4_compress(newcave)}
 body=bytearray(elf[:pho+128]);newph=[]
 for k,p in enumerate(ph):
  q=list(p);blob=blobs.get(k,elf[p[1]:p[1]+p[4]])
  body+=b'\0'*((-len(body))%8);q[1]=len(body);body+=blob
  if k in blobs:
   length=len(mainseg) if k==2 else len(newcave);q[4]=len(blob);q[5]=length;q[2]=B.inplace_vaddr(q[3],length,blob)
  newph.append(q)
 for k,p in enumerate(newph):struct.pack_into('>8I',body,pho+32*k,*p)
 newsize=(len(body)+15)&~15;assert off+newsize<=min(e[0] for e in entries[1:])
 rom[off:off+size]=b'\0'*size;rom[off:off+len(body)]=body;struct.pack_into('>I',rom,0x1944,newsize)
 dst.parent.mkdir(parents=True,exist_ok=True);dst.write_bytes(rom);assert hashlib.sha256(src.read_bytes()).hexdigest()==before
 meta.update(sha256=hashlib.sha256(rom).hexdigest(),bytes=len(rom),base_sha256=before)
 import json
 print(json.dumps(meta,indent=2));return meta
if __name__=='__main__':main(*sys.argv[1:])
