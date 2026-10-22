"""Mechanism signatures independent of game title/CRC.

The WatchLo rule recognizes a complete osInitialize relationship: native
disable call, four-instruction setter, template pointer, four full vector
publications and a unique native handler/template inside the IPL3 image.
No mutation on partial or ambiguous matches. This repairs exception hooking;
it does not assert ownership of every game's heap or framebuffer RAM.
"""

SETTER=(0x40849000,0,0x03E00008,0)
PUBLISHER=[]
for vector in (0,0x80,0x100,0x180):
    PUBLISHER.append(0x3C068000)
    if vector:PUBLISHER.append(0x34C60000|vector)
    PUBLISHER.extend((0x8C430000,0x8C440004,0x8C450008,
                      0xACC30000,0xACC40004,0xACC50008,
                      0x8C43000C,0xACC3000C))
PUBLISHER=tuple(PUBLISHER)
assert len(PUBLISHER)==39

def find_watchlo(data,entry):
    """Read-only reference recognizer; data is exactly the loaded 1-MiB image."""
    import struct
    def word(addr):return struct.unpack_from('>I',data,addr-entry)[0]
    end=entry+len(data);found=[]
    for call in range(entry,end-0xDC,4):
        w=word(call)
        if w>>26!=3 or word(call+4)!=0x3C040490:continue
        target=0x80000000|((w&0x3FFFFFF)<<2)
        if not entry<=target<=end-16:continue
        if tuple(word(target+4*i) for i in range(4))!=SETTER:continue
        pub=call+0x3C;a,b=word(pub),word(pub+4)
        if a>>16!=0x3C02 or b>>16!=0x2442:continue
        template=((a&65535)<<16)+((b&65535)^0x8000)-0x8000
        if template%4 or not entry<=template<=end-16:continue
        if tuple(word(pub+8+4*i) for i in range(39))!=PUBLISHER:continue
        a,b,c,d=(word(template+4*i) for i in range(4))
        if a>>16!=0x3C1A or b>>16!=0x275A or c!=0x03400008 or d:continue
        handler=((a&65535)<<16)+((b&65535)^0x8000)-0x8000
        if handler%4 or not entry<=handler<end:continue
        found.append(dict(call=call,setter=target,publisher=pub,template=template,handler=handler))
    return found

def boot_watchlo(data,entry):
    """Accept only the SDK BSS -> main -> first initialization call path."""
    import struct
    w=lambda off:struct.unpack_from('>I',data,off)[0]
    high=lambda off:w(off)>>16
    if high(0)!=0x3C08 or high(12)!=0x2529:return None
    if (high(4),high(8)) not in ((0x2508,0x3C09),(0x3C09,0x2508)):return None
    if tuple(w(x) for x in range(16,40,4))!=(0xAD000000,0xAD000004,0x21080008,0x2129FFF8,0x1520FFFB,0):return None
    if high(0x28)!=0x3C0A:return None
    if high(0x2C)==0x254A and high(0x30)==0x3C1D and w(0x34)==0x01400008 and high(0x38)==0x27BD:
        low=0x2C
    elif high(0x2C)==0x3C1D and high(0x30)==0x254A and high(0x34)==0x27BD and w(0x38)==0x01400008 and w(0x3C)==0:
        low=0x30
    else:return None
    main=((w(0x28)&65535)<<16)+((w(low)&65535)^0x8000)-0x8000
    if main%4 or not entry<=main<=entry+len(data)-32:return None
    first=next((w(main-entry+i) for i in range(0,32,4) if w(main-entry+i)>>26==3),None)
    if first is None:return None
    init=0x80000000|((first&0x3FFFFFF)<<2)
    if not entry<=init<=entry+len(data)-0x110:return None
    if tuple(w(init-entry+x) for x in (0,4,8))!=(0x27BDFFE0,0x24020001,0xAFBF0018):return None
    found=[x for x in find_watchlo(data,entry) if x['call']==init+0x30]
    return found[0] if len(found)==1 else None

def boot_watchlo_v19(data,entry):
    """Additional SDK bootstrap forms; same complete WatchLo mechanism.

    Recognizes SP-before-main setup and a BEEF/DEAD + four-byte BSS loop.
    No title, CRC, CIC or fixed game address participates in recognition.
    """
    import struct
    old=boot_watchlo(data,entry)
    if old:return old
    w=lambda off:struct.unpack_from('>I',data,off)[0]
    h=lambda off:w(off)>>16
    decode=lambda hi,lo:((w(hi)&65535)<<16)+((w(lo)&65535)^0x8000)-0x8000
    if (h(0),h(4),h(8),h(12))==(0x3C08,0x2508,0x3C09,0x2529) and tuple(w(x) for x in range(16,40,4))==(0xAD000000,0xAD000004,0x21080008,0x2129FFF8,0x1520FFFB,0) and (h(40),h(44),h(48),h(52),w(56),w(60))==(0x3C1D,0x27BD,0x3C0A,0x254A,0x01400008,0):
        main=decode(48,52)
    elif (w(0),w(4),h(8),h(12),h(16),h(20),h(24),h(28))==(0x3C08BEEF,0x3508DEAD,0x3C1D,0x37BD,0x3C08,0x2508,0x3C09,0x2529) and tuple(w(x) for x in range(32,56,4))==(0x11090005,0,0x25080004,0x0109082B,0x1420FFFD,0xAD00FFFC) and w(56)>>26==3 and w(60)==0:
        main=0x80000000|((w(56)&0x3FFFFFF)<<2)
    else:return None
    if main%4 or not entry<=main<=entry+len(data)-32:return None
    first=next((w(main-entry+i) for i in range(0,32,4) if w(main-entry+i)>>26==3),None)
    if first is None:return None
    init=0x80000000|((first&0x3FFFFFF)<<2)
    if not entry<=init<=entry+len(data)-0x110:return None
    if tuple(w(init-entry+x) for x in (0,4,8))!=(0x27BDFFE0,0x24020001,0xAFBF0018):return None
    found=[x for x in find_watchlo(data,entry) if x['call']==init+0x30]
    return found[0] if len(found)==1 else None

def emit_watchlo(Asm,start,labels,igr_addr,protected_codes,extended=False):
    """Recognize a boot-reachable SDK routine; keep already supported paths."""
    a=Asm(start);table=start
    for word in PUBLISHER:a.word(word)
    a.label('v18_vaccine_gate')
    a.lui('t3',0xA460);a.label('vacc_pi')
    a.lw('t4',0x10,'t3');a.andi('t4','t4',3);a.bne('t4','zero','vacc_pi');a.nop()
    a.lui('t3',0xB000);a.lw('t4',0x3C,'t3');a.srl('t4','t4',16)
    for code in sorted(set(protected_codes)):
        a.ori('t5','zero',code);a.beq('t4','t5','vacc_fallback');a.nop()
    a.lui('t5',0x10);a.addu('t5','t5','t1')
    def eqword(address_reg,offset,expected):
        a.lw('k0',offset,address_reg);a.li('k1',expected)
        a.bne('k0','k1','vacc_next');a.nop()
    def bounds(reg,size):
        a.r(reg,'t1','k0',0,0x2B);a.bne('k0','zero','vacc_next');a.nop()
        a.addiu('k1',reg,size);a.r('t5','k1','k0',0,0x2B)
        a.bne('k0','zero','vacc_next');a.nop()
        a.andi('k0',reg,3);a.bne('k0','zero','vacc_next');a.nop()
    def high(reg,offset,value):
        a.lw('k0',offset,reg);a.srl('k0','k0',16);a.ori('k1','zero',value)
        a.bne('k0','k1','vacc_next');a.nop()
    if extended:
        # Detect boot-code variants, then follow their actual main/init calls.
        # The legacy path below remains byte-identical when extended=False.
        a.lw('k0',0,'t1');a.li('k1',0x3C08BEEF)
        a.beq('k0','k1','vacc_bss_four');a.nop()
        a.lw('k0',0x28,'t1');a.srl('k0','k0',16);a.ori('k1','zero',0x3C1D)
        a.beq('k0','k1','vacc_sp_first');a.nop()
        a.j('vacc_legacy_start');a.nop()
        a.label('vacc_sp_first')
        for offset,value in ((0,0x3C08),(4,0x2508),(8,0x3C09),(12,0x2529)):
            high('t1',offset,value)
        for offset,word in zip(range(16,40,4),(0xAD000000,0xAD000004,0x21080008,0x2129FFF8,0x1520FFFB,0)):
            eqword('t1',offset,word)
        for offset,value in ((40,0x3C1D),(44,0x27BD),(48,0x3C0A),(52,0x254A)):
            high('t1',offset,value)
        eqword('t1',56,0x01400008);eqword('t1',60,0)
        a.lw('t7',52,'t1');a.sll('t7','t7',16);a.r('zero','t7','t7',16,3)
        a.lw('k0',48,'t1');a.sll('k0','k0',16);a.addu('t7','t7','k0')
        a.j('vacc_new_main_common');a.nop()
        a.label('vacc_bss_four')
        eqword('t1',0,0x3C08BEEF);eqword('t1',4,0x3508DEAD)
        for offset,value in ((8,0x3C1D),(12,0x37BD),(16,0x3C08),(20,0x2508),(24,0x3C09),(28,0x2529)):
            high('t1',offset,value)
        for offset,word in zip(range(32,56,4),(0x11090005,0,0x25080004,0x0109082B,0x1420FFFD,0xAD00FFFC)):
            eqword('t1',offset,word)
        eqword('t1',60,0)
        a.lw('t7',56,'t1');a.srl('k0','t7',26);a.ori('k1','zero',3)
        a.bne('k0','k1','vacc_next');a.nop()
        a.sll('t7','t7',6);a.srl('t7','t7',4);a.lui('k0',0x8000);a.or_('t7','t7','k0')
        a.label('vacc_new_main_common');bounds('t7',32)
        a.ori('t6','zero',8);a.or_('t9','t7','zero')
        a.j('vacc_first_call');a.nop()
        a.label('vacc_legacy_start')
    high('t1',0,0x3C08);high('t1',12,0x2529)
    a.lw('k0',4,'t1');a.srl('k0','k0',16);a.ori('k1','zero',0x2508)
    a.beq('k0','k1','vacc_bss_a');a.nop()
    high('t1',4,0x3C09);high('t1',8,0x2508)
    a.j('vacc_bss_common');a.nop()
    a.label('vacc_bss_a');high('t1',8,0x3C09)
    a.label('vacc_bss_common')
    for offset,word in zip(range(16,40,4),(0xAD000000,0xAD000004,0x21080008,0x2129FFF8,0x1520FFFB,0)):
        eqword('t1',offset,word)
    high('t1',0x28,0x3C0A)
    a.lw('k0',0x2C,'t1');a.srl('k0','k0',16);a.ori('k1','zero',0x254A)
    a.beq('k0','k1','vacc_main_a');a.nop()
    high('t1',0x2C,0x3C1D);high('t1',0x30,0x254A);high('t1',0x34,0x27BD)
    eqword('t1',0x38,0x01400008);eqword('t1',0x3C,0)
    a.lw('t7',0x30,'t1');a.j('vacc_main_address');a.nop()
    a.label('vacc_main_a');high('t1',0x30,0x3C1D);eqword('t1',0x34,0x01400008);high('t1',0x38,0x27BD)
    a.lw('t7',0x2C,'t1')
    a.label('vacc_main_address')
    a.sll('t7','t7',16);a.r('zero','t7','t7',16,3)
    a.lw('k0',0x28,'t1');a.sll('k0','k0',16);a.addu('t7','t7','k0');bounds('t7',32)
    a.ori('t6','zero',8);a.or_('t9','t7','zero')
    a.label('vacc_first_call')
    a.lw('t7',0,'t9');a.srl('k0','t7',26);a.ori('k1','zero',3)
    a.beq('k0','k1','vacc_init_target');a.nop()
    a.addiu('t9','t9',4);a.addiu('t6','t6',-1)
    a.bne('t6','zero','vacc_first_call');a.nop();a.j('vacc_next');a.nop()
    a.label('vacc_init_target')
    a.sll('t4','t7',6);a.srl('t4','t4',4);a.lui('k0',0x8000);a.or_('t4','t4','k0')
    bounds('t4',0x110)
    for offset,word in ((0,0x27BDFFE0),(4,0x24020001),(8,0xAFBF0018)):eqword('t4',offset,word)
    a.addiu('t4','t4',0x30)
    a.label('vacc_scan')
    a.lw('t6',0,'t4');a.srl('k0','t6',26);a.ori('k1','zero',3)
    a.bne('k0','k1','vacc_next');a.nop()
    eqword('t4',4,0x3C040490)
    a.sll('t7','t6',6);a.srl('t7','t7',4);a.lui('k0',0x8000);a.or_('t7','t7','k0')
    bounds('t7',16)
    for i,word in enumerate(SETTER):eqword('t7',4*i,word)
    a.addiu('t9','t4',0x3C)
    for offset,hi in ((0,0x3C02),(4,0x2442)):
        a.lw('k0',offset,'t9');a.srl('k0','k0',16);a.ori('k1','zero',hi)
        a.bne('k0','k1','vacc_next');a.nop()
    a.lw('t8',0,'t9');a.sll('t8','t8',16)
    a.lw('k1',4,'t9');a.sll('k1','k1',16);a.r('zero','k1','k1',16,3)
    a.addu('t8','t8','k1');bounds('t8',16)
    a.addiu('t9','t9',8);a.li('t7',table);a.ori('t6','zero',39)
    a.label('vacc_pub_loop')
    a.lw('k0',0,'t9');a.lw('k1',0,'t7');a.bne('k0','k1','vacc_next');a.nop()
    a.addiu('t9','t9',4);a.addiu('t7','t7',4);a.addiu('t6','t6',-1)
    a.bne('t6','zero','vacc_pub_loop');a.nop()
    for offset,hi in ((0,0x3C1A),(4,0x275A)):
        a.lw('k0',offset,'t8');a.srl('k0','k0',16);a.ori('k1','zero',hi)
        a.bne('k0','k1','vacc_next');a.nop()
    eqword('t8',8,0x03400008);eqword('t8',12,0)
    a.lw('t7',0,'t8');a.sll('t7','t7',16)
    a.lw('k1',4,'t8');a.sll('k1','k1',16);a.r('zero','k1','k1',16,3)
    a.addu('t7','t7','k1');bounds('t7',4)
    a.or_('t0','t8','zero')
    a.lw('t7',0,'t0');a.sll('t7','t7',16)
    a.lw('k1',4,'t0');a.sll('k1','k1',16);a.r('zero','k1','k1',16,3)
    a.addu('t7','t7','k1');a.lui('t6',igr_addr>>16)
    a.sw('t7',labels['ORIG']-igr_addr,'t6');a.ori('t7','zero',1)
    a.sw('t7',labels['TPLFLAG']-igr_addr,'t6');a.cache(0x19,labels['TPLFLAG']-igr_addr,'t6')
    entry=labels['entryB']
    for offset,word in ((0,0x3C1A0000|(((entry+0x8000)>>16)&65535)),
                        (4,0x275A0000|(entry&65535))):
        a.li('t7',word);a.sw('t7',offset,'t0');a.cache(0x19,offset,'t0');a.cache(0x10,offset,'t0')
    a.word(0xF);a.mtc0('zero',18);a.mtc0('zero',19)
    for _ in range(3):a.nop()
    a.jr('t1');a.nop()
    a.label('vacc_next');a.label('vacc_fallback');a.j(labels['dispatch_v18' if extended else 'dispatch_v17']);a.nop()
    if extended:
        # Namespace appended routines so all released V18 labels remain intact.
        a.labels={'v19_'+key:value for key,value in a.labels.items()}
        scoped=[]
        for kind,value in a.items:
            if kind in ('j','jal') and isinstance(value,str):value='v19_'+value
            elif kind=='b':value=(*value[:3],'v19_'+value[3])
            scoped.append((kind,value))
        a.items=scoped
        a.labels['dispatch_v19']=a.labels['v19_v18_vaccine_gate']
    return a.build(),a.labels
