"""Guarded compatibility library, v17.

Mechanisms are reusable; addresses are specific to the supplied US revisions.
Never infer addresses or enable a RAM patch from a game's CIC alone. Every
early guard must pass before any mutation. Late guards are a separate stage.
Full SHA256 identifies laboratory input, not a runtime whole-cartridge check.
"""

PROFILES = (
    dict(key='starcraft', name='StarCraft 64 US', id_revision='NSQE00',
         header=0x53514500, crc=(0x0684FBFB,0x5D3EA8A5), entry=0x80000400,
         sha256='e7d21880c13953b45b8f8db6b2b6cfa02daa29d35b23799a967e96f21001b020',
         template=0x80099D60, handler=0x80099D70,
         mechanisms=('direct_exception_template','fixed_heap_ceiling'),
         patches=((0x8002A7F8,0x3C030080,0x3C03007C),),
         guards=((0x8002A808,0xAC83F10C),)),
    dict(key='battletanx', name='BattleTanx US', id_revision='NBXE00',
         header=0x42584500, crc=(0x6AA4DDE7,0xE3E2F4E7), entry=0x80071000,
         sha256='c5b7cf3523de025e3f18e2c8df2deb0eced5613e7c46cb8c6c5a4f22644ead3f',
         template=0x80111690, handler=0x801116A0,
         mechanisms=('direct_exception_template','saved_vector_wrapper'),
         patches=(),guards=((0x80077138,0x8D4C0000),(0x8007714C,0xAD4D0000))),
    dict(key='battletanx_global', name='BattleTanx Global Assault US', id_revision='NBQE00',
         header=0x42514500, crc=(0x75A4E247,0x6008963D), entry=0x80071000,
         sha256='88268ce770ff39f2ca839848b842c87866df6c5ddaf775f180b2522c18ff6221',
         template=0x80104FA0, handler=0x80104FB0,
         mechanisms=('direct_exception_template','saved_vector_wrapper'),
         patches=(),guards=((0x80078D78,0x8D4C0000),(0x80078D8C,0xAD4D0000))),
    dict(key='batman', name='Batman Beyond US', id_revision='NJQE00',
         header=0x4A514500, crc=(0x204489C1,0x1286CF2B), entry=0x80180000,
         sha256='0df3afffed7ec4c8e6962c9c1505acad3259f443f981e4f5d97db0824fa6e001',
         template=0x8018ADA0, handler=0x8018ADB0,
         mechanisms=('direct_exception_template','native_watchlo_disable'),
         patches=(),guards=((0x8019C688,0x0C0650B0),(0x801942C0,0x40849000))),
    dict(key='racer', name='Star Wars Racer US', id_revision='NEPE00',
         header=0x45504500, crc=(0x72F70398,0x6556A98B), entry=0x80000400,
         sha256='8d6f85683b630e25385619af37197d48279366f6609bb6edc1201ff24c08b757',
         template=0x8008CB00, handler=0x8008CB10,
         mechanisms=('direct_exception_template','video_allocation_ceiling'),
         # Replace only the framebuffer top address. v1 retains real 8 MiB;
         # all native comparisons selecting 640-pixel / 32-bit mode survive.
         patches=((0x80039A5C,0x00615025,0x3C0A807C),),
         guards=((0x80039A34,0x8C630318),(0x80039A60,0x006C082B))),
    dict(key='yoshi', name="Yoshi's Story US", id_revision='NYSE00',
         header=0x59534500, crc=(0x2337D8E8,0x6B8E7CEC), entry=0x80000400,
         header_entry=0x80200400, ipl3_crc32=0xACC8580A,
         sha256='e8a63388c38f8f0bea37e9b13a97f0898ac5496e08ca2028afb8db9a866e0ce9',
         template=0x80083DD0, handler=0x80083DE0,
         mechanisms=('direct_exception_template','osmemsize_tail_and_video'),
         memsize=0x007C0000,patches=(),
         guards=((0x8006740C,0x8DCE0318),(0x800712BC,0x8F180318))),
    dict(key='spiderman', name='Spider-Man US', id_revision='NSLE00',
         header=0x534C4500, crc=(0xA60ED171,0x3D85D06E), entry=0x80000400,
         sha256='feff90ed1201c91ff167d66958048e61c192c9d6a756ddb98f799017ac9cd25c',
         template=0x800022F0, handler=0x80002300,
         mechanisms=('direct_exception_template','post_decode_heap_ceiling'),
         patches=(),guards=((0x80000A84,0x0C0305B3),(0x80000A88,0)),
         late=dict(call=0x80000A84, original=0x800C16CC,
                   guards=((0x800C1628,0x8C420318),(0x800C1630,0x0082202B),
                           (0x800C1658,0x8C66BF98),(0x800C1664,0x00C23023)),
                   patches=((0x800C1658,0x8C66BF98,0x3C06007C),))),
)

def template_words(handler):
    return (0x3C1A0000|(((handler+0x8000)>>16)&0xFFFF),
            0x275A0000|(handler&0xFFFF),0x03400008,0)

def early_guards(profile):
    return (tuple((profile['template']+4*i,w)
                  for i,w in enumerate(template_words(profile['handler'])))
            +profile.get('guards',())
            +tuple((addr,old) for addr,old,new in profile['patches']))

def late_guards(stage):
    guards=dict(stage['guards'])
    for address,old,new in stage['patches']:
        assert address not in guards or guards[address]==old
        guards[address]=old
    return tuple(guards.items())

CRUISN_EXOTICA = dict(key='cruisn', name="Cruis'n Exotica US", id_revision='NXOE00',
    header=0x584F4500, crc=(0x46A3F7AF,0x0F7591D0), entry=0x80000400,
    sha256='d26ecb1b3a3dc965acc1063cc243ab573bf5ffca310e96aff2f6d2265a49f0b1',
    template=0x80045C00, handler=0x80045C10,
    mechanisms=('direct_exception_template','native_watchlo_disable','fixed_heap_ceiling'),
    patches=((0x800162B8,0x8CC60318,0x3C06007C),),
    guards=((0x80045948,0x0C011E80),(0x80047A00,0x40849000),
            (0x800162C8,0x00C23023)))

def profiles_v18(disable_battletanx=False):
    """Cold-RAM hypothesis for BattleTanx; control mode isolates IRQ hooking.

    Preserve boot globals below 400 and the complete IPL3-loaded 1-MiB image.
    The game itself clears its BSS. Never clear IGR/installer in upper RDRAM.
    This matches a low-4-MiB clear followed by IPL3 DMA, not an RI reinit.
    Physical cause of the reported black screen remains unproven.
    """
    result=[CRUISN_EXOTICA]
    for p in PROFILES:
        if not p['key'].startswith('battletanx'):continue
        result.append(dict(p,clear_ranges=((0x80000400,p['entry']),
                           (p['entry']+0x100000,0x80400000)),
                           disable_igr=disable_battletanx,
                           mechanisms=p['mechanisms']+('cold_boot_ram_gaps',)))
    return tuple(result)

def validate_profiles(profiles=PROFILES):
    """Reject inconsistent/new unguarded profiles at build time."""
    assert len({p['header'] for p in profiles})==len(profiles)
    for p in profiles:
        identity=p['id_revision']
        assert p['header']==int.from_bytes(identity[1:4].encode()+bytes.fromhex(identity[4:]),'big')
        assert len(p['sha256'])==64
        guards=early_guards(p)
        assert all(a%4==0 and p['entry']<=a<p['entry']+0x100000 for a,w in guards)
        if 'late' in p:late_guards(p['late'])
        for lo,hi in p.get('clear_ranges',()):
            assert lo%16==hi%16==0 and 0x80000400<=lo<hi<=0x80400000
            assert hi<=p['entry'] or lo>=p['entry']+0x100000

def emit_runtime(Asm, start, labels, igr_addr,profiles=PROFILES,version=17,previous='dispatch_v15'):
    """Append guarded dispatch without moving any previously released routine."""
    validate_profiles(profiles)
    a=Asm(start);prefix='v%d_'%version;fallback=prefix+'fallback'
    def guard(address,expected,target=fallback):
        a.li('t6',address);a.lw('t4',0,'t6');a.li('t5',expected)
        a.bne('t4','t5',target);a.nop()
    def patch(address,new):
        a.li('t6',address);a.li('t4',new);a.sw('t4',0,'t6')
        a.cache(0x19,0,'t6');a.cache(0x10,0,'t6')
    # Helpers precede dispatch so generated JAL constants are final immediately.
    for p in profiles:
        if 'late' not in p:continue
        late=p['late'];done=p['key']+'_late_done'
        a.label(p['key']+'_after_decode')
        for address,expected in late_guards(late):guard(address,expected,done)
        for address,old,new in late['patches']:patch(address,new)
        a.word(0xF);a.label(done);a.j(late['original']);a.nop()
    a.label('dispatch_v%d'%version)
    a.lui('t3',0xA460);a.label(prefix+'pi')
    a.lw('t4',0x10,'t3');a.andi('t4','t4',3)
    a.bne('t4','zero',prefix+'pi');a.nop()
    a.lui('t3',0xB000);a.lw('t4',0x3C,'t3')
    for p in profiles:
        a.li('t5',p['header']);a.beq('t4','t5',prefix+p['key']);a.nop()
    a.label(fallback);a.j(labels[previous]);a.nop()
    for p in profiles:
        a.label(prefix+p['key'])
        for offset,expected in zip((0x10,0x14),p['crc']):
            a.lw('t4',offset,'t3');a.li('t5',expected)
            a.bne('t4','t5',fallback);a.nop()
        a.li('t5',p['entry']);a.bne('t1','t5',fallback);a.nop()
        for address,expected in early_guards(p):guard(address,expected)
        # No state, instruction or osMemSize change before the final guard.
        if p.get('clear_ranges'):
            a.li('t6',labels['BOOTCHEATS']);a.lw('t4',0,'t6')
            a.bne('t4','zero',prefix+p['key']+'_clear_done');a.nop()
        for i,(lo,hi) in enumerate(p.get('clear_ranges',())):
            loop=prefix+p['key']+'_clear_%d'%i
            a.li('t6',lo);a.li('t7',hi);a.label(loop)
            for offset in (0,4,8,12):a.sw('zero',offset,'t6')
            a.cache(0x15,0,'t6') # write back/invalidate each complete zeroed D line
            a.addiu('t6','t6',16);a.bne('t6','t7',loop);a.nop()
        if p.get('clear_ranges'):a.label(prefix+p['key']+'_clear_done')
        for address,old,new in p['patches']:patch(address,new)
        if 'late' in p:
            patch(p['late']['call'],0x0C000000|((a.labels[p['key']+'_after_decode']>>2)&0x03FFFFFF))
        if 'memsize' in p:
            a.li('t6',0x80000318);a.li('t4',p['memsize'])
            a.sw('t4',0,'t6');a.cache(0x19,0,'t6')
        if p.get('disable_igr'):
            # Diagnostic control: keep installer/RI path, but restore native
            # live vector and leave all native templates unchanged.
            for i,word in enumerate(template_words(p['handler'])):
                patch(0x80000180+4*i,word)
            a.word(0xF);a.mtc0('zero',18);a.mtc0('zero',19)
            for _ in range(3):a.nop()
            a.jr('t1');a.nop()
            continue
        a.lui('t7',igr_addr>>16);a.li('t4',p['handler'])
        a.sw('t4',labels['ORIG']-igr_addr,'t7')
        a.ori('t4','zero',1);a.sw('t4',labels['TPLFLAG']-igr_addr,'t7')
        a.cache(0x19,labels['TPLFLAG']-igr_addr,'t7')
        for i,word in enumerate(template_words(labels['entryB'])[:2]):
            patch(p['template']+4*i,word)
        a.word(0xF);a.mtc0('zero',18);a.mtc0('zero',19)
        for _ in range(3):a.nop()
        a.jr('t1');a.nop()
    return a.build(),a.labels
