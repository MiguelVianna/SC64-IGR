"""Late-bound arena ceilings for verified startup/allocator pairs.

The two bindings describe the supplied revisions, not every game using a CIC.
The reusable operation caps only an allocator's end or size argument. It never
changes osMemSize, skips a clear or borrows memory outside the IGR reservation.
Both loader and decoded consumer are checked before each installation.
"""

CEILING = 0x807C0000

# Exact instructions encode relations established in the native heap study.
# Wider guards are data tables so the common checker remains small.
BINDINGS = (
    dict(key='1080', header=0x54454100, crc=(0x1FBAF161, 0x2C1C54F1),
         hook=0x80001108, target=None, allocator=0x80105490, argument='end',
         early=((0x80000400, 0x3C088001), (0x80000404, 0x3C090001),
                (0x80000408, 0x2508ABC0), (0x8000040C, 0x352953E0),
                (0x80000430, 0x01400008), (0x80000434, 0x27BD2BC0),
                (0x800010FC, 0x8F020004), (0x80001100, 0x3C048001),
                (0x80001104, 0x24842BC0), (0x80001108, 0x0040F809),
                (0x8000110C, 0), (0x80001110, 0x3C018001),
                (0x80001114, 0xAC222BE4)),
         late=((0x80105490, 0x27BDFFE0), (0x80105494, 0xAFB00018),
               (0x80105498, 0x00808025), (0x8010549C, 0xAFBF001C),
               (0x801054A4, 0xAFA60028), (0x801054AC, 0xAFA50024),
               (0x801054B0, 0x0C037B33), (0x801054C0, 0x8FAE0028),
               (0x801054D0, 0x01C51023), (0x801054D4, 0xAE020028),
               (0x801054FC, 0xACB00004), (0x80105500, 0xACB00008),
               (0x80105504, 0xACB90000), (0x80105508, 0xACA4000C),
               (0x800DF70C, 0x0C041524), (0x800DF710, 0x00A63021),
               (0x800EBA98, 0x0C041524), (0x800EBA9C, 0x00AE3021))),
    dict(key='thps3', header=0x33544500, crc=(0x1A7F70B5, 0x00B7B9FD),
         hook=0x80000A84, target=0x800BACB8, allocator=0x800B7E00,
         argument='size',
         early=((0x80000400, 0x3C1D803F), (0x80000404, 0x37BDFFF0),
                (0x80000460, 0x0C00021C), (0x80000464, 0),
                (0x80000A74, 0x3C020001), (0x80000A78, 0x0282A021),
                (0x80000A7C, 0x08000264), (0x80000A80, 0x26730001),
                (0x80000A84, 0x0C02EB2E), (0x80000A88, 0),
                (0x80000A8C, 0x8FBF0034), (0x80000A90, 0x8FB60030)),
         late=((0x800BACB8, 0x27BDFFE0), (0x800BACBC, 0xAFBF0018),
               (0x800BACC4, 0x0C02EA05),
               (0x800BAC10, 0x3C028000), (0x800BAC14, 0x8C420318),
               (0x800BAC38, 0x3C058010), (0x800BAC3C, 0x24A56080),
               (0x800BAC44, 0x8C6696D8), (0x800BAC48, 0x00A21021),
               (0x800BAC4C, 0x0C02DF80), (0x800BAC50, 0x00C23023),
               (0x800B7E00, 0x27BDFFC8), (0x800B7E04, 0xAFB5002C),
               (0x800B7E08, 0x0080A821), (0x800B7E10, 0x00A08821),
               (0x800B7E18, 0x00C09021), (0x800B7E20, 0x00002821),
               (0x800B7E30, 0x0C02DED4), (0x800B7E34, 0xAFB00018),
               (0x800B7E4C, 0x02519023))),
)


def emit(Asm, start, labels):
    a = Asm(start)
    for p in BINDINGS:
        for phase in ('early', 'late'):
            a.label('arena_' + p['key'] + '_' + phase + '_table')
            for address, word in p[phase]:
                a.word(address); a.word(word)
            a.word(0)

    def match(p, phase, fail):
        name = 'arena_' + p['key'] + '_' + phase
        a.li('t6', a.labels[name + '_table']); a.label(name + '_loop')
        a.lw('k0', 0, 't6'); a.beq('k0', 'zero', name + '_matched'); a.nop()
        a.lw('k1', 4, 't6'); a.lw('t7', 0, 'k0')
        a.bne('k1', 't7', fail); a.addiu('t6', 't6', 8)
        a.j(name + '_loop'); a.nop(); a.label(name + '_matched')

    def patch(address, word):
        a.li('t6', address); a.li('k0', word); a.sw('k0', 0, 't6')
        a.cache(0x19, 0, 't6'); a.word(0xF); a.cache(0x10, 0, 't6')

    # Helpers are emitted before the dispatcher so hook addresses are final.
    for p in BINDINGS:
        key = p['key']; native = 'arena_' + key + '_native'
        a.label('arena_' + key + '_after_load')
        match(p, 'late', native)
        # No mutation occurs if even the final consumer/caller guard failed.
        fix = len(a.items); a.lui('k0', 0x0800); a.ori('k0', 'k0', 0)
        a.li('t6', p['allocator']); a.sw('k0', 0, 't6'); a.sw('zero', 4, 't6')
        a.cache(0x19, 0, 't6'); a.word(0xF); a.cache(0x10, 0, 't6'); a.word(0xF)
        a.label(native)
        if p['target'] is None: a.jr('v0')
        else: a.j(p['target'])
        a.nop()
        a.label('arena_' + key + '_cap')
        # Only well-formed KSEG0 arenas crossing the reserved ceiling are capped.
        a.lui('t6', 0x8000); a.sltu('k0', 'a1', 't6')
        done = 'arena_' + key + '_cap_done'
        a.bne('k0', 'zero', done); a.nop()
        a.lui('t6', CEILING >> 16); a.sltu('k0', 'a1', 't6')
        a.beq('k0', 'zero', done); a.nop()
        if p['argument'] == 'size':
            a.subu('t6', 't6', 'a1')
        a.sltu('k0', 't6', 'a2'); a.beq('k0', 'zero', done); a.nop()
        a.or_('a2', 't6', 'zero'); a.label(done)
        # Replay the overwritten prologue with the original RA/SP/arguments.
        first = dict(p['late'])
        a.word(first[p['allocator']]); a.word(first[p['allocator'] + 4])
        a.j(p['allocator'] + 8); a.nop()
        jump = 0x08000000 | ((a.labels['arena_' + key + '_cap'] >> 2) & 0x3FFFFFF)
        a.items[fix] = ('w', 0x3C1A0000 | (jump >> 16))
        a.items[fix + 1] = ('w', 0x375A0000 | (jump & 0xFFFF))

    a.label('dispatch_v21r2')
    a.lui('t3', 0xA460); a.label('arena_pi')
    a.lw('t4', 0x10, 't3'); a.andi('t4', 't4', 3)
    a.bne('t4', 'zero', 'arena_pi'); a.nop()
    a.lui('t3', 0xB000)
    for p in BINDINGS:
        fail = 'arena_' + p['key'] + '_reject'
        for off, value in ((0x3C, p['header']), (0x10, p['crc'][0]), (0x14, p['crc'][1])):
            a.lw('t4', off, 't3'); a.li('t5', value)
            a.bne('t4', 't5', fail); a.nop()
        a.li('t5', 0x80000400); a.bne('t1', 't5', fail); a.nop()
        match(p, 'early', fail)
        patch(p['hook'], 0x0C000000 | ((a.labels['arena_' + p['key'] + '_after_load'] >> 2) & 0x3FFFFFF))
        a.word(0xF); a.j(labels['dispatch_v20']); a.nop(); a.label(fail)
    a.j(labels['dispatch_v20']); a.nop()
    return a.build(), a.labels
