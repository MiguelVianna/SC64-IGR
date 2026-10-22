"""Perfect Dark US 1.1: native cold/warm RAM metadata and bounded expansion heap.

Public-source-derived mechanism; boot() integrity bytes stay unchanged.
One guarded main_proc framebuffer limit is patched after decompression.
The received ROM supplies revision/opcode guards and lab validation.
"""
import struct
import build_igr as B
import build_indiana_candidate as I
import build_three_games_candidate as C

HEADER = (0x50444501, 0x41F2B98F, 0xB458B466)
ENTRY = 0x80001000
STACK_START = 0x803F50B8
LIMIT = 0x7C0000
GUARDS = tuple(zip(range(ENTRY, ENTRY + 0x38, 4), (
    0x3C088009, 0x3C090002, 0x2508AE20, 0x352923A0,
    0x2129FFF8, 0xAD000000, 0xAD000004, 0x1520FFFC,
    0x21080008, 0x3C0A8000, 0x3C1D8000, 0x254A1050,
    0x01400008, 0x27BD0F10))) + (
    (0x800016AC, 0x3C077020), (0x800016B0, 0x24E7126C),
    (0x800016B4, 0x00E00008), (0x800016B8, 0))
LATE_GUARDS = ((0x8000D6E8, 0x3C010040), (0x8000D6EC, 0x34210001),
               (0x8000D6F0, 0x0041082A), (0x8000D6F4, 0x1020000E),
               (0x8000D6FC, 0x3C0B8006))
FB_SITE = 0x8000D6F8


def runtime():
    raw, labels = I.runtime()
    data = bytearray(raw)
    a = B.Asm(B.IGR_ADDR + len(raw))
    a.label('pd_after_inflate')
    a.addiu('sp', 'sp', -32); a.sw('ra', 28, 'sp')
    a.word(0x00E0F809); a.nop()  # jalr a3: original seg_inflate tail target
    for addr, value in LATE_GUARDS:
        a.li('t6', addr); a.lw('t4', 0, 't6'); a.li('t5', value)
        a.bne('t4', 't5', 'pd_late_reject'); a.nop()
    a.li('t6', FB_SITE); a.lw('t4', 0, 't6'); a.li('t5', 0x3C02807C)
    a.beq('t4', 't5', 'pd_inflate_return'); a.nop()  # second inflate is idempotent
    a.li('t5', 0x3C028080)
    a.bne('t4', 't5', 'pd_late_reject'); a.nop()
    a.li('t4', 0x3C02807C); a.sw('t4', 0, 't6')
    a.cache(0x19, 0, 't6'); a.word(0xF); a.cache(0x10, 0, 't6'); a.word(0xF)
    a.j('pd_inflate_return'); a.nop()
    a.label('pd_late_reject'); a.mtc0('zero', 18); a.nop()
    a.label('pd_inflate_return')
    a.lw('ra', 28, 'sp'); a.addiu('sp', 'sp', 32); a.jr('ra'); a.nop()
    a.label('pd_dispatch')
    a.lui('t3', 0xB000)
    for off, value in zip((0x3C, 0x10, 0x14), HEADER):
        a.lw('t4', off, 't3'); a.li('t5', value)
        a.bne('t4', 't5', 'pd_fallback'); a.nop()
    a.li('t5', ENTRY)
    a.bne('t1', 't5', 'pd_reject'); a.nop()
    for addr, value in GUARDS:
        a.li('t6', addr); a.lw('t4', 0, 't6'); a.li('t5', value)
        a.bne('t4', 't5', 'pd_reject'); a.nop()
    # boot() saves osMemSize on cold boot, but reads STACK_START on warm boot.
    # memp_set_heap() derives the expansion bank's upper limit from osGetMemSize().
    # Publish the same >4MiB limit to both native paths, reserving [7C0000,800000).
    # boot()/exception templates remain intact, including integrity checks.
    for addr in (0x80000318, STACK_START):
        a.li('t6', addr); a.li('t4', LIMIT); a.sw('t4', 0, 't6')
        a.cache(0x19, 0, 't6'); a.word(0xF)
    # The copyright/pak screen bypasses memp and uses a hardcoded 8MiB end.
    # Hook seg_inflate's tail (not boot(), which has a native integrity check)
    # to guard/cap that one main_proc instruction after lib decompression.
    a.li('t6', 0x800016B4)
    a.li('t4', 0x08000000 | ((a.labels['pd_after_inflate'] >> 2) & 0x3FFFFFF))
    a.sw('t4', 0, 't6'); a.cache(0x19, 0, 't6'); a.word(0xF)
    a.cache(0x10, 0, 't6'); a.word(0xF)
    a.jr('t1'); a.nop()
    a.label('pd_reject')
    a.mtc0('zero', 18); a.nop(); a.jr('t1'); a.nop()
    a.label('pd_fallback')
    a.j(labels['indiana_dispatch']); a.nop()
    site = labels['r2_reboot'] - B.IGR_ADDR - 8
    assert struct.unpack_from('>II', data, site) == (
        0x08000000 | ((labels['indiana_dispatch'] >> 2) & 0x3FFFFFF), 0)
    struct.pack_into('>I', data, site,
                     0x08000000 | ((a.labels['pd_dispatch'] >> 2) & 0x3FFFFFF))
    return bytes(data) + a.build(), dict(labels, **a.labels)


def cave():
    return C.cave(runtime, I.Q.EXTRA, I.Q.PROFILES,
                  common_headers=(I.HEADER, HEADER))


def main(src, dst):
    return C.main(src, dst, cave_builder=cave)


if __name__ == '__main__':
    import sys
    main(*sys.argv[1:])
