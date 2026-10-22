"""Exact US Fighter Destiny 2 binding; preserve native WatchLo setup and handler."""
import struct
import build_igr as B
import build_perfect_dark_candidate as P
import build_three_games_candidate as C

HEADER = (0x46474500, 0xAEEF2F45, 0xF97E30F1)
ENTRY = 0x80000400
TEMPLATE = 0x80025C10
HANDLER = 0x80025CE4
GUARDS = (
    (0x80000400, 0x3C088005), (0x80000404, 0x25082440),
    (0x80000408, 0x3C09000F), (0x8000040C, 0x2529B130),
    (0x80000428, 0x3C0A8000), (0x8000042C, 0x254A047C),
    (0x80000430, 0x3C1D800E), (0x80000434, 0x01400008),
    (0x80000438, 0x27BDCC00),
    (0x80025C10, 0x3C1A8002), (0x80025C14, 0x275A5CE4),
    (0x80025C18, 0x03400008), (0x80025C1C, 0),
    (0x80025CE4, 0x3C1A800C), (0x80025CE8, 0x275A9F58),
    (0x800282B0, 0x40849000), (0x800282B4, 0),
    (0x800282B8, 0x03E00008), (0x800282BC, 0),
    (0x80024EE0, 0x0C00A0AC), (0x80024EE4, 0x3C040490))


def runtime():
    raw, labels = P.runtime(); data = bytearray(raw)
    a = B.Asm(B.IGR_ADDR + len(raw)); a.label('fd2_dispatch')
    a.lui('t3', 0xB000)
    for off, value in zip((0x3C, 0x10, 0x14), HEADER):
        a.lw('t4', off, 't3'); a.li('t5', value)
        a.bne('t4', 't5', 'fd2_fallback'); a.nop()
    a.li('t5', ENTRY); a.bne('t1', 't5', 'fd2_reject'); a.nop()
    for addr, value in GUARDS:
        a.li('t6', addr); a.lw('t4', 0, 't6'); a.li('t5', value)
        a.bne('t4', 't5', 'fd2_reject'); a.nop()
    a.mtc0('zero', 18); a.nop()
    def patch(addr, value):
        a.li('t6', addr); a.li('t4', value); a.sw('t4', 0, 't6')
        a.cache(0x19, 0, 't6'); a.word(0xF); a.cache(0x10, 0, 't6'); a.word(0xF)
    patch(labels['ORIG'], HANDLER); patch(labels['TPLFLAG'], 1)
    entryb = labels['entryB']
    assert (entryb & 0xFFFF) < 0x8000
    patch(TEMPLATE, 0x3C1A0000 | (entryb >> 16))
    patch(TEMPLATE + 4, 0x275A0000 | (entryb & 0xFFFF))
    a.jr('t1'); a.nop()
    a.label('fd2_reject'); a.mtc0('zero', 18); a.nop(); a.jr('t1'); a.nop()
    a.label('fd2_fallback'); a.j(labels['pd_dispatch']); a.nop()
    site = labels['r2_reboot'] - B.IGR_ADDR - 8
    assert struct.unpack_from('>II', data, site) == (
        0x08000000 | ((labels['pd_dispatch'] >> 2) & 0x3FFFFFF), 0)
    struct.pack_into('>I', data, site, 0x08000000 | ((a.labels['fd2_dispatch'] >> 2) & 0x3FFFFFF))
    return bytes(data) + a.build(), dict(labels, **a.labels)


def cave():
    return C.cave(runtime, P.I.Q.EXTRA, P.I.Q.PROFILES,
                  common_headers=(P.I.HEADER, P.HEADER, HEADER))


def main(src, dst): return C.main(src, dst, cave_builder=cave)


if __name__ == '__main__':
    import sys
    main(*sys.argv[1:])
