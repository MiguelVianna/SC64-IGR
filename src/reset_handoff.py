"""V21 R2: blank VI without writing the game's live framebuffer.

The inherited painter assumes a 240-line allocation. VI width/origin alone do
not establish its size or ownership: painting before the GPU stops can corrupt
adjacent live allocations. All reset paint calls become no-ops in this revision.
The timeout fallback keeps FLUSH asserted while allowing the RDP to progress,
then clears it and checks idle again. A permanently busy GPU still stops; no
software sequence is claimed to reset arbitrarily locked RCP silicon.
"""
import struct


def append(Asm, raw, labels, igr_addr):
    data = bytearray(raw); a = Asm(igr_addr + len(raw))
    a.label('r2_reboot')
    a.lui('t0', 0xA440); a.sw('zero', 0, 't0'); a.word(0xF)
    # Replay the replaced entry, including WatchLo and subsequent CP0 setup.
    a.mtc0('zero', 18); a.lui('t0', 0x3400)
    a.j(labels['reboot'] + 8); a.nop()

    def recover(prefix, target):
        a.label(prefix)
        a.lui('t2', 0xA410)
        a.ori('t1', 'zero', 0x24)  # SET_FLUSH | CLR_FREEZE, retain source
        a.sw('t1', 12, 't2'); a.word(0xF)
        a.lui('t9', 0x10)
        a.label(prefix + '_wait')
        a.lw('t1', 12, 't2'); a.andi('t1', 't1', 0x770)
        a.beq('t1', 'zero', prefix + '_drained'); a.addiu('t9', 't9', -1)
        a.bne('t9', 'zero', prefix + '_wait'); a.nop()
        # Some devices/models only finish when FLUSH is released. Even after
        # this first timeout, release it and require a second observed idle.
        a.label(prefix + '_drained')
        a.ori('t1', 'zero', 0x14); a.sw('t1', 12, 't2'); a.word(0xF)
        # A second bounded wait covers the state transition after CLR_FLUSH.
        a.lui('t9', 0x10); a.label(prefix + '_verify')
        a.lw('t1', 12, 't2'); a.andi('t1', 't1', 0x770)
        a.beq('t1', 'zero', prefix + '_ready'); a.addiu('t9', 't9', -1)
        a.bne('t9', 'zero', prefix + '_verify'); a.nop()
        a.j(labels['rdp_unrecovered']); a.nop()
        a.label(prefix + '_ready'); a.j(target); a.nop()

    recover('r2_rdp_recover', labels['rdp_switch_after_idle'])
    a.label('r2_rdp_before_pi')
    a.lui('t2', 0xA410); a.lw('t1', 12, 't2'); a.andi('t1', 't1', 0x770)
    a.labels['r2_ready_pi'] = labels['rdp_pi_ready']
    a.beq('t1', 'zero', 'r2_ready_pi'); a.nop()
    # Separate fall-through recovery goes to the old, known idle PI setup.
    recover('r2_rdp_final', labels['rdp_pi_ready'])

    for source, target in ((labels['reboot'], a.labels['r2_reboot']),
                           (labels['rdp_recover_before_filler'], a.labels['r2_rdp_recover']),
                           (labels['rdp_require_idle_before_pi'], a.labels['r2_rdp_before_pi'])):
        struct.pack_into('>II', data, source - igr_addr,
                         0x08000000 | ((target >> 2) & 0x3FFFFFF), 0)
    # Replaces the common painter itself, including all white/cyan/diagnostic
    # calls and the old magenta failure call. No stack or framebuffer store.
    struct.pack_into('>II', data, labels['paint'] - igr_addr, 0x03E00008, 0)
    return bytes(data) + a.build(), dict(labels, **a.labels)
