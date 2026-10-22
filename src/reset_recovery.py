"""V21: bounded flush fallback, then require an idle RDP before menu reboot.

The normal V20 drain remains first. Only a timeout invokes the FLUSH/FREEZE
pulse also used by libdragon die(). This cannot promise silicon lock recovery.
If still busy, stop visibly instead of loading a new menu over the active GPU.
No game identifiers or game RAM writes are involved.
"""
import struct


def append(Asm, raw, labels, igr_addr):
    data = bytearray(raw)
    pi = labels['reset_pi_stage'] - igr_addr
    assert struct.unpack_from('>II', data, pi) == (0x3C08A460, 0x3C190004)
    skip = labels['rdp_skip_busy_filler'] - igr_addr
    assert struct.unpack_from('>II', data, skip) == (
        0x08000000 | ((labels['reset_pi_stage'] >> 2) & 0x3FFFFFF), 0)
    a = Asm(igr_addr + len(raw))

    def pulse_and_wait(prefix):
        # Producer is already halted by the inherited common reset.
        # Preserve XBUS until after completion; never touch START/END here.
        a.ori('t1', 'zero', 0x28)  # SET_FREEZE | SET_FLUSH
        a.sw('t1', 12, 't2'); a.word(0xF)
        a.lw('t1', 12, 't2')      # posted MMIO readback
        a.ori('t1', 'zero', 0x14)  # CLR_FREEZE | CLR_FLUSH
        a.sw('t1', 12, 't2'); a.word(0xF)
        a.lui('t9', 0x10)
        a.label(prefix + '_wait')
        a.lw('t1', 12, 't2'); a.andi('t1', 't1', 0x770)
        a.beq('t1', 'zero', prefix + '_idle'); a.addiu('t9', 't9', -1)
        a.bne('t9', 'zero', prefix + '_wait'); a.nop()
        a.j('rdp_unrecovered'); a.nop()
        a.label(prefix + '_idle')

    a.label('rdp_recover_before_filler')
    # V20 jumps here only after the initial drain timeout.
    a.lui('t2', 0xA410)
    pulse_and_wait('rdp_recover')
    a.j(labels['rdp_switch_after_idle']); a.nop()

    a.label('rdp_require_idle_before_pi')
    a.lui('t2', 0xA410)
    a.lw('t1', 12, 't2'); a.andi('t1', 't1', 0x770)
    a.beq('t1', 'zero', 'rdp_pi_ready'); a.nop()
    # Also handle a timeout while processing our own final SYNC_FULL.
    pulse_and_wait('rdp_final')
    a.label('rdp_pi_ready')
    a.lui('t0', 0xA460); a.lui('t9', 4)
    a.j(igr_addr + pi + 8); a.nop()

    a.label('rdp_unrecovered')
    # Reuse the existing bounded framebuffer painter; Watch/interrupts are off.
    # The magenta stop means recovery failed and needs a physical power cycle.
    a.lui('a0', 0xF83F); a.ori('a0', 'a0', 0xF83F)
    a.lui('a1', 0xFF00); a.ori('a1', 'a1', 0xFFFF)
    a.jal(labels['paint']); a.nop()
    a.label('rdp_unrecovered_stop'); a.j('rdp_unrecovered_stop'); a.nop()
    patches = {skip: a.labels['rdp_recover_before_filler'],
               pi: a.labels['rdp_require_idle_before_pi']}
    for at, target in patches.items():
        struct.pack_into('>II', data, at, 0x08000000 | ((target >> 2) & 0x3FFFFFF), 0)
    extra = dict(a.labels, dispatch_v21=labels['dispatch_v20'])
    extra.update({'v21_reset_patch_' + str(i): igr_addr + at
                  for i, at in enumerate(sorted(patches))})
    return bytes(data) + a.build(), dict(labels, **extra)
