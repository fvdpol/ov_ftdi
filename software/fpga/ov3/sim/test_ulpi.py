# Copyright (c) 2026 Tomasz Moń
# SPDX-License-Identifier: BSD-3-Clause

import unittest
import collections

from migen import *
from migen.sim import run_simulation, passive

from ovhw.constants import *
from ovhw.ulpi import ULPI_ctrl, ULPI_pl, ULPI_REG, ULPI_LS_LINK_DECISION_TIMEOUT
from sim.model_ulpi import ULPIPhyModel, ULPIRxEvent, ULPI_PHY_MODEL, ULPI_TX_CMD_CODE

EV_ABORT = ULPIRxEvent(rxcmd=0x00)
EV_RX_DATA = ULPIRxEvent(rxcmd=0x01, payload=[0x4B, 0x6F, 0x00, 0x93])

# Host sends PRE at Full-Speed and continues with Low-Speed packet without EOP.
# Simulation does not model actual D+/D- signaling, so just add a stuff byte
# that will keep the transmission ongoing. DUT is expected to terminate the
# transfer after PRE is received so the stuff byte must not appear in captured
# payload.

# Full-Speed PRE token with a stuffed byte
FS_PRE = ULPIRxEvent(payload=[0x3C, 0xAA])

# Low-Speed IN token (host->device)
LS_IN = ULPIRxEvent(payload=[0x69, 0x88])

# Low-Speed NAK handshake (device->host)
LS_NAK = ULPIRxEvent(payload=[0x5A])

# Function Control XcvrSelect
XCVR_SPEED_STR = {
    0b00: "HS",
    0b01: "FS",
    0b10: "LS",
    0b11: "FS-for-LS",
}

class ULPITB(Module):
    def __init__(self, handle_fs_pre=0):
        self.ulpi_reg = Record(ULPI_REG)
        phy_io = Record(ULPI_PHY_MODEL)

        self.submodules.pl = pl = ULPI_pl()

        # Connect ULPI_pl to PHY model interface
        # First capture actual ULPI outputs temporary flip-flops
        d_o = Signal(8)
        d_oe = Signal()
        stp = Signal()
        self.sync.ulpi += [
            d_o.eq(pl.d_o),
            d_oe.eq(pl.d_oe),
            stp.eq(pl.stp)
        ]
        # Then mimic the propagation delay
        link_doe = Signal()
        self.sync.ulpi_link_output += [
            phy_io.data_link.eq(d_o),
            link_doe.eq(d_oe),
            phy_io.stp.eq(stp),
        ]
        self.comb += [
            phy_io.link_drives_data.eq(link_doe & ~phy_io.dir),
            pl.d_i.eq(phy_io.data_phy),
            pl.dir.eq(phy_io.dir),
            pl.nxt.eq(phy_io.nxt),
        ]

        # Run ULPI controller in simulator sys clock domain
        self.submodules.ctrl = ctrl = ULPI_ctrl(pl.ulpi_bus, self.ulpi_reg, handle_fs_pre)

        self.submodules.phy = ULPIPhyModel()
        # Hack: Make PHY behave like High-Speed to eliminate interpacket gaps.
        # This causes speed mismatch between DUT reported speed (which defaults
        # to Full-Speed which matches PHY) and how simulated PHY behaves during
        # tests. If test doesn't want the mismatch, it can either set PHY
        # directly to Full-Speed, or perform DUT write to Function Control.
        self.phy.regs.write(0x04, 0x40)

        self.comb += [
            self.phy.io.connect(phy_io),
            # Always accept capture stream.
            ctrl.data_out_source.ack.eq(1),
        ]

        # key: timestamp, value: (speed, packet) tuple
        self.packets = collections.OrderedDict()

    @passive
    def pkt_reader(self):
        src = self.ctrl.data_out_source
        packet_timestamp = None
        packet_speed = None
        packet_data = None
        timestamp = 0
        while True:
            if (yield src.stb) and (yield src.ack):
                rxcmd = (yield src.payload.rxcmd)
                d = (yield src.payload.d)
                speed = (yield src.payload.speed)

                if packet_data is not None:
                    if speed != packet_speed:
                        raise AssertionError("Speed changed during packet")

                if rxcmd:
                    if d == RXCMD_MAGIC_SOP:
                        if packet_data is not None:
                            raise AssertionError("SOP but previous packet not finished")

                        packet_timestamp = timestamp
                        packet_speed = speed
                        packet_data = []
                    elif d == RXCMD_MAGIC_EOP:
                        if packet_data:
                            packet = (XCVR_SPEED_STR[packet_speed], packet_data)
                            self.packets[packet_timestamp] = packet

                        packet_timestamp = None
                        packet_speed = None
                        packet_data = None
                    elif (d & 0x40) == 0:
                        # Not a magic value, but actual ULPI RX CMD
                        rx_active = d & 0x01

                        if rx_active and (packet_data is None):
                            packet_timestamp = timestamp
                            packet_speed = speed
                            packet_data = []
                else:
                    if packet_data is None:
                        raise AssertionError("Payload received without SOP/RxActive")
                    else:
                        packet_data.append(d)

            yield
            timestamp = timestamp + 1


class TestULPI(unittest.TestCase):
    def _run(self, sequence, vcd_suffix=None, handle_fs_pre=0):
        tb = ULPITB(handle_fs_pre=handle_fs_pre)
        name = self.id().rsplit(".test_", 1)[-1]
        vcd_name = "testulpi-" + name
        if vcd_suffix:
            vcd_name += "-" + vcd_suffix
        vcd_name += ".vcd"
        if isinstance(sequence, list):
            test_sequence = [stim(tb) for stim in sequence]
        else:
            test_sequence = [sequence(tb)]
        # Everything runs in ulpi clock domain, but add fake ulpi_phy_output
        # clock that is shifted by 6 ns (PHY output delay max) to make VCD files
        # resemble real waveforms that can be captured with logic analyzer.
        run_simulation(tb, {"ulpi": test_sequence + [tb.pkt_reader(), tb.phy.run()]},
                       clocks={
                           "ulpi": 16,
                           "ulpi_phy_output": (16, 10),
                           "ulpi_link_output": (16, 6),
                       },
                       vcd_name=vcd_name)
        return tb

    def _extra_noop_cycle(self, tb):
        # NOOP cycle introduced when registering ULPI outputs. ULPI controller
        # refactor should make it possible to eliminate this additional NOOP
        # cycle, but it is not considered important. This function is intended
        # to clearly mark the places in test sequences where the functionality
        # differs post registration. Do not use for other purposes.
        self.assertEqual(0, (yield tb.phy.io.data_link))
        self.assertEqual(0, (yield tb.phy.io.dir))
        self.assertEqual(0, (yield tb.phy.io.nxt))
        yield

    def _start_regread(self, tb, addr):
        yield tb.ulpi_reg.raddr.eq(addr)
        yield tb.ulpi_reg.rreq.eq(1)
        # Make the request visible to controller
        yield
        # Controller picks up request
        yield
        yield from self._extra_noop_cycle(tb)

    def _perform_regread(self, tb, addr, cmd_event=None, turnaround_event=None):
        # Test only supports immediate 6-bit addresses
        EXTR = 0b101111
        self.assertIn(addr, [i for i in range(0x40) if i != EXTR])

        exp_cmd_byte = (ULPI_TX_CMD_CODE["RegRead"] << 6) | addr

        # Command phase
        for i in range(tb.phy.reg_cmd_delay + 1):
            if cmd_event and i == tb.phy.reg_cmd_delay:
                tb.phy.queue_rx_event(cmd_event)

            self.assertEqual(0, (yield tb.phy.io.dir))
            self.assertEqual(0, (yield tb.phy.io.nxt))
            self.assertEqual(exp_cmd_byte, (yield tb.phy.io.data_link))
            yield

        if cmd_event:
            # PHY takes ownership of the bus, aborts read
            self.assertEqual(1, (yield tb.phy.io.dir))
            return False

        # PHY accepts RegRead command
        self.assertEqual(exp_cmd_byte, (yield tb.phy.io.data_link))
        self.assertEqual(1, (yield tb.phy.io.nxt))
        self.assertEqual(0, (yield tb.phy.io.dir))

        if turnaround_event:
            tb.phy.queue_rx_event(turnaround_event)

        yield

        # Turnaround
        self.assertEqual(1, (yield tb.phy.io.dir))

        if turnaround_event:
            # Register read attempt ends here
            self.assertEqual(1, (yield tb.phy.io.nxt))
            return False

        self.assertEqual(0, (yield tb.phy.io.nxt))

        return True

    def _complete_regread(self, tb, addr, cmd_event=None, turnaround_event=None):
        success = yield from self._perform_regread(tb, addr, cmd_event, turnaround_event)
        if not success:
            return

        yield

        # Controller samples register value
        yield

        self.assertEqual(1, (yield tb.ulpi_reg.rack))
        yield tb.ulpi_reg.rreq.eq(0)

    def _regread(self, tb, addr, cmd_event=None, turnaround_event=None):
        yield from self._start_regread(tb, addr)
        yield from self._complete_regread(tb, addr, cmd_event, turnaround_event)

    def _start_regwrite(self, tb, addr, val):
        yield tb.ulpi_reg.waddr.eq(addr)
        yield tb.ulpi_reg.wdata.eq(val)
        yield tb.ulpi_reg.wreq.eq(1)
        # Make the request visible to controller
        yield
        # Controller picks up request
        yield
        yield from self._extra_noop_cycle(tb)

    def _perform_regwrite(self, tb, addr, val, cmd_event=None, data_event=None):
        # Test only supports immediate 6-bit addresses
        EXTW = 0b101111
        self.assertIn(addr, [i for i in range(0x40) if i != EXTW])

        exp_cmd_byte = (ULPI_TX_CMD_CODE["RegWrite"] << 6) | addr

        # Command phase
        for i in range(tb.phy.reg_cmd_delay + 1):
            if cmd_event and i == tb.phy.reg_cmd_delay:
                tb.phy.queue_rx_event(cmd_event)

            self.assertEqual(exp_cmd_byte, (yield tb.phy.io.data_link))
            if i <= tb.phy.reg_cmd_delay:
               self.assertEqual(0, (yield tb.phy.io.dir))
               self.assertEqual(0, (yield tb.phy.io.nxt))

            yield

        if cmd_event:
            # PHY takes ownership of the bus, aborts write
            self.assertEqual(1, (yield tb.phy.io.dir))
            return False

        # PHY accepts RegWrite command
        self.assertEqual(exp_cmd_byte, (yield tb.phy.io.data_link))
        self.assertEqual(1, (yield tb.phy.io.nxt))
        self.assertEqual(0, (yield tb.phy.io.dir))

        # Data phase
        for i in range(tb.phy.reg_data_delay + 1):
            if data_event and i == tb.phy.reg_data_delay:
                tb.phy.queue_rx_event(data_event)
            yield

            if i < tb.phy.reg_data_delay:
                self.assertEqual(0, (yield tb.phy.io.nxt))
                self.assertEqual(val, (yield tb.phy.io.data_link))

        if data_event:
            # PHY takes ownership of the bus, aborts write
            self.assertEqual(1, (yield tb.phy.io.dir))
            return False

        # PHY accepts data
        self.assertEqual(val, (yield tb.phy.io.data_link))
        self.assertEqual(1, (yield tb.phy.io.nxt))
        self.assertEqual(0, (yield tb.phy.io.dir))

        return True

    def _complete_regwrite(self, tb, addr, val, cmd_event=None, data_event=None):
        success = yield from self._perform_regwrite(tb, addr, val, cmd_event, data_event)
        if not success:
            return

        yield
        self.assertEqual(1, (yield tb.phy.io.stp))

        # Controller takes one more cycle to acknowledge write
        yield

        self.assertEqual(1, (yield tb.ulpi_reg.wack))
        yield tb.ulpi_reg.wreq.eq(0)

    def _regwrite(self, tb, addr, val, cmd_event=None, data_event=None):
        yield from self._start_regwrite(tb, addr, val)
        yield from self._complete_regwrite(tb, addr, val, cmd_event, data_event)

    def _receive_rxcmd(self, tb, expected_rxcmd):
        self.assertEqual(1, (yield tb.phy.io.dir))
        self.assertEqual(0, (yield tb.phy.io.nxt))
        self.assertEqual(expected_rxcmd, (yield tb.phy.io.data_phy))
        yield

    def _receive_packet(self, tb, packet):
        for byte in packet:
            for _ in range(tb.phy.cycles_per_byte - 1):
                self.assertEqual(1, (yield tb.phy.io.dir))
                self.assertEqual(0, (yield tb.phy.io.nxt))
                yield

            self.assertEqual(1, (yield tb.phy.io.dir))
            self.assertEqual(1, (yield tb.phy.io.nxt))
            self.assertEqual(byte, (yield tb.phy.io.data_phy))
            yield

    def _event_sequence(self, tb, event, after_turnaround=False, before_turnaround=False):
        if after_turnaround:
            self.assertEqual(0, (yield tb.phy.turnaround))
        else:
            if before_turnaround:
                self.assertEqual(0, (yield tb.phy.io.dir))
                yield

            self.assertEqual(1, (yield tb.phy.turnaround))
            self.assertEqual(1, (yield tb.phy.io.dir))
            self.assertEqual(1 if event.payload else 0, (yield tb.phy.io.nxt))
            yield

        # RXCMD
        yield from self._receive_rxcmd(tb, event.rxcmd)

        if event.payload:
            yield from self._receive_packet(tb, event.payload)

        # Turnaround PHY->Link
        self.assertEqual(1, (yield tb.phy.turnaround))
        self.assertEqual(0, (yield tb.phy.io.dir))
        yield

    def test_regwrite_delay_combinations(self):
        # Link must wait for nxt to assert while driving reg write command, and
        # it must also wait for nxt to assert while driving actual data. Check
        # multiple cases to ensure all possibilities are handled correctly.
        addr = 0x16
        value = 0x42
        for cmd_delay, data_delay in [(0, 0), (1, 0), (0, 1), (1, 1), (2, 2)]:
            with self.subTest(cmd_delay=cmd_delay, data_delay=data_delay):
                def sequence(tb):
                    tb.phy.reg_cmd_delay = cmd_delay
                    tb.phy.reg_data_delay = data_delay
                    yield from self._regwrite(tb, addr, value)

                vcd_suffix = "cmd%d-data%d" % (cmd_delay, data_delay)
                tb = self._run(sequence, vcd_suffix=vcd_suffix)
                self.assertEqual(tb.phy.reg_writes, [(addr, value)])

    def test_regwrite_retry_after_dir_abort(self):
        # PHY must retry register write after write being aborted by PHY
        addr = 0x16
        value = 0x42
        def sequence(tb):
            yield from self._regwrite(tb, addr, value, cmd_event=EV_ABORT)
            yield from self._event_sequence(tb, EV_ABORT)
            yield from self._complete_regwrite(tb, addr, value)

        tb = self._run(sequence)
        self.assertEqual(tb.phy.reg_writes, [(addr, value)])

    def test_regwrite_abort_at_every_cycle(self):
        # PHY can abort register write at any cycle prior to stp
        addr = 0x16
        value = 0x42

        for cmd_abort_at in range(3):
            with self.subTest(cmd_abort_at=cmd_abort_at):
                def sequence(tb):
                    tb.phy.reg_cmd_delay = cmd_abort_at
                    yield from self._regwrite(tb, addr, value, cmd_event=EV_ABORT)
                    yield from self._event_sequence(tb, EV_ABORT)
                    yield from self._complete_regwrite(tb, addr, value)

                vcd_suffix = "cmdabort%d" % cmd_abort_at
                tb = self._run(sequence, vcd_suffix=vcd_suffix)
                self.assertEqual(tb.phy.reg_writes, [(addr, value)])

        for data_abort_at in range(3):
            with self.subTest(data_abort_at=data_abort_at):
                def sequence(tb):
                    tb.phy.reg_data_delay = data_abort_at
                    yield from self._regwrite(tb, addr, value, data_event=EV_ABORT)
                    yield from self._event_sequence(tb, EV_ABORT)
                    yield from self._complete_regwrite(tb, addr, value)

                vcd_suffix = "dataabort%d" % data_abort_at
                tb = self._run(sequence, vcd_suffix=vcd_suffix)
                self.assertEqual(tb.phy.reg_writes, [(addr, value)])

    def test_regwrite_xcvr_select_updates_only_on_success(self):
        # Reported transceiver speed must update on successful register write.
        # Verify that reported speed does not change on aborted write, but does
        # once the write succesfully finishes.
        def sequence(tb):
            addr = 0x04
            value = 0x42
            yield from self._regwrite(tb, addr, value, cmd_event=EV_ABORT)
            yield from self._event_sequence(tb, EV_ABORT)
            yield from self._complete_regwrite(tb, addr, value)
            self.assertEqual(value & 0x3, (yield tb.ctrl.data_out_source.payload.speed))

        @passive
        def watch_speed_unchanged(tb):
            yield
            expected_speed = (yield tb.ctrl.data_out_source.payload.speed)
            self.assertEqual(expected_speed, 0b01)
            while True:
                if (yield tb.ulpi_reg.wack):
                    expected_speed = 0b10
                speed = (yield tb.ctrl.data_out_source.payload.speed)
                self.assertEqual(expected_speed, speed)
                yield

        self._run([sequence, watch_speed_unchanged])

    def test_regread(self):
        def sequence(tb):
            yield from self._regread(tb, 0x00)
            self.assertEqual(0x24, (yield tb.ulpi_reg.rdata))

        self._run(sequence)

    def test_regread_minimum_nxt_latency(self):
        # ULPI specification does not require any wait cycles on register reads.
        # Configure model to respond to register reads as fast as possible and
        # verify that controller can handle such behavior.
        def sequence(tb):
            tb.phy.reg_cmd_delay = 0
            yield from self._regread(tb, 0x00)
            self.assertEqual(0x24, (yield tb.ulpi_reg.rdata))

        self._run(sequence)

    def test_regread_reflects_prior_write(self):
        def sequence(tb):
            addr = 0x16
            value = 0x5A
            yield from self._regwrite(tb, addr, value)
            yield from self._regread(tb, addr)
            self.assertEqual(value, (yield tb.ulpi_reg.rdata))
            self.assertEqual(value, tb.phy.regs.read(addr))

        self._run(sequence)

    def test_fig23_regread_aborted_by_usb_receive_during_cmd(self):
        # Figure 23: Register read aborted by USB receive during TX CMD byte
        addr = 0x00
        exp_value = 0x24
        def sequence(tb):
            yield from self._regread(tb, addr, cmd_event=EV_RX_DATA)
            yield from self._event_sequence(tb, EV_RX_DATA)

            yield from self._extra_noop_cycle(tb)

            # Link must retry RegRead
            yield from self._complete_regread(tb, addr)
            self.assertEqual(0x24, (yield tb.ulpi_reg.rdata))

        tb = self._run(sequence)
        self.assertEqual(tb.phy.reg_reads, [(addr, exp_value)])
        self.assertEqual(list(tb.packets.values()), [("FS", EV_RX_DATA.payload)])

    def test_fig23_regwrite_aborted_by_usb_receive_during_cmd(self):
        # Figure 23: Register write aborted by USB receive during TX CMD byte
        addr = 0x16
        value = 0x42
        def sequence(tb):
            yield from self._regwrite(tb, addr, value, cmd_event=EV_RX_DATA)
            yield from self._event_sequence(tb, EV_RX_DATA)

            # Link must retry RegWrite
            yield from self._complete_regwrite(tb, addr, value)

        tb = self._run(sequence)
        self.assertEqual(tb.phy.reg_writes, [(addr, value)])
        self.assertEqual(list(tb.packets.values()), [("FS", EV_RX_DATA.payload)])

    def test_fig24_regread_aborted_by_usb_receive_at_turnaround(self):
        # Figure 24: Register read turnaround cycle aborted by USB receive
        addr = 0x00
        exp_value = 0x24
        def sequence(tb):
            yield from self._regread(tb, addr, turnaround_event=EV_RX_DATA)
            yield from self._event_sequence(tb, EV_RX_DATA)

            yield from self._extra_noop_cycle(tb)

            # Link must retry RegWrite
            yield from self._complete_regread(tb, addr)
            self.assertEqual(exp_value, (yield tb.ulpi_reg.rdata))

        tb = self._run(sequence)
        self.assertEqual(tb.phy.reg_reads, [(addr, exp_value)])
        self.assertEqual(list(tb.packets.values()), [("FS", EV_RX_DATA.payload)])

    def test_fig24_regwrite_aborted_by_usb_receive_at_data_cycle(self):
        # Figure 24: Register write data cycle aborted by USB receive
        addr = 0x16
        value = 0x42
        def sequence(tb):
            yield from self._regwrite(tb, addr, value, data_event=EV_RX_DATA)
            yield from self._event_sequence(tb, EV_RX_DATA)

            # Link must retry RegWrite
            yield from self._complete_regwrite(tb, addr, value)

        tb = self._run(sequence)
        self.assertEqual(tb.phy.reg_writes, [(addr, value)])
        self.assertEqual(list(tb.packets.values()), [("FS", EV_RX_DATA.payload)])

    def test_fig25_usb_receive_same_cycle_as_regread_data(self):
        # Figure 25: USB receive in same cycle as register read data.
        # USB receive is delayed.
        addr = 0x00
        exp_value = 0x24
        def sequence(tb):
            yield from self._start_regread(tb, addr)
            success = yield from self._perform_regread(tb, addr)
            self.assertTrue(success)

            # Queue RX packet on the same cycle Reg Data is driven
            tb.phy.queue_rx_event(EV_RX_DATA)
            yield

            self.assertTrue(tb.phy.delayed_receive)

            # Controller samples register value, PHY delays RX
            yield
            self.assertEqual(exp_value, (yield tb.ulpi_reg.rdata))
            self.assertEqual(1, (yield tb.ulpi_reg.rack))
            yield tb.ulpi_reg.rreq.eq(0)

            yield from self._event_sequence(tb, EV_RX_DATA, after_turnaround=True)

        tb = self._run(sequence)
        self.assertEqual(tb.phy.reg_reads, [(addr, exp_value)])
        self.assertEqual(list(tb.packets.values()), [("FS", EV_RX_DATA.payload)])

    def test_fig26_regread_followed_immediately_by_usb_receive(self):
        # Figure 26: Register read followed immediately by a USB receive
        # Actual waveform is the same as Figure 25, the only difference is that
        # the in Figure 25 data is delayed, but here it is not.
        addr = 0x00
        exp_value = 0x24
        def sequence(tb):
            yield from self._start_regread(tb, addr)
            success = yield from self._perform_regread(tb, addr)
            self.assertTrue(success)

            # Queue RX packet a cycle after Reg Data is driven
            yield
            tb.phy.queue_rx_event(EV_RX_DATA)

            self.assertFalse(tb.phy.delayed_receive)

            # Controller samples register value, PHY delays RX
            yield
            self.assertEqual(exp_value, (yield tb.ulpi_reg.rdata))
            self.assertEqual(1, (yield tb.ulpi_reg.rack))
            yield tb.ulpi_reg.rreq.eq(0)

            yield from self._event_sequence(tb, EV_RX_DATA, after_turnaround=True)

        tb = self._run(sequence)
        self.assertEqual(tb.phy.reg_reads, [(addr, exp_value)])
        self.assertEqual(list(tb.packets.values()), [("FS", EV_RX_DATA.payload)])

    def test_fig27_regwrite_followed_by_usb_receive_during_stp(self):
        # Figure 27: Register write followed immediately by a USB receive during
        # stp assertion. This is not an abort, but successful write.
        addr = 0x16
        value = 0x42
        def sequence(tb):
            yield from self._start_regwrite(tb, addr, value)
            yield from self._perform_regwrite(tb, addr, value)

            # Queue RX packet to have it delivered at STP cycle
            tb.phy.queue_rx_event(EV_RX_DATA)
            yield

            # Figure 27 Turnaround cycle
            self.assertEqual(1, (yield tb.phy.io.stp))
            self.assertEqual(1, (yield tb.phy.io.dir))
            self.assertEqual(1, (yield tb.phy.io.nxt))
            yield

            # Controller acknowledges register write at RX CMD cycle
            self.assertEqual(1, (yield tb.ulpi_reg.wack))
            yield tb.ulpi_reg.wreq.eq(0)
            yield from self._event_sequence(tb, EV_RX_DATA, after_turnaround=True)

        tb = self._run(sequence)
        self.assertEqual(tb.phy.reg_writes, [(addr, value)])
        self.assertEqual(list(tb.packets.values()), [("FS", EV_RX_DATA.payload)])

    def test_fig28_regread_followed_by_usb_receive(self):
        # Figure 28: Register read followed by a USB receive
        # There are two turnaround cycles back to back.
        addr = 0x00
        exp_value = 0x24
        def sequence(tb):
            yield from self._regread(tb, addr)
            self.assertEqual(exp_value, (yield tb.ulpi_reg.rdata))
            tb.phy.queue_rx_event(EV_RX_DATA)
            yield from self._event_sequence(tb, EV_RX_DATA, before_turnaround=True)

        tb = self._run(sequence)
        self.assertEqual(tb.phy.reg_reads, [(addr, exp_value)])
        self.assertEqual(list(tb.packets.values()), [("FS", EV_RX_DATA.payload)])

    def test_fig32_phy_aborted_by_link_stp_then_regwrite(self):
        # When Full-Speed host sends PRE PID the packet is not ended with EOP,
        # but instead a Low-Speed packet follows. ULPI controller excersises
        # ULPI specification Revision 1.1 "3.8.4.2 PHY aborted by Link" to
        # switch transceiver from Full-Speed to Low-Speed.
        #
        # This test case contains Figure 32 "PHY aborted by Link asserting stp.
        # Link performs register write or USB transmit." in the test sequence.
        # In order for this test to pass, Link must drive RegWrite command
        # immediately after turnaround cycle. Like in Figure 34 "Link aborts
        # PHY. Link fails to drive a TX CMD. PHY re-asserts dir" the test case
        # will reassert dir and test will fail.
        def sequence_prefix(tb):
            # Set PHY to operate at Full-Speed so PRE handing has time to react
            tb.phy.regs.write(0x04, 0x41)

            # The PHY drives a full-speed receive whose first byte is a PRE.
            # Host sends PRE followed by Low-Speed packet. PHY model does not
            # have equivalent to this, so just attach a data byte that should
            # be aborted by DUT.
            tb.phy.queue_rx_event(FS_PRE)

            # Queue LS IN packet, so it can void guaranteed access if Link does
            # not drive RegWrite immediately after asserting STP.
            tb.phy.queue_rx_event(LS_IN)

            # Wait for model to start delivering RX packet
            self.assertEqual(0, (yield tb.phy.io.dir))
            self.assertEqual(0, (yield tb.phy.io.nxt))
            yield

            # Model starts delivering PRE packet
            self.assertEqual(1, (yield tb.phy.io.dir))
            self.assertEqual(1, (yield tb.phy.io.nxt))
            yield

            yield from self._receive_rxcmd(tb, FS_PRE.rxcmd)

            # Wait for PRE token
            for _ in range(tb.phy.cycles_per_byte - 1):
                self.assertEqual(1, (yield tb.phy.io.dir))
                self.assertEqual(0, (yield tb.phy.io.nxt))
                yield

            # Expect PRE token to be delivered on this cycle
            self.assertEqual(1, (yield tb.phy.io.dir))
            self.assertEqual(1, (yield tb.phy.io.nxt))
            self.assertEqual(FS_PRE.payload[0], (yield tb.phy.io.data_phy))
            yield

            # DUT should abort receive immediately after receiving PRE token
            self.assertEqual(1, (yield tb.phy.io.dir))
            self.assertEqual(1, (yield tb.phy.io.stp))
            yield

            # Turnaround cycle
            self.assertEqual(0, (yield tb.phy.io.dir))
            yield

            yield from self._perform_regwrite(tb, 0x04, 0x6B)
            yield # STP
            self.assertEqual(1, (yield tb.phy.io.stp))

            yield from self._event_sequence(tb, LS_IN, before_turnaround=True)

        def sequence_nak(tb):
            # Low-Speed device responds with NAK
            tb.phy.queue_rx_event(LS_NAK)
            yield from self._event_sequence(tb, LS_NAK, before_turnaround=True)

        def sequence_timeout(tb):
            # Low-Speed device does not reply
            for _ in range(ULPI_LS_LINK_DECISION_TIMEOUT):
                self.assertEqual(0, (yield tb.phy.io.dir))
                self.assertEqual(0, (yield tb.phy.io.nxt))
                self.assertEqual(0, (yield tb.phy.io.stp))
                self.assertEqual(0, (yield tb.phy.io.data_link))
                yield

        def sequence_suffix(tb):
            yield from self._extra_noop_cycle(tb)

            yield from self._perform_regwrite(tb, 0x04, 0x69)
            yield # STP

        for suffix, receives_nak in (("NAK", True), ("timeout", False)):
            with self.subTest(msg=suffix, receives_nak=receives_nak):
                def sequence(tb):
                    yield from sequence_prefix(tb)
                    if receives_nak:
                        yield from sequence_nak(tb)
                    else:
                        yield from sequence_timeout(tb)
                    yield from sequence_suffix(tb)

                tb = self._run(sequence, vcd_suffix=suffix, handle_fs_pre=1)

                # There must be two register writes to FUNC_CTL (0x04):
                #   - switch to FS-for-LS + reset xcvr (0x6b)
                #   - switch to FS (0x69)
                self.assertEqual(tb.phy.reg_writes, [(0x04, 0x6b), (0x04, 0x69)])
                # Captured packets: FS PRE followed the FS-for-LS
                expected_packets = [("FS", [FS_PRE.payload[0]]),
                                    ("FS-for-LS", LS_IN.payload)]
                # and NAK handshake from device in the non-timeout case
                if receives_nak:
                    expected_packets.append(("FS-for-LS", LS_NAK.payload))
                self.assertEqual(list(tb.packets.values()), expected_packets)

    def test_rx_capture(self):
        data = [0x2D, 0x01, 0xE8]

        def sequence(tb):
                event = ULPIRxEvent(payload=data)
                tb.phy.queue_rx_event(event)
                yield from self._event_sequence(tb, event, before_turnaround=True)

        tb = self._run(sequence)
        self.assertEqual(list(tb.packets.values()), [("FS", data)])


if __name__ == "__main__":
    unittest.main()
