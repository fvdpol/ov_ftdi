# Copyright (c) 2026 Tomasz Moń
# SPDX-License-Identifier: BSD-3-Clause

"""ULPI PHY behavioural model designed to mimic real PHY

USB signaling side is not modeled. Test Bench is expected to queue ULPIRxEvent
at specific test sequence cycles to force certain conditions.
"""

import unittest

from migen import *
from migen.genlib.record import Record, DIR_M_TO_S, DIR_S_TO_M
from migen.sim import passive, run_simulation

from ovhw.constants import *

ULPI_PHY_MODEL = [
     # Migen sim does not support bidirectional IO so we use link_drives_data,
     # data_link and data_phy instead of a bidirectional data.
     ("link_drives_data", 1, DIR_S_TO_M),
     ("data_link", 8, DIR_S_TO_M),
     ("data_phy", 8, DIR_M_TO_S),
     ("dir", 1, DIR_M_TO_S),
     ("nxt", 1, DIR_M_TO_S),
     ("stp", 1, DIR_S_TO_M),
]

# 3.8.1.1 Transmit Command Byte (TX CMD) Command Code data(7:6)
ULPI_TX_CMD_STR = {
    0b00: "Special",
    0b01: "Transmit",
    0b10: "RegWrite",
    0b11: "RegRead",
}
ULPI_TX_CMD_CODE = {v: k for k, v in ULPI_TX_CMD_STR.items()}

ULPI_TX_NOOP = 0

# Migen simulator does not support X value so we need a poison pattern that is
# used during DIR turnaround cycle and in case Link does not drive data bus when
# it should. The pattern used is RSVD TX CMD.
ULPI_BUS_UNKNOWN = 0x3F

# RX CMD status byte the model drives between bytes during Low and Full Speed
# receive. Model does not vary J/K like a real PHY does (as a result of actual
# USB NRZI signaling) but rather uses a fixed value that indicates RxActive,
# LineState=K, VbusState=SessValid.
ULPI_RXCMD_RXACTIVE = 0x5a

# ULPI clocks between consecutive RX data bytes depend on transceiver speed.
# Bitstuffing is not simulated and therefore the number of clocks is fixed
# regardless of the payload.
ULPI_XCVR_CYCLES_PER_BYTE = {0b00: 1, 0b01: 40, 0b10: 320, 0b11: 320}


class ULPIRxEvent:
    def __init__(self, rxcmd=ULPI_RXCMD_RXACTIVE, payload=[]):
        self.rxcmd = rxcmd
        self.payload = payload

    def __bool__(self):
        return self.rxcmd is not None or bool(self.payload)

    def __str__(self):
        msg = []
        if self.rxcmd is not None:
            msg.append(f"RXCMD 0x{self.rxcmd:02x}")
        if self.payload:
            msg.extend(["Payload", bytes(self.payload).hex(' ')])
        return ' '.join(msg)

    def __eq__(self, other):
        if not isinstance(other, ULPIRxEvent):
            return NotImplemented

        return self.rxcmd == other.rxcmd and self.payload == other.payload


class ULPIPhyRegisters:
    """ULPI PHY register storage based on USB3343 datasheet"""

    # (addr, reset value) - read-only
    _READ_ONLY = [
        (0x00, 0x24),  # Vendor ID Low
        (0x01, 0x04),  # Vendor ID High
        (0x02, 0x09),  # Product ID Low
        (0x03, 0x00),  # Product ID High
        (0x13, 0x00),  # USB Interrupt Status
        (0x14, 0x00),  # USB Interrupt Latch
        (0x15, 0x00),  # Debug
        (0x20, 0x00),  # Carkit Interrupt Status
        (0x21, 0x00),  # Carkit Interrupt Latch
    ]

    # (addr, reset value) - read/write
    _READ_WRITE = [
        (0x31, 0x00),  # HS Compensation Register
        (0x32, 0x00),  # USB-IF Charger Detection
        (0x33, 0x00),  # Headset Audio Mode
    ]

    # (write_addr, reset value, set_addr, clear_addr) - read/write registers
    # with multiple aliases
    _READ_WRITE_SET_CLEAR = [
        (0x04, 0x41, 0x05, 0x06),  # Function Control
        (0x07, 0x00, 0x08, 0x09),  # Interface Control
        (0x0A, 0x06, 0x0B, 0x0C),  # OTG Control
        (0x0D, 0x1F, 0x0E, 0x0F),  # USB Interrupt Enable Rising
        (0x10, 0x1F, 0x11, 0x12),  # USB Interrupt Enable Falling
        (0x16, 0x00, 0x17, 0x18),  # Scratch Register
        (0x19, 0x00, 0x1A, 0x1B),  # Carkit Control
        (0x1D, 0x00, 0x1E, 0x1F),  # Carkit Interrupt Enable
        (0x36, 0x00, 0x37, 0x38),  # Vendor Rid Conversion
        (0x39, 0x04, 0x3A, 0x3B),  # USB IO & Power Management
    ]

    def __init__(self):
        # Register storage
        self._regs = {}
        # Register type "ro"/"rw"/"set"/"clear"
        self._type = {}
        # Mapping between register alias and actual storage address
        self._base = {}

        for addr, reset in self._READ_ONLY:
            self._regs[addr] = reset
            self._type[addr] = "ro"
            self._base[addr] = addr

        for addr, reset in self._READ_WRITE:
            self._regs[addr] = reset
            self._type[addr] = "rw"
            self._base[addr] = addr

        for write_addr, reset, set_addr, clear_addr in self._READ_WRITE_SET_CLEAR:
            self._regs[write_addr] = reset
            self._type[write_addr] = "rw"
            self._type[set_addr] = "set"
            self._type[clear_addr] = "clear"
            self._base[write_addr] = write_addr
            self._base[set_addr] = write_addr
            self._base[clear_addr] = write_addr

    def read(self, addr):
        if addr not in self._base:
            raise AssertionError(f"ULPI register 0x{addr:02x} does not exist")
        return self._regs[self._base[addr]]

    def write(self, addr, data):
        if addr not in self._base:
            raise AssertionError(f"ULPI register 0x{addr:02x} does not exist")

        reg_type = self._type[addr]
        base = self._base[addr]

        if reg_type == "ro":
            raise AssertionError(f"write to read-only ULPI register 0x{addr:02x}")
        elif reg_type == "set":
            self._regs[base] = self._regs[base] | data
        elif reg_type == "clear":
            self._regs[base] = self._regs[base] & ~data
        else:
            self._regs[base] = data


class ULPIPhyModel(Module):
    def __init__(self):
        self.io = Record(ULPI_PHY_MODEL)
        self.regs = ULPIPhyRegisters()

        # Control signals changed by model
        self.dir = Signal()
        self.nxt = Signal()
        self.data_phy = Signal(8)

        # Store previous DIR signal state to allow marking turnaround cycles
        self.dir_prev = dir_prev = Signal(reset=1)
        self.turnaround = turnaround = Signal()
        self.sync.ulpi += dir_prev.eq(self.dir)
        self.comb += turnaround.eq(dir_prev != self.dir)

        # Migen simulator does not have timing offsets, just use fake shifted
        # clock to make the transitions appear shifted.
        self.sync.ulpi_phy_output += [
            self.io.dir.eq(self.dir),
            self.io.nxt.eq(self.nxt),
            self.io.data_phy.eq(self.data_phy),
        ]

        # Mark any cycles where ULPI data bus is floating
        floating = Signal()
        self.comb += floating.eq(~self.dir & ~self.io.link_drives_data)

        # Model actual state on bidirectional ULPI data bus
        self.ulpi_data_bus = ulpi_data_bus = Signal(8)
        self.comb += [
            If(turnaround | floating,
                ulpi_data_bus.eq(ULPI_BUS_UNKNOWN),
            ).Elif(self.io.dir,
                ulpi_data_bus.eq(self.io.data_phy),
            ).Else(
                ulpi_data_bus.eq(self.io.data_link),
            ),
        ]

        # Internal flag used to mark guaranteed Link access as described in
        # UTMI+ Low Pin Interface Specification, Revision 1.1
        # 3.8.4.2 PHY aborted by Link
        self._aborted_by_link = False

        # Record all register accesses that happened on ULPI interface
        # New entry (addr, value) is appended to reg_writes/reg_reads when
        # RegWrite/RegRead command finishes. Aborted attempts are not recorded.
        self.reg_writes = []
        self.reg_reads = []

        # True if USB receive happens in same cycle as register read data.
        self.delayed_receive = False

        # One cycle Reg Read/Reg Write delay means that the register command
        # will be driven for 3 cycles:
        #   - initial cycle (after this cycle PHY samples command)
        #   - 1 delay cycle (matches USB3343)
        #   - command accepted cycle (PHY drives nxt)
        self.reg_cmd_delay = 1
        # Number of cycles it takes the Reg Write to accept data
        self.reg_data_delay = 0

        # ULPIRxEvent queue
        self.events = []

    def queue_rx_event(self, event):
        """Queue ULPIRxEvent for processing. If multiple events are queued,
        then they are processed in FIFO order."""
        self.events.append(event)

    def _take_pending_event(self):
        if self.events:
            return self.events.pop(0)
        return None

    def _tick(self):
        # Perform bus tri-state sanity checks on every simulation cycle

        phy_owns_data = (yield self.dir)
        link_drives_data = (yield self.io.link_drives_data)

        if phy_owns_data and link_drives_data:
            raise AssertionError("Data tristate conflict")

        yield

        phy_owns_data_after_clk = (yield self.dir)
        link_drives_data_after_clk = (yield self.io.link_drives_data)

        if phy_owns_data != phy_owns_data_after_clk:
            if phy_owns_data_after_clk:
                # Link -> PHY turnaround
                if link_drives_data_after_clk:
                    raise AssertionError("Link drives data on Link->PHY turnaround")
            else:
                # PHY -> Link turnaround
                if link_drives_data:
                    raise AssertionError("Link drives data on PHY->Link turnaround")
        else:
            if not phy_owns_data_after_clk and not link_drives_data_after_clk:
                raise AssertionError("Link does not drive data")

    @property
    def cycles_per_byte(self):
        """ULPI clocks between consecutive RX data bytes at the transceiver
        speed currently selected in Function Control register."""
        return ULPI_XCVR_CYCLES_PER_BYTE[self.regs.read(0x04) & 0x3]

    def _deliver_payload(self, payload):
        for byte in payload:
            # Inter-byte gap before each byte. Real PHY is signaling line state
            # throughout the packet receive according to actual D+/D- state.
            # This model just assumes a fixed RX CMD. Also at High-Speed there
            # can be a gap due to bitstuffing, but this model does not simulate
            # this and assumes no gap.
            for _ in range(self.cycles_per_byte - 1):
                if (yield self.io.stp):
                    # PHY aborted by Link
                    return
                yield self.nxt.eq(0)
                yield self.data_phy.eq(ULPI_RXCMD_RXACTIVE)
                yield from self._tick()
            if (yield self.io.stp):
                # PHY aborted by Link
                return
            yield self.data_phy.eq(byte)
            yield self.nxt.eq(1)
            yield from self._tick()

    def _deliver(self, event):
        """Deliver event on simulated ULPI bus."""
        if not (yield self.dir):
            # Link->PHY Turnaround
            yield self.dir.eq(1)
            yield self.nxt.eq(1 if event.payload else 0)
            yield self.data_phy.eq(0)
            if event.rxcmd is None:
                raise AssertionError("RX CMD is mandatory after turnaround")
            yield from self._tick()

        if event.rxcmd is not None:
            yield self.nxt.eq(0)
            yield self.data_phy.eq(event.rxcmd)
            yield from self._tick()

            if (yield self.io.stp):
                self._aborted_by_link = True

        if event.payload and not self._aborted_by_link:
            yield from self._deliver_payload(event.payload)
            if (yield self.io.stp):
                self._aborted_by_link = True

        yield self.nxt.eq(0)
        yield self.dir.eq(0)
        yield self.data_phy.eq(0)

    def _hold_cmd_phase(self, cmd, guaranteed):
        event = None if guaranteed else self._take_pending_event()

        for _ in range(self.reg_cmd_delay):
            if event:
                return event

            yield self.nxt.eq(0)
            yield from self._tick()

            data = (yield self.ulpi_data_bus)
            if data != cmd:
                raise AssertionError(f"ULPI bus changed from 0x{cmd:02x} to 0x{data:02x}")

            event = None if guaranteed else self._take_pending_event()

        return event

    def _hold_data_phase(self, guaranteed):
        event = None if guaranteed else self._take_pending_event()

        for _ in range(self.reg_data_delay):
            yield from self._tick()

            event = None if guaranteed else self._take_pending_event()

        return event


    def _do_regwrite(self, cmd, guaranteed):
        addr = cmd & 0x3F

        # Link presented Reg Write command and is expected to keep driving the
        # command byte until PHY accepts or aborts the write.
        event = yield from self._hold_cmd_phase(cmd, guaranteed)
        if event:
            yield from self._deliver(event)
            return

        # Accept Reg Write command
        yield self.nxt.eq(1)
        yield from self._tick()

        # ULPI specification allows PHY to throttle register write.
        # Delay for configured data delay cycles, aborting if necessary.
        yield self.nxt.eq(0)
        event = yield from self._hold_data_phase(guaranteed)
        if event:
            yield from self._deliver(event)
            return

        # Accept data
        yield self.nxt.eq(1)
        yield from self._tick()
        yield self.nxt.eq(0)

        # Perform register write
        value = (yield self.ulpi_data_bus)
        self.regs.write(addr, value)
        self.reg_writes.append((addr, value))

        # Link must assert stp on next cycle. If there is back-to-back Register
        # Write and USB Receive, then dir will be asserted during stp cycle.
        event = None if guaranteed else self._take_pending_event()
        if event:
            yield self.dir.eq(1)
            if event.payload:
                yield self.nxt.eq(1)
        yield from self._tick()
        if not (yield self.io.stp):
            raise AssertionError("Missing stp after register write")

        if event:
            yield from self._deliver(event)

    def _do_regread(self, cmd, guaranteed):
        addr = cmd & 0x3F

        # Link presented Reg Read command and is expected to keep driving the
        # command byte until PHY accepts or aborts the read.
        event = yield from self._hold_cmd_phase(cmd, guaranteed)
        if event:
            yield from self._deliver(event)
            return

        # Accept Reg Read command
        yield self.nxt.eq(1)
        yield from self._tick()
        yield self.nxt.eq(0)

        event = None if guaranteed else self._take_pending_event()
        if event:
            # Register read turnaround cycle aborted by USB receive
            if not event.payload:
                # Event aborting read on turnaround cycle must assert both dir
                # and nxt to indicate RxActive, not asserting nxt means register
                # data will follow.
                raise AssertionError(str(event), "does not have payload")
            yield from self._deliver(event)
            return

        # Turnaround before presenting data
        yield self.dir.eq(1)
        yield from self._tick()

        event = None if guaranteed else self._take_pending_event()
        if event:
            # PHY cannot abort register read now. RX CMD and packet data will
            # follow after register data.
            self.delayed_receive = True

        # Present Register data. PHY cannot throttle.
        value = self.regs.read(addr)
        yield self.data_phy.eq(value)
        yield from self._tick()
        self.reg_reads.append((addr, value))

        if event:
            yield from self._deliver(event)
            self.delayed_receive = False

    @passive
    def run(self):
        while True:
            guaranteed = self._aborted_by_link
            event = None if guaranteed else self._take_pending_event()
            if event:
                yield from self._deliver(event)
                continue

            if (yield self.dir) == 1:
                # No data to send, give bus ownership to Link
                yield self.dir.eq(0)
                yield from self._tick()
                continue

            if (yield self.turnaround):
                # Ignore data on turnaround cycle
                yield from self._tick()
                continue

            # Link access is guaranteed only for the transaction happening
            # immadietely after PHY aborted by Link turnaround cycle.
            self._aborted_by_link = False

            ulpi_data = (yield self.ulpi_data_bus)
            code = ulpi_data >> 6
            if ulpi_data == ULPI_TX_NOOP:
                yield from self._tick()
            elif code == ULPI_TX_CMD_CODE["RegWrite"]:
                yield from self._do_regwrite(ulpi_data, guaranteed)
            elif code == ULPI_TX_CMD_CODE["RegRead"]:
                yield from self._do_regread(ulpi_data, guaranteed)
            else:
                name = ULPI_TX_CMD_STR[code]
                raise AssertionError(f"Unhandled {name} CMD 0x{ulpi_data:02x}")


class TestULPIPhyRegisters(unittest.TestCase):
    def test_reset_values(self):
        regs = ULPIPhyRegisters()
        # Vendor ID Low
        self.assertEqual(regs.read(0x00), 0x24)
        # Function Control
        self.assertEqual(regs.read(0x04), 0x41)
        # OTG Control
        self.assertEqual(regs.read(0x0A), 0x06)

    def test_plain_write_replaces_value(self):
        regs = ULPIPhyRegisters()
        # Write and then read back Scratch Register
        regs.write(0x16, 0x5A)
        self.assertEqual(regs.read(0x16), 0x5A)

    def test_set_and_clear_aliases_share_base_register(self):
        regs = ULPIPhyRegisters()
        # Function Control has Write, Set and Clear addresses. All aliases must
        # read the same value. First write 0xC8 to Write address.
        regs.write(0x04, 0xC8)
        self.assertEqual(regs.read(0x04), 0xC8)
        self.assertEqual(regs.read(0x05), 0xC8)
        self.assertEqual(regs.read(0x06), 0xC8)

        # Set least significant bit
        regs.write(0x05, 0x01)
        self.assertEqual(regs.read(0x04), 0xC9)
        self.assertEqual(regs.read(0x05), 0xC9)
        self.assertEqual(regs.read(0x06), 0xC9)

        # Clear most significant bit
        regs.write(0x06, 0x80)
        self.assertEqual(regs.read(0x04), 0x49)
        self.assertEqual(regs.read(0x05), 0x49)
        self.assertEqual(regs.read(0x06), 0x49)

    def test_write_to_read_only_register_raises(self):
        regs = ULPIPhyRegisters()
        with self.assertRaises(AssertionError):
            # Vendor ID Low is read-only
            regs.write(0x00, 0x00)


if __name__ == "__main__":
    unittest.main()
