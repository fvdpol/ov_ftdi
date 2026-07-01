# Copyright (c) 2026 Tomasz Moń
# SPDX-License-Identifier: BSD-3-Clause

import unittest

from migen import *
from migen.sim import run_simulation

from ovhw.ftdi_bus import FTDI_sync245
from sim.model_ftdi import FT245SyncModel, FT245_MODEL


class TestBench(Module):
    INCOMING_DEPTH = 64
    OUTPUT_DEPTH = 64 + 1

    def __init__(self):
        ftdi_io = Record(FT245_MODEL)

        self.submodules.dut = dut = FTDI_sync245()

        # Connect controller signals to FTDI model interface
        ftdi_io.rd_n.reset = dut.rd_n.reset
        ftdi_io.oe_n.reset = dut.oe_n.reset
        ftdi_io.wr_n.reset = dut.wr_n.reset
        ftdi_io.siwu_n.reset = dut.siwua_n.reset
        self.comb += [
            dut.rxf_n.eq(ftdi_io.rxf_n),
            dut.txe_n.eq(ftdi_io.txe_n),
            dut.d_i.eq(ftdi_io.data_ftdi),
            ftdi_io.siwu_n.eq(dut.siwua_n),
        ]
        self.sync.ftdi += [
            ftdi_io.rd_n.eq(dut.rd_n),
            ftdi_io.oe_n.eq(dut.oe_n),
            ftdi_io.wr_n.eq(dut.wr_n),
            ftdi_io.data_ext.eq(dut.d_o),
            ftdi_io.ext_drives_data.eq(dut.d_oe),
        ]

        self.submodules.ftdi_model = FT245SyncModel()
        self.comb += [
            self.ftdi_model.io.connect(ftdi_io),
        ]

    def add_reset_generator(self):
        # Reset generator, reset ftdi clock domain after 4 sys clock cycles
        # Do not add new clock domain here to not slow down simulation
        self.clock_domains.cd_sys = ClockDomain()
        self.clock_domains.cd_ftdi = ClockDomain()

        self.cd_sys.rst.reset = 0
        self.cd_ftdi.rst.reset = 1

        rst_ctr = Signal(max=4)
        self.sync += [
            If(rst_ctr == 3,
                self.cd_ftdi.rst.eq(0)
            ).Else(
                rst_ctr.eq(rst_ctr+1)
            )
        ]

    def connect_loopback(self):
        # sys-domain loopback: incoming -> outgoing
        inc = self.dut.incoming_fifo
        out = self.dut.output_fifo
        self.comb += [
            out.din.eq(inc.dout),
            out.we.eq(inc.readable & out.writable),
            inc.re.eq(inc.readable & out.writable),
        ]


class TestFTDI(unittest.TestCase):
    def _run_loopback_test(self, sequence):
        tb = TestBench()
        name = self.id().rsplit(".test_", 1)[-1]
        vcd_name = f"testftdi-{name}.vcd"

        tb.add_reset_generator()
        tb.connect_loopback()

        run_simulation(
            tb,
            {"ftdi": [sequence(tb), tb.ftdi_model.run()]},
            clocks={"sys": 10, "ftdi": 16},
            vcd_name=vcd_name,
        )

        self.assertEqual(tb.ftdi_model.unread_rx_bytes, 0)
        sent = [f"{byte:02x}" for byte in tb.ftdi_model.rx_data]
        received = [f"{byte:02x}" for byte in tb.ftdi_model.tx_data]
        self.maxDiff = None
        self.assertSequenceEqual(sent, received)

    def test_loopback(self):
        def sequence(tb):
            # Fill both incoming and output fifos
            filler = bytes([i for i in range(tb.INCOMING_DEPTH + tb.OUTPUT_DEPTH)])
            tb.ftdi_model.append_rx(filler)

            # Wait for reset to be released
            while (yield tb.cd_ftdi.rst):
                yield

            # Allow up to 5 cycles per byte
            for _ in range(5 * (tb.INCOMING_DEPTH + tb.OUTPUT_DEPTH)):
                yield

            # Both fifos should be full and FTDI should have no more RX data
            self.assertEqual((yield tb.dut.incoming_fifo.writable), 0)
            self.assertEqual((yield tb.dut.output_fifo.writable), 0)
            self.assertEqual(tb.ftdi_model.unread_rx_bytes, 0)

            # Allow two bytes to go out from DUT
            tb.ftdi_model.accept_tx(2)
            for _ in range(10):
                yield

            # Allow another byte byte to go out from DUT
            tb.ftdi_model.accept_tx(1)
            for _ in range(10):
                yield

            tb.ftdi_model.append_rx([0x12, 0x34, 0x56, 0x78])
            for _ in range(20):
                yield

            # Fetch whole output fifo while constantly issuing new data
            tb.ftdi_model.append_rx([i for i in range(tb.OUTPUT_DEPTH)])
            tb.ftdi_model.accept_tx(tb.OUTPUT_DEPTH)
            for _ in range(5 * tb.OUTPUT_DEPTH):
                yield

            # Drain output fifo, allow TXing more bytes that were fed
            tb.ftdi_model.accept_tx(tb.INCOMING_DEPTH + tb.OUTPUT_DEPTH + 100)
            for _ in range(5 * (tb.INCOMING_DEPTH + tb.OUTPUT_DEPTH)):
                yield

        self._run_loopback_test(sequence)

    def test_write_yields_on_stall(self):
        def sequence(tb):
            # Get data into DUT from model RX -> incoming_fifo -> output_fifo
            tb.ftdi_model.append_rx([1, 2, 3, 4])
            for _ in range(20):
                yield

            # Accept 1 TX byte from DUT
            tb.ftdi_model.accept_tx(1)
            for _ in range(20):
                yield

            # New data available for DUT to read
            tb.ftdi_model.append_rx([5, 6, 7, 8])
            i = 0
            timeout = 100
            while tb.ftdi_model.unread_rx_bytes and i < timeout:
                yield
                i = i + 1
            self.assertLess(i, timeout, "Controller stuck in WRITE didn't service pending read")

            tb.ftdi_model.accept_tx(7)
            for _ in range(20):
                yield

        self._run_loopback_test(sequence)

    def test_write_yields_when_done(self):
        def sequence(tb):
            # Get data into DUT from model RX -> incoming_fifo -> output_fifo
            tb.ftdi_model.append_rx([1, 2, 3, 4])
            for _ in range(20):
                yield

            # Accept 4 TX byte from DUT
            tb.ftdi_model.accept_tx(4)
            for _ in range(20):
                yield

            # All 4 bytes should have made it into FTDI
            self.assertEqual(tb.ftdi_model.available_tx_space, 0)

            # New data available for DUT to read
            tb.ftdi_model.append_rx([5, 6, 7, 8])
            i = 0
            timeout = 100
            while tb.ftdi_model.unread_rx_bytes and i < timeout:
                yield
                i = i + 1
            self.assertLess(i, timeout, "Controller stuck in WRITE didn't service pending read")

            tb.ftdi_model.accept_tx(7)
            for _ in range(20):
                yield

        self._run_loopback_test(sequence)


if __name__ == "__main__":
    unittest.main()
