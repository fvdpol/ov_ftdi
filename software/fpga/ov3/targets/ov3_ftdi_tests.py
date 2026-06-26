# Copyright (c) 2026 Tomasz Moń
# SPDX-License-Identifier: BSD-3-Clause

"""Standalone FTDI test bitstreams for testing FTDI bus on real hardware.

FTDILoopback : on startup (after the PLL locks) transmit a fixed banner once,
               then loop the incoming FIFO (host -> FPGA) straight back into
               the outgoing FIFO (FPGA -> host).
FTDITXRamp   : ignore host input, stream an incrementing mod-256 counter to
               the host forever. Isolates the write (FPGA -> host) path.
"""

from migen import *

from targets.ov3_base import OV3BaseSoC

LOOPBACK_BANNER = b"OV FTDI LOOPBACK READY\r\n"


class FTDILoopback(OV3BaseSoC):
    def __init__(self, plat):
        super().__init__(plat)

        ftdi_bus = self.add_ftdi_bus(plat.request('ftdi'))

        inc = ftdi_bus.incoming_fifo
        out = ftdi_bus.output_fifo

        # Stream startup banner from array ROM to output fifo.
        banner_rom = Array(Constant(b, 8) for b in LOOPBACK_BANNER)
        banner_idx = Signal(max=len(LOOPBACK_BANNER) + 1)
        banner_done = Signal()
        self.comb += banner_done.eq(banner_idx == len(LOOPBACK_BANNER))
        self.sync.sys += If(~banner_done & out.writable,
                            banner_idx.eq(banner_idx + 1))

        self.comb += [
            If(banner_done,
                # Normal operation: loop incoming straight back out.
                out.din.eq(inc.dout),
                out.we.eq(inc.readable & out.writable),
                inc.re.eq(inc.readable & out.writable),
            ).Else(
                # Banner phase: drive the banner, hold off the loopback.
                out.din.eq(banner_rom[banner_idx]),
                out.we.eq(out.writable),
                inc.re.eq(0),
            ),
        ]

        leds = plat.request("leds")
        self.comb += leds.eq(~Cat(ftdi_bus.rx_ind, ftdi_bus.tx_ind, Constant(0, 1)))


class FTDITXRamp(OV3BaseSoC):
    def __init__(self, plat):
        super().__init__(plat)

        ftdi_bus = self.add_ftdi_bus(plat.request('ftdi'))

        inc = ftdi_bus.incoming_fifo
        out = ftdi_bus.output_fifo
        counter = Signal(8)
        self.sync.sys += If(out.writable, counter.eq(counter + 1))
        self.comb += [
            out.din.eq(counter),
            out.we.eq(out.writable),
            # Discard any data written by host
            inc.re.eq(inc.readable),
        ]

        leds = plat.request("leds")
        self.comb += leds.eq(~Cat(ftdi_bus.rx_ind, ftdi_bus.tx_ind, Constant(0, 1)))
