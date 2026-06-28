# Copyright (c) 2026 Tomasz Moń
# SPDX-License-Identifier: BSD-3-Clause

"""Behavioural model of an FT2232H channel A in FT245 synchronous FIFO mode.

USB side of chip is not modeled. There is simple interface to provide RX data
and to accept specified number of TX bytes. This simple interface allows writing
test scenarios that excersise the controller behavior under corner conditions.

Model does verify that there are no conflicts on the bidirectional data bus.
Test is responsible for getting the full controller coverage, because model will
raise exception after bad state is actually entered. The goal is to not have
bad states in the controller, which can only be confirmed if all possible paths
are excersised during test.
"""

from migen import *
from migen.genlib.record import Record, DIR_M_TO_S, DIR_S_TO_M
from migen.sim import passive

FT245_MODEL = [
     # Migen sim does not support bidirectional IO so we use ext_drives_data,
     # data_ext and data_ftdi instead of a bidirectional data.
     ("ext_drives_data", 1, DIR_S_TO_M),
     ("data_ext", 8, DIR_S_TO_M),
     ("data_ftdi", 8, DIR_M_TO_S),
     ("rxf_n", 1, DIR_M_TO_S),
     ("txe_n", 1, DIR_M_TO_S),
     ("rd_n", 1, DIR_S_TO_M),
     ("wr_n", 1, DIR_S_TO_M),
     ("oe_n", 1, DIR_S_TO_M),
     ("siwu_n", 1, DIR_S_TO_M),
]

FTDI_BUS_UNKNOWN = 0xAA

class FT245SyncModel(Module):
    def __init__(self):
        self.io = Record(FT245_MODEL)
        self.rx_data = bytearray()
        self.tx_data = bytearray()
        self.allowed_tx = 0
        self.rx_ptr = 0

    def append_rx(self, data):
        self.rx_data.extend(data)

    @property
    def unread_rx_bytes(self):
        return len(self.rx_data) - self.rx_ptr

    @property
    def available_tx_space(self):
        return self.allowed_tx - len(self.tx_data)

    def accept_tx(self, num_bytes):
        # This is not how the chip works, but implementing the latency timer,
        # endpoint buffers and internal TxFIFO is not practical for simulation.
        # We just maintain a simple function that increases total number of
        # bytes the model can receive.
        assert int(num_bytes) >= 0
        self.allowed_tx = self.allowed_tx + int(num_bytes)

    @passive
    def run(self):
        while True:
            outputs_rx_data = self.rx_ptr < len(self.rx_data)
            accepts_tx_data = len(self.tx_data) < self.allowed_tx

            ftdi_owns_data_bus = (yield self.io.oe_n) == 0
            ext_drives_data = (yield self.io.ext_drives_data)

            yield self.io.txe_n.eq(0 if accepts_tx_data else 1)
            yield self.io.rxf_n.eq(0 if outputs_rx_data else 1)
            if ftdi_owns_data_bus and outputs_rx_data:
                yield self.io.data_ftdi.eq(self.rx_data[self.rx_ptr])
            else:
                yield self.io.data_ftdi.eq(FTDI_BUS_UNKNOWN)

            if ftdi_owns_data_bus and ext_drives_data:
                # Both sides driving tristate at the same cycle can damage real
                # hardware. Definitely forbidden state.
                raise AssertionError("Data tristate conflict")

            yield

            ftdi_owns_data_bus_after_clk = (yield self.io.oe_n) == 0
            ext_drives_data_after_clk = (yield self.io.ext_drives_data)

            # Both FTDI and external device take some time before its tristate
            # driver gets disabled. To avoid transient conflicts, ensure that
            # on bus ownership change cycle, neither side drives the bus.
            if ftdi_owns_data_bus == ftdi_owns_data_bus_after_clk:
                # Tristate conflict check above is sufficient
                pass
            elif not ftdi_owns_data_bus_after_clk:
                # Transition cycle: FTDI owned data bus, but no longer does
                # External device should wait one cycle before enabling outputs
                if ext_drives_data_after_clk:
                    raise AssertionError("Missing Hi-Z cycle on READ->WRITE")
            else:
                # Transition cycle: FTDI didn't own data bus, but now does
                # External device should have disabled outputs in previous cycle
                if ext_drives_data:
                    raise AssertionError("Missing Hi-Z cycle on WRITE->READ")

            if (yield self.io.rd_n) == 0:
                if not ftdi_owns_data_bus:
                    raise AssertionError("RD# was low when OE# was high")
                # External device acknowledged data
                if self.rx_ptr < len(self.rx_data):
                   self.rx_ptr = self.rx_ptr + 1

            if (yield self.io.wr_n) == 0:
                tx_byte = (yield self.io.data_ext)
                if ftdi_owns_data_bus:
                    raise AssertionError("WR# was low when OE# was low")
                if not ext_drives_data_after_clk:
                    raise AssertionError("WR# was low but bus was not driven")
                if accepts_tx_data:
                    self.tx_data.append(tx_byte)
