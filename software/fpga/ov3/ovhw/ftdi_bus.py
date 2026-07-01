from migen import *
from migen.genlib.cdc import MultiReg
from migen.genlib.fsm import *
from migen.genlib.fifo import *

class FTDI_sync245(Module):
    def __init__(self):
        # FTDI controller uses unidirectional logical interface that allows
        # simulation testing with Migen simulator.

        # SoC must register d_oe, d_o, rd_n, oe_n and wr_n in the FTDI clock
        # domain. All other signals (siwua_n output and all inputs) should be
        # connected using combinational logic, i.e. without registering.

        # SoC must instantiate a vendor-specific tri-state buffer for data.
        # When d_oe = 1, d_o drives FTDI data bus.
        # When d_oe = 0, d_i samples FTDI data bus.
        self.d_oe = Signal(reset=0)

        # Controller outputs (controller -> SoC -> FTDI)
        self.d_o = Signal(8)           # Data to drive on bidirectional bus
        self.rd_n = Signal(reset=1)    # RD#
        self.oe_n = Signal(reset=1)    # OE#
        self.wr_n = Signal(reset=1)    # WR#
        self.siwua_n = Signal(reset=1)

        # Controller inputs (FTDI -> SoC -> controller)
        self.d_i = Signal(8)           # Data read from the bus
        self.rxf_n = Signal(reset=1)   # RXF#
        self.txe_n = Signal(reset=1)   # TXE#


        # Input FIFO for reads from FT245
        self.incoming_fifo = incoming_fifo = AsyncFIFO(8, 64)
        self.submodules.incoming = ClockDomainsRenamer(
            {"write":"ftdi", "read":"sys"})(incoming_fifo)

        # Output FIFO
        self.output_fifo = output_fifo = AsyncFIFO(8, 64)
        self.submodules.outgoing = ClockDomainsRenamer(
            {"write":"sys", "read":"ftdi"})(output_fifo)

        self.comb += self.siwua_n.eq(1)

        next_RD = Signal(reset=0)
        next_OE = Signal(reset=0)
        next_dOE = Signal(reset=0)

        # Sample FT245 inputs on FTDI clock rising edge
        din_r = Signal(8)
        rxf_r = Signal(reset=1)
        txe_r = Signal(reset=1)
        self.sync.ftdi += [
            din_r.eq(self.d_i),
            rxf_r.eq(self.rxf_n),
            txe_r.eq(self.txe_n),
        ]

        # Combinatorial bus controls SoC registers in FTDI clock domain.
        # WR# and the write data come from the write datapath below.
        self.comb += [
            self.rd_n.eq(~next_RD | rxf_r),
            self.oe_n.eq(~next_OE),
            self.d_oe.eq(next_dOE),
        ]

        # Delayed copies for qualifying logic
        # SoC may register rd_n/oe_n in a way that does not allow routing back
        # the registered outputs to fabric logic, so we keep our own registered
        # copies in rd_n_r/oe_n_r.
        d_o_r = Signal(8)
        wr_n_r = Signal(reset=1)
        rd_n_r = Signal(reset=1)
        rd_n_d = Signal(reset=1)
        oe_n_r = Signal(reset=1)
        oe_n_d = Signal(reset=1)
        self.sync.ftdi += [
            d_o_r.eq(self.d_o),
            wr_n_r.eq(self.wr_n),
            rd_n_r.eq(self.rd_n),
            rd_n_d.eq(rd_n_r),
            oe_n_r.eq(self.oe_n),
            oe_n_d.eq(oe_n_r),
        ]

        # Captured data (din_r) is valid on cycle where FT245 was driving data
        # bus (OE# low), FT245 had data available (RXF# low) and controller
        # accepted it (RD# low).
        rx_valid = Signal()
        self.comb += rx_valid.eq(~oe_n_d & ~rd_n_d & ~rxf_r)

        # AsyncFIFO only reports when it is already full (writable equal 0), but
        # by the time we know that incoming_fifo is full, we may have already
        # committed to up to 2 more bytes (rd_n -> rd_n_r -> rd_n_d).
        # Use rx_skid buffer to absorb the data on incoming_fifo backpressure.
        RX_SKID_DEPTH = 4
        RX_GUARD = 2
        self.submodules.rx_skid = rx_skid = ClockDomainsRenamer("ftdi")(
            SyncFIFO(8, RX_SKID_DEPTH))
        skid_room = Signal()
        self.comb += [
            skid_room.eq(rx_skid.level < (RX_SKID_DEPTH - RX_GUARD)),
            rx_skid.din.eq(din_r),
            rx_skid.we.eq(rx_valid & rx_skid.writable),
            incoming_fifo.din.eq(rx_skid.dout),
            incoming_fifo.we.eq(rx_skid.readable & incoming_fifo.writable),
            rx_skid.re.eq(rx_skid.readable & incoming_fifo.writable),
        ]

        # FTDI accepts data when both WR# and TXE# are low.
        tx_taken = Signal()
        # When write burst starts, tx_outstanding goes high on first byte read
        # from output_fifo and remains high for one cycle after the last byte
        # is transmitted.
        # State machine can go to READ with tx_outstanding high if TXE# was high
        # (FTDI was unable to accept more data). In such case, the data remains
        # latched in d_o_r so it can be re-presented on next WRITE state entry.
        # On the cycle when tx_taken is high, tx_outstanding should be ignored
        # (there is inherent one cycle delay for when tx_outstanding goes low).
        tx_outstanding = Signal()
        # When the data presented to FTDI is not accepted (FTDI transmit buffer
        # full, TXE# high), tx_stalled goes high. It remains high until the data
        # is accepted by FTDI.
        tx_stalled = Signal()
        self.comb += [
            tx_taken.eq(~wr_n_r & ~self.txe_n),
            tx_stalled.eq(tx_outstanding & ~tx_taken),
            # By default, we do not have data available for FTDI to accept
            self.wr_n.eq(1),
        ]
        self.sync.ftdi += [
            If(output_fifo.re,
                tx_outstanding.eq(1),
            ).Elif(tx_taken,
                tx_outstanding.eq(0),
            )
        ]

        # Indicates that data is available for FTDI to pick up. Note that it is
        # FSM that decides when the data is actually driven on the bus. Here it
        # is determined that data is ready. Note that d_o_r is effectively used
        # as one extra output buffer byte.
        tx_ready = Signal()
        self.comb += [
            If(tx_taken | ~tx_outstanding,
                # FTDI just accepted the byte or there is no outstanding byte.
                # Present next byte, if any.
                If(output_fifo.readable,
                    self.d_o.eq(output_fifo.dout),
                    output_fifo.re.eq(1),
                    tx_ready.eq(1),
                ).Else(
                    # Keep holding previously presented data.
                    self.d_o.eq(d_o_r),
                    tx_ready.eq(0),
                )
            ).Else(
                # Keep holding outstanding byte until it is picked up.
                self.d_o.eq(d_o_r),
                tx_ready.eq(tx_outstanding),
            ),
        ]

        # WRITE state can be entered if TXE# is low and there is data to send.
        # READ state can be entered if RXF# is low and skid buffer has room.
        can_write = Signal()
        can_read = Signal()
        self.comb += [
            can_write.eq(~txe_r & tx_ready),
            can_read.eq(skid_room & ~rxf_r),
        ]

        bsf = FSM()

        bsf.act('IDLE_W',
            # Bus turnaround (OE# high, SoC tristate not driving). Prefer read.
            If(can_read,
                next_OE.eq(1),
                NextState('READ'),
            ).Elif(can_write,
                # Enable tristate output and write data if ready.
                next_dOE.eq(1),
                self.wr_n.eq(~tx_ready),
                NextState('WRITE'),
            )
        )

        bsf.act('IDLE_R',
            # Bus turnaround (OE# high, SoC tristate not driving). Prefer write.
            If(can_write,
                # Enable tristate output and write data if ready.
                next_dOE.eq(1),
                self.wr_n.eq(~tx_ready),
                NextState('WRITE'),
            ).Elif(can_read,
                next_OE.eq(1),
                NextState('READ'),
            )
        )

        bsf.act('READ',
            # Perform bus turnaround only if skid buffer cannot accept more data
            # and there is write pending. If there is no write pending, just
            # keep waiting here to allow resuming read without turnaround.
            If(~can_read & can_write,
                next_OE.eq(0),
                NextState('IDLE_R'),
            ).Else(
                next_OE.eq(1),
                next_RD.eq(can_read),
            )
        )

        bsf.act('WRITE',
            # Perform bus turnaround if there is any data available for reading
            # and we either don't have anything to send or FTDI buffer is full.
            # If there is nothing to read and nothing to send, just keep owning
            # the bus to allow resuming write without turnaround cycles.
            If(can_read & (tx_stalled | ~tx_ready),
                next_dOE.eq(0),
                NextState('IDLE_W'),
            ).Else(
                # Drive the data bus, drive WR# low when new byte is ready.
                next_dOE.eq(1),
                self.wr_n.eq(~tx_ready),
            )
        )

        bsf.finalize()
        bsf.state.reset = bsf.encoding['IDLE_W']

        self.submodules.bsf = ClockDomainsRenamer({"sys": "ftdi"})(bsf)


        # LED Indicators for RX and TX
        self.tx_ind = Signal()
        self.rx_ind = Signal()

        self.specials += MultiReg(~self.wr_n, self.tx_ind)
        self.specials += MultiReg(~self.rd_n, self.rx_ind)
