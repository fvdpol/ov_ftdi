from migen import *
from migen.genlib.cdc import MultiReg
from migen.genlib.fsm import *
from migen.genlib.fifo import *

class FTDI_sync245(Module):
    def __init__(self):
        # FTDI controller uses unidirectional logical interface that allows
        # simulation testing with Migen simulator.

        # SoC should connect all outputs and inputs using combinational logic,
        # i.e. without registering.

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
        next_WR = Signal(reset=0)
        next_OE = Signal(reset=0)
        next_dOE = Signal(reset=0)

        # Use registers for all IOs to help timing
        self.sync.ftdi += [
            self.rd_n.eq(~next_RD | self.rxf_n),
            self.oe_n.eq(~next_OE),
            self.d_oe.eq(next_dOE),
            ]



        bsf = FSM()

        can_write = Signal()

        # Try a write whenever we have data in the fifo
        self.comb += can_write.eq(~self.txe_n & output_fifo.readable)

        # Try a read whenever we have data in the FTDI fifo and nothing in the IC fifo
        can_read = Signal()
        self.comb += [
                can_read.eq(~self.rxf_n & incoming_fifo.writable),
                incoming_fifo.din.eq(self.d_i),
                self.d_o.eq(output_fifo.dout)]

        bsf.act('IDLE',
            # Reads from FTDI take priority over writes
            # Host must throttle reads to prevent overusage of bus BW
            If(can_read, NextState('READ'),
                next_OE.eq(1))
            .Elif(can_write,
                NextState('I2W'),
                next_OE.eq(0)
            ))

        bsf.act('I2W',
            If(~can_write,
                NextState('IDLE'),
                next_dOE.eq(0)
            ).Else(
                next_WR.eq(1),
                next_dOE.eq(1),

                output_fifo.re.eq(0),
                NextState('WRITE')
            )

        )

        bsf.act('WRITE',
                If(~can_write,
                    NextState('W2I'),
                    self.wr_n.eq(1),
                    next_dOE.eq(0),
                    output_fifo.re.eq(0)
                ).Else(
                    self.wr_n.eq(0),
                    next_dOE.eq(1),
                    output_fifo.re.eq(1),
                    next_WR.eq(1),
                    ))

        bsf.act('W2I',
                NextState('IDLE'),
                next_OE.eq(1))

        # Shitty read SM to avoid proper handshaking
        # TODO: fixup to provide higher read speads
        # Shouldn't matter timing-wise
        bsf.act('READ',
                If(can_read,
                    next_RD.eq(1),
                    next_OE.eq(1),
                    NextState('READ2')).Else(NextState('IDLE'), next_OE.eq(0))
                )
        bsf.act('READ2',
                incoming_fifo.we.eq(1),
                next_RD.eq(0),
                next_OE.eq(0),
                NextState('IDLE')
                )

        bsf.finalize()
        bsf.state.reset = bsf.encoding['IDLE']


        self.submodules.bsf = ClockDomainsRenamer({"sys": "ftdi"})(bsf)


        # LED Indicators for RX and TX
        self.tx_ind = Signal()
        self.rx_ind = Signal()

        self.specials += MultiReg(~self.wr_n, self.tx_ind)
        self.specials += MultiReg(~self.rd_n, self.rx_ind)
