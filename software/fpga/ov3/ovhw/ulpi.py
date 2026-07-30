from migen import *
from migen.fhdl import verilog
#from migen.sim.generic import Simulator, TopLevel
from migen.genlib.fsm import FSM, NextState
from migen.genlib.misc import WaitTimer
from migen.genlib.record import *
from misoc.interconnect.stream import Endpoint

from ovhw.constants import *
from ovhw.ov_types import ULPI_DATA_D

ULPI_BUS = [
    ("rst", 1, DIR_M_TO_S),
    ("nxt", 1, DIR_S_TO_M),
    ("dir", 1, DIR_S_TO_M),
    ("stp", 1, DIR_M_TO_S),
    ("do", 8, DIR_M_TO_S),
    ("di", 8, DIR_S_TO_M),
    ("doe", 1, DIR_M_TO_S)
]

ULPI_REG = [
    ("waddr", 6, DIR_M_TO_S),
    ("raddr", 6, DIR_M_TO_S),
    ("wdata", 8, DIR_M_TO_S),
    ("rdata", 8, DIR_S_TO_M),
    ("wreq", 1, DIR_M_TO_S),
    ("wack", 1, DIR_S_TO_M),
    ("rreq", 1, DIR_M_TO_S),
    ("rack", 1, DIR_S_TO_M)
]

# The timeout value is taken from UTMI+ Low Pin Interface Specification,
# Revision 1.1 Table 10 – Link decision times. It might be too high for
# use in passive hardware sniffer but the error is on the wait-too-long
# rather than wait-too-little.
ULPI_LS_LINK_DECISION_TIMEOUT = 718


def pid_compare(first_byte, pid):
    return first_byte == (pid | ((~pid & 0xF) << 4))


class ULPI_pl(Module):
    """
    ULPI Physical layer interface. Connects internal unidirectional buses to
    bidirectional ULPI interface. Instantiated as a separate module to allow
    simulation testing of unidirectional controller
    """
    def __init__(self, stp_ovr=0):
        self.ulpi_bus = ulpi_bus = Record(ULPI_BUS)

        # SoC should connect all outputs and inputs using combinational logic,
        # i.e. without registering.

        # SoC must instantiate a vendor-specific tri-state buffer for data.
        # When d_oe = 1, d_o drives ULPI data bus.
        # When d_oe = 0, d_i samples ULPI data bus.
        self.d_oe = Signal()

        # Controller outputs (controller -> SoC -> ULPI PHY)
        self.d_o = Signal(8)     # Data to drive on bidirectional bus
        self.rst = Signal()      # ULPI RST# (active-low)
        self.stp = Signal()

        # Controller inputs (ULPI PHY -> SoC -> controller)
        self.d_i = Signal(8)     # Data read from the bus
        self.nxt = Signal()
        self.dir = Signal()

        self.comb += [
            self.rst.eq(~ulpi_bus.rst),
            self.d_o.eq(ulpi_bus.do),
            self.d_oe.eq(ulpi_bus.doe),
            self.stp.eq(ulpi_bus.stp | stp_ovr),
            ulpi_bus.nxt.eq(self.nxt),
            ulpi_bus.dir.eq(self.dir),
            ulpi_bus.di.eq(self.d_i),
        ]


class ULPI_ctrl(Module):
    def __init__(self, ulpi_bus, ulpi_reg, handle_fs_pre):

        ulpi_data_out = Signal(8)
        ulpi_data_tristate = Signal()

        ulpi_data_next = Signal(8)
        ulpi_data_tristate_next = Signal()
        ulpi_stp_next = Signal()

        reg_write_addr = Signal(8)
        reg_write_data = Signal(8)

        xcvr_select = Signal(2, reset=1)

        # Packet tracking needed for Full-Speed PRE handling
        fs_pre_en = Signal()
        internal_reg_write = Signal()
        first_byte_received = Signal()
        first_byte = Signal(8)
        switch_to_low_speed = Signal()
        switch_to_full_speed = Signal()
        ls_packet_on_fs_link = Signal()
        wait_for_ls_response = Signal()
        ls_response_timeout = ClockDomainsRenamer("ulpi")(
            WaitTimer(ULPI_LS_LINK_DECISION_TIMEOUT))
        self.comb += ls_response_timeout.wait.eq(wait_for_ls_response)
        self.submodules += ls_response_timeout
        self.sync.ulpi += fs_pre_en.eq(handle_fs_pre & xcvr_select[0])

        ulpi_state_rx = Signal()
        ulpi_state_rrd = Signal()

        self.data_out_source = Endpoint(ULPI_DATA_D)

        RegWriteReqR = Signal()
        RegReadReqR = Signal()
        RegWriteReq = Signal()
        RegReadReq = Signal()
        RegReadAckSet = Signal()
        RegWriteAckSet = Signal()

        # register the reg read/write requests
        self.sync.ulpi += RegReadReqR.eq(ulpi_reg.rreq)
        self.sync.ulpi += RegWriteReqR.eq(ulpi_reg.wreq)

        # signal when read/write is requested but not done
        self.comb += RegReadReq.eq(RegReadReqR & ~ulpi_reg.rack)
        v = (RegReadReqR & ~ulpi_reg.rack)
        self.comb += RegWriteReq.eq(RegWriteReqR & ~ulpi_reg.wack)

        # ack logic: set ack=0 when req=0, set ack=1 when access done
        self.sync.ulpi += If(~RegReadReqR, ulpi_reg.rack.eq(0)
            ).Elif(RegReadAckSet, ulpi_reg.rack.eq(1))
        self.sync.ulpi += If(~RegWriteReqR, ulpi_reg.wack.eq(0)
            ).Elif(RegWriteAckSet, ulpi_reg.wack.eq(1))

        # output data if required by state
        self.comb += ulpi_bus.stp.eq(ulpi_stp_next)
        self.comb += ulpi_data_out.eq(ulpi_data_next)
        self.comb += ulpi_data_tristate.eq(ulpi_data_tristate_next)
        self.comb += ulpi_bus.do.eq(ulpi_data_out)
        self.comb += ulpi_bus.doe.eq(~ulpi_data_tristate)

        # capture RX data at the end of RX, but only if no turnaround was requested
        # We also support "stuffing" data, to indicate conditions such as:
        #  - Simultaneous DIR + NXT assertion
        #    (the spec doesn't require an RXCMD - DIR+NXT asserting may be the'
        #    only SOP signal)
        #  - End-of-packet
        #    (Packets may end without an RXCMD, unless an error occurs)
        ulpi_rx_stuff   = Signal()
        ulpi_rx_stuff_d = Signal(8)

        self.sync.ulpi += self.data_out_source.stb.eq(1)
        self.sync.ulpi += self.data_out_source.payload.speed.eq(xcvr_select)
        self.sync.ulpi += [
            If(ulpi_rx_stuff,
                self.data_out_source.payload.d.eq(ulpi_rx_stuff_d),
                self.data_out_source.payload.rxcmd.eq(1)
            ).Elif(ulpi_state_rx & ulpi_bus.dir,
                If(~ulpi_bus.nxt,
                    self.data_out_source.payload.d.eq(ulpi_bus.di & RXCMD_MASK),
                    self.data_out_source.payload.rxcmd.eq(1)
                ).Else(
                    self.data_out_source.payload.d.eq(ulpi_bus.di),
                    self.data_out_source.payload.rxcmd.eq(0)
                )
            ).Else(
                self.data_out_source.payload.d.eq(RXCMD_MAGIC_NOP),
                self.data_out_source.payload.rxcmd.eq(1)
            )
        ]

        self.sync.ulpi += If (~fs_pre_en,
            # User disabled automatic FS PRE handling. Do not switch to FS
            # even if we are currently automatically switched to LS to avoid
            # potential conflicts over configured speed.
            switch_to_low_speed.eq(0),
            switch_to_full_speed.eq(0),
            ls_packet_on_fs_link.eq(0),
        )

        regwrite_pending = Signal()
        regwrite_request = Signal()
        reg_write_addr_next = Signal(8)
        reg_write_data_next = Signal(8)
        internal_reg_write_next = Signal()
        self.comb += [
            If(regwrite_pending,
                # Keep holding the request accepted by FSM
                reg_write_addr_next.eq(reg_write_addr),
                reg_write_data_next.eq(reg_write_data),
                regwrite_request.eq(1),
                internal_reg_write_next.eq(internal_reg_write),
            ).Elif(fs_pre_en & switch_to_low_speed,
                reg_write_addr_next.eq(0x84), # REGW FUNC_CTL
                reg_write_data_next.eq(0x6b), # FS-for-LS, reset transceiver
                regwrite_request.eq(1),
                internal_reg_write_next.eq(1),
            ).Elif(fs_pre_en & (switch_to_full_speed | ls_response_timeout.done),
                reg_write_addr_next.eq(0x84), # REGW FUNC_CTL
                reg_write_data_next.eq(0x69), # FS, reset transceiver
                regwrite_request.eq(1),
                internal_reg_write_next.eq(1),
            ).Elif(RegWriteReq,
                reg_write_addr_next.eq(0x80 | ulpi_reg.waddr), # REGW
                reg_write_data_next.eq(ulpi_reg.wdata),
                regwrite_request.eq(1),
                internal_reg_write_next.eq(0),
            ).Else(
                regwrite_request.eq(0),
            )
        ]

        # Keep updating requested write until FSM locks in the request
        self.sync.ulpi += If (~regwrite_pending,
            reg_write_addr.eq(reg_write_addr_next),
            reg_write_data.eq(reg_write_data_next),
            internal_reg_write.eq(internal_reg_write_next),
        )

        # capture register reads at the end of RRD
        self.sync.ulpi += If(ulpi_state_rrd,ulpi_reg.rdata.eq(ulpi_bus.di))

        fsm = ClockDomainsRenamer("ulpi")(FSM())
        self.submodules += fsm

        fsm.act("IDLE",
            ulpi_data_next.eq(0x00), # NOOP
            ulpi_data_tristate_next.eq(0),
            ulpi_stp_next.eq(0),
            If(~ulpi_bus.dir & ~ulpi_bus.nxt & ~(switch_to_low_speed | switch_to_full_speed | ls_response_timeout.done | RegWriteReq | RegReadReq),
                NextState("IDLE")
            ).Elif(ulpi_bus.dir, # TA, and then either RXCMD or Data
                NextState("RX"),
                NextValue(first_byte_received, 0),
                ulpi_data_tristate_next.eq(1),
                # If dir & nxt, we're starting a packet, so stuff a custom SOP
                If(ulpi_bus.nxt,
                    ulpi_rx_stuff.eq(1),
                    ulpi_rx_stuff_d.eq(RXCMD_MAGIC_SOP)
                )
            ).Elif(regwrite_request,
                NextState("RW0"),
                NextValue(regwrite_pending, 1),
                ulpi_data_next.eq(reg_write_addr_next),
            ).Elif(RegReadReq,
                NextState("RR0"),
                ulpi_data_next.eq(0xC0 | ulpi_reg.raddr), # REGR
                ulpi_data_tristate_next.eq(0),
                ulpi_stp_next.eq(0)
            ).Else(
                NextState("ERROR")
            ),
        )

        fsm.act("RX",
            If(ulpi_bus.dir, # stay in RX
                NextState("RX"),
                ulpi_state_rx.eq(1),
                ulpi_data_tristate_next.eq(1),
                If(ulpi_bus.nxt & ~first_byte_received,
                    NextValue(first_byte_received, 1),
                    NextValue(first_byte, ulpi_bus.di),
                    If(fs_pre_en & pid_compare(ulpi_bus.di, PID_PRE_ERR),
                        # Request stop on PRE packet ID
                        ulpi_stp_next.eq(1),
                        NextValue(switch_to_low_speed, 1),
                        NextValue(wait_for_ls_response, 0),
                    )
                )
            ).Else( # TA back to idle
                # Stuff an EOP on return to idle
                ulpi_rx_stuff.eq(1),
                ulpi_rx_stuff_d.eq(RXCMD_MAGIC_EOP),
                ulpi_data_tristate_next.eq(0),
                If(fs_pre_en & ls_packet_on_fs_link & first_byte_received,
                    If(wait_for_ls_response,
                        # We have just received response from device. Switch
                        # to full speed because host always sends PRE before
                        # next low speed packet
                        NextValue(switch_to_full_speed, 1),
                        NextValue(wait_for_ls_response, 0),
                    ).Elif(pid_compare(first_byte, PID_DATA0) |
                           pid_compare(first_byte, PID_IN) |
                           pid_compare(first_byte, PID_DATA1),
                        # Host expects handshake from device. Note that there
                        # are no isochronous transfers at low speed so there
                        # always is handshake expected after DATA0/DATA1.
                        # If data is from device, host will send handshake with
                        # its own PRE (wait_for_ls_response will be set though
                        # so this elif branch won't be taken then).
                        # LPM SubPID is indirectly handled here because it
                        # shares PID with DATA0 and EXT PID is always sent with
                        # its own PRE.
                        NextValue(wait_for_ls_response, 1),
                    ).Else(
                        # Host either sent handshake or will send next packet
                        NextValue(switch_to_full_speed, 1),
                    )
                ),
                NextState("IDLE")
            ),
        )

        fsm.act("RW0",
            If(ulpi_bus.dir,
                NextState("RX"),
                ulpi_data_tristate_next.eq(1),
            ).Elif(~ulpi_bus.dir,
                ulpi_data_next.eq(reg_write_addr), # REGW
                ulpi_data_tristate_next.eq(0),
                ulpi_stp_next.eq(0),
                If(ulpi_bus.nxt, NextState("RWD")).Else(NextState("RW0")),
            ).Else(
                NextState("ERROR")
            ),
        )

        fsm.act("RWD",
            If(ulpi_bus.dir,
                NextState("RX"),
                ulpi_data_tristate_next.eq(1),
            ).Elif(~ulpi_bus.dir,
                ulpi_data_tristate_next.eq(0),
                ulpi_stp_next.eq(0),
                If(ulpi_bus.nxt,
                    # Write is finished at end of this cycle, STP happens
                    # unconditionally at next cycle. Even if PHY asserts
                    # dir next cycle it does not abort the write.
                    NextState("RWS"),
                    ulpi_data_next.eq(reg_write_data),
                    # Update transceiver speed on function control register change
                    If(reg_write_addr == 0x84,
                        NextValue(xcvr_select, reg_write_data[0:2])
                    ).Elif(reg_write_addr == 0x85,
                        NextValue(xcvr_select, xcvr_select | reg_write_data[0:2])
                    ).Elif(reg_write_addr == 0x86,
                        NextValue(xcvr_select, xcvr_select & ~reg_write_data[0:2])
                    ),
                ).Else(
                    # Keep holding data on the bus until nxt asserts again
                    NextState("RWD"),
                    ulpi_data_next.eq(reg_write_data),
                ),
            ).Else(
                NextState("ERROR")
            ),
        )

        fsm.act("RWS",
            # STP is asserted in this cycle because register write is completed.
            ulpi_stp_next.eq(1),
            NextValue(regwrite_pending, 0),
            If(internal_reg_write,
                NextValue(internal_reg_write, 0),
                NextValue(ls_packet_on_fs_link, switch_to_low_speed),
                NextValue(switch_to_low_speed, 0),
                NextValue(switch_to_full_speed, 0),
                NextValue(wait_for_ls_response, 0),
            ).Else(
                RegWriteAckSet.eq(1),
            ),
            If(~ulpi_bus.dir,
                NextState("IDLE"),
                ulpi_data_next.eq(0x00), # NOOP
                ulpi_data_tristate_next.eq(0),
            ).Else(
                NextState("RX"),
                ulpi_data_tristate_next.eq(1),
            ),
        )

        fsm.act("RR0",
            If(ulpi_bus.dir,
                ulpi_data_tristate_next.eq(1), # TA
                NextState("RX"),
            ).Elif(~ulpi_bus.dir,
                ulpi_data_next.eq(0xC0 | ulpi_reg.raddr),
                If(ulpi_bus.nxt,
                    # PHY accepts RegRead command
                    NextState("RR1")
                ).Else(
                    # Keep holding RegRead command
                    NextState("RR0")
                ),
            ).Else(
                NextState("ERROR")
            ),
        )

        fsm.act("RR1",
            ulpi_data_tristate_next.eq(1),
            If(~ulpi_bus.nxt, # REGR continue
                NextState("RRD")
            ).Elif(ulpi_bus.dir, # PHY indicates RX
                NextState("RX"),
            ).Else(
                NextState("ERROR")
            ),
        )

        fsm.act("RRD",
            If(ulpi_bus.dir & ~ulpi_bus.nxt,
                NextState("RX"),
                RegReadAckSet.eq(1),
                ulpi_state_rrd.eq(1),
            ).Elif(ulpi_bus.dir & ulpi_bus.nxt,
                NextState("RX"),
            ).Else(
                NextState("ERROR")
            ),
            ulpi_data_tristate_next.eq(1),
        )

        fsm.act("ERROR", NextState("IDLE"))
