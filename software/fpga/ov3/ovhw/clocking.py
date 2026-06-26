from migen import *

class ClockGen(Module):
    def __init__(self, platform):
        clkin = platform.request("clk12") # 12mhz reference clock from which all else is derived

        self.clk_sys = Signal()
        self.clk_sdram = Signal()
        self.clk_sdram_sample = Signal()
        self.cd_sys = ClockDomain()
        self.pll_locked = Signal()

        clkout0, clkout2 = Signal(), Signal()
        dcm_locked = Signal()
        clk2x = Signal()   # raw DCM CLK2X output (drives the PLL directly)
        clkfb = Signal()   # CLK2X buffered through a BUFG, fed back to CLKFB

        feedback = Signal()
        # Simple 2X: 12MHz -> 24MHz
        #
        # Feedback is buffered to match UG382 Spartan-6 FPGA Clocking Resources
        # Figure 3-15: DCM Driving a PLL. We do use CLK2X instead of CLK0 as
        # feedback in order to meet minimum PLL frequency requirement.
        # All BUFGs are in the central CLKC tile (they are global, region-less),
        # so the loop runs DCM(bottom) -> BUFG(center) -> global GCLK spine ->
        # DCM.CLKFB; the DLL compensates the whole loop delay.
        #
        # Input chain: P50(clk12) -> IBUFG -> BUFIO2 -> DCM.CLKIN.
        # IBUFG + BUFIO2 are made explicit only so the BUFIO2 can be LOC'd
        clkin_g = Signal()
        clkin_b = Signal()
        self.specials += Instance("IBUFG", i_I=clkin, o_O=clkin_g)
        self.specials.bufio2 = Instance("BUFIO2",
            i_I=clkin_g, o_DIVCLK=clkin_b,
            p_DIVIDE=1, p_DIVIDE_BYPASS="TRUE",
            p_I_INVERT="FALSE", p_USE_DOUBLER="FALSE")
        self.specials.dcm = Instance("DCM_SP",
            i_CLKIN=clkin_b, i_CLKFB=clkfb, i_RST=0, i_PSEN=0,
            o_CLK2X=clk2x, o_LOCKED=dcm_locked,
            p_CLK_FEEDBACK="2X")
        self.specials += Instance("BUFG", i_I=clk2x, o_O=clkfb)

        # VCO 400.1000MHz
        # PFD 19..400MHz
        # 24MHz in, /1 24MHz PFD, x25 600MHz VCO, /6 100MHz CLKOUT
        self.specials.pll = Instance("PLL_BASE",
            i_CLKIN=clk2x, i_CLKFBIN=feedback, i_RST=~dcm_locked,
            o_CLKFBOUT=feedback, o_CLKOUT0=clkout0, o_CLKOUT1=self.clk_sdram,
            o_CLKOUT2=clkout2, o_LOCKED = self.pll_locked,
            p_BANDWIDTH="LOW",
            p_COMPENSATION="DCM2PLL", p_CLK_FEEDBACK="CLKFBOUT",
            p_DIVCLK_DIVIDE=1, p_CLKFBOUT_MULT=25,
            p_CLKOUT0_DIVIDE=6, p_CLKOUT0_PHASE=0.0,
            p_CLKOUT1_DIVIDE=6, p_CLKOUT1_PHASE=180.0,
            p_CLKOUT2_DIVIDE=6, p_CLKOUT2_PHASE=180.0,
            p_CLKOUT3_DIVIDE=18, p_CLKOUT3_PHASE=0.0,
        )

        # Pin the whole clock chain into clk12's clock region (X0Y0) so the
        # pin -> buffer -> DCM path is region-coherent:
        #   P50 (region X0Y0)
        #     -> BUFIO2_X1Y1   (region X0Y0)
        #     -> DCM_X0Y0      (region X0Y0)
        #     -> PLL_ADV_X0Y0  (region X0Y1; the bottom CMT's PLL and the only
        #                       PLL anywhere near the bottom-edge clk12 pin).
        # DCM_X0Y0 and PLL_ADV_X0Y0 are in the same (bottom) CMT, so the
        # dedicated in-tile DCM->PLL route required by COMPENSATION=DCM2PLL is
        # used; the DCM->PLL region boundary is crossed only on that hard route.
        platform.add_platform_command("""
INST "{dcm}" LOC = "DCM_X0Y0";
INST "{pll}" LOC = "PLL_ADV_X0Y0";
INST "{bufio2}" LOC = "BUFIO2_X1Y1";
""", dcm=self.dcm, pll=self.pll, bufio2=self.bufio2)

        self.specials += [
            Instance("BUFG", i_I=clkout0, o_O=self.clk_sys),
            Instance("BUFG", i_I=clkout2, o_O=self.clk_sdram_sample),
        ]

        # Reset generator: 4 cycles in reset after PLL is locked
        rst_ctr = Signal(max=4)
        self.clock_domains.cd_rst = ClockDomain()
        self.cd_sys.rst.reset = 1
        self.sync.rst += If(rst_ctr == 3,
                            self.cd_sys.rst.eq(0)
                         ).Else(
                            rst_ctr.eq(rst_ctr+1)
                         )
        self.comb += [
            self.cd_rst.clk.eq(self.clk_sys),
            self.cd_rst.rst.eq(~self.pll_locked),
            self.cd_sys.clk.eq(self.clk_sys),
        ]
