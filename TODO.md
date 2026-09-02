# TODO

Pending cleanup and follow-up items. Add new entries under the relevant heading;
check them off (`[x]`) or delete them when done.

## Gateware

- [ ] **Drop the inert `init_b` platform entry in `ov3.py`.**
  `software/fpga/ov3/ovplatform/ov3.py` still declares
  `("init_b", 0, Pins("P39"), IOStandard("LVCMOS33"))` in `_io`, with the
  comment `# Just disable the pull-down`. Nothing requests it any more — the
  `self.request("init_b")` call was removed in `71068c0` ("Correctly set pad
  voltage and eliminate warnings"). The declaration is therefore dead: pin P39
  is left UNUSED and picks up bitgen's default `UnusedPin = PULLDOWN`.

  That pulldown made the FPGA loader misread INIT_B ~10 ms after configuration
  and print a bogus `FPGA: CRC failed` (DONE was High, the bitstream was fine).
  The loader was fixed to trust DONE and only consult INIT_B while DONE is Low
  (see `software/host/fpgaconfig.c`). With that fix in place the `ov3.py` entry
  has no functional effect, so it can be removed for tidiness — delete the
  `_io` line and the stale comment. Purely cosmetic; requires a gateware
  rebuild.
