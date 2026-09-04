#!/usr/bin/env python3
"""Minimal --filter-nak capture: enable the filtered stream, then do NOTHING for
N seconds, then tear down.

This is the "clean reference" client for the usbmon bisect
(OpenVizslaTNG/ov_ftdi#25). It issues zero register I/O during the capture
window -- all CSR access is one-time setup and one-time teardown -- which is the
one behavioral difference from ``ovctl.py sniff`` (whose ~1 Hz status loop reads
CSRs from the main thread while LibOV's __comms thread frames the stream).

LibOV frames the stream on its own thread and prints ``Unmatched byte ..`` to
stdout if it desyncs. Expected here: silent.

    ./mincapture.py [seconds]        # default 20

Run it with usbmon capturing in parallel -- see run_bisect.sh / README.md.
"""

import os
import sys
import time
import zipfile

HERE = os.path.dirname(os.path.realpath(__file__))
HOST = os.path.normpath(os.path.join(HERE, "..", ".."))     # software/host
sys.path.insert(0, HOST)

import LibOV                                                 # noqa: E402

PKG = os.getenv("OV_PKG", os.path.join(HOST, "ov3.fwpkg"))
RING_BASE = 0
RING_SIZE = 16 * 1024 * 1024


def open_device():
    pkg = zipfile.ZipFile(PKG, "r")
    dev = LibOV.OVDevice(mapfile=pkg.open("map.txt", "r"))

    err = dev.open(bitstream=None)
    if err:
        sys.exit("open failed: %r" % err)
    if not dev.isLoaded():
        dev.close()
        err = dev.open(bitstream=pkg.open("ov3.bit", "r"))
        if err:
            sys.exit("open (with bitstream) failed: %r" % err)

    if dev.dev.eeprom_sanitycheck() != 0:
        sys.exit("EEPROM sanity check failed -- run 'ovctl.py eep-program' first")

    # ovctl.main() does this flush before every command.
    dev.dev.write(LibOV.FTDI_INTERFACE_A, b"\x00" * 512, async_=False)
    return dev


def setup(dev):
    """One-time setup, mirrors ovctl.do_sniff for hs + NAK filter."""
    if not dev.regs.ucfg_stat.rd():
        sys.exit("ULPI clock has not started -- oscillator?")

    dev.regs.LEDS_MUX_2.wr(0)
    dev.regs.LEDS_OUT.wr(0)
    dev.regs.LEDS_MUX_0.wr(2)
    dev.regs.LEDS_MUX_1.wr(2)

    dev.regs.SDRAM_SINK_GO.wr(0)
    dev.regs.SDRAM_HOST_READ_GO.wr(0)
    dev.regs.SDRAM_SINK_RING_BASE.wr(RING_BASE)
    dev.regs.SDRAM_SINK_RING_END.wr(RING_BASE + RING_SIZE)
    dev.regs.SDRAM_HOST_READ_RING_BASE.wr(RING_BASE)
    dev.regs.SDRAM_HOST_READ_RING_END.wr(RING_BASE + RING_SIZE)
    dev.regs.SDRAM_SINK_GO.wr(1)
    dev.regs.SDRAM_HOST_READ_GO.wr(1)

    dev.regs.OVF_INSERT_CTL.wr(1)
    dev.regs.OVF_INSERT_CTL.wr(0)

    # High Speed, non-drive.
    dev.ulpiregs.func_ctl.wr(0x48)

    # CSTREAM_CFG bit 0 = stream enable, bit 2 = NAK filter, bit 3 = SOF filter.
    cfg = 1
    if os.getenv("FILTER_NAK", "1") == "1":
        cfg |= (1 << 2)
    if os.getenv("FILTER_SOF", "0") == "1":
        cfg |= (1 << 3)
    dev.regs.CSTREAM_CFG.wr(cfg)


def teardown(dev):
    # OVF_INSERT_NUM_OVF/_TOTAL are cumulative since setup()'s reset pulse
    # (OVF_INSERT_CTL.wr(1) then wr(0)) -- CSRStatus values latch on any
    # write to OVF_INSERT_CTL (Perfcounter's "snapshot" pulse), so a plain
    # wr(0) here (no reset, just re-latch) refreshes them to their final
    # value for the whole capture window before we read. One register write
    # + two reads, after time.sleep() has already returned -- doesn't
    # reintroduce the CSR-during-capture confound this client exists to avoid.
    # Same wording as ovctl.py's status-loop print, so run_bisect.sh parses
    # both clients with one regex.
    dev.regs.OVF_INSERT_CTL.wr(0)
    ovf = dev.regs.OVF_INSERT_NUM_OVF.rd()
    total = dev.regs.OVF_INSERT_NUM_TOTAL.rd()
    print("%d overflow, %08x total" % (ovf, total), flush=True)

    dev.regs.SDRAM_SINK_GO.wr(0)
    dev.regs.SDRAM_HOST_READ_GO.wr(0)
    dev.regs.CSTREAM_CFG.wr(0)


def main():
    secs = float(sys.argv[1]) if len(sys.argv) > 1 else 20.0

    dev = open_device()

    # Drop LibOV's default per-packet verbose printer (USBInterpreter). Leaving
    # it in makes the consumer slow enough to starve the __comms framing thread
    # -- the classic "slow consumer desyncs, fast consumer is clean" effect --
    # which would confound the bisect. ov_snapshot.py does the same. The outer
    # framer still runs and still prints "Unmatched byte" on a real desync.
    dev.rxcsniff.service.handlers = []

    setup(dev)
    print("capturing for %.1f s with the NAK filter on, zero register I/O ..."
          % secs, flush=True)
    try:
        time.sleep(secs)
    except KeyboardInterrupt:
        pass
    finally:
        teardown(dev)
        dev.close()
    print("done -- if nothing printed 'Unmatched byte', the client stayed in sync.")


if __name__ == "__main__":
    main()
