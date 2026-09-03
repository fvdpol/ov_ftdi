#!/usr/bin/env python3
"""Reframe a usbmon pcap of OpenVizsla traffic with LibOV's outer framer.

Purpose -- bisect the ``--filter-nak`` framer desync (OpenVizslaTNG/ov_ftdi#25).

LibOV frames the FTDI byte stream in ``OVDevice.__comms`` on a dedicated thread.
The live desync only shows up when register I/O runs concurrently on the main
thread (``ovctl.py sniff``'s ~1 Hz status loop). This script takes the bytes the
*kernel* delivered -- captured with usbmon, i.e. in a single, well defined
completion order -- and runs the identical outer service framing offline.

    clean offline reframe + client desynced  ->  fault is in LibOV's concurrent
                                                 byte assembly, not on the wire
    offline reframe also desyncs             ->  fault is upstream of the host
                                                 (FPGA <-> FT2232H, or the
                                                 FT2232H's USB side)

Input: a classic pcap written by ``tcpdump -i usbmonN -w cap.pcap``, link type
LINKTYPE_USB_LINUX_MMAPPED (220). Standard library only.

    ./reframe.py cap.pcap
    ./reframe.py cap.pcap --bus 3 --dev 7        # pin the device
    ./reframe.py cap.pcap --dump-stream s.bin    # also write the reframed stream
    ./reframe.py cap.pcap --no-skip-startup      # do not hunt for first lock

Framing mirrors ``software/host/LibOV.py`` in this repo:

    io       0x55              size 5
    lfsr     0xAA              size buf[1] + 2
    rxcsniff 0xA1              size 1
             0xAC 0xAD         size 2
             0xA0 0xA2         size orig_len + 4 + delta_ts_len, or
                               MAX_PACKET_SIZE + 4 + delta_ts_len on HF0_TRUNC
    sdram    0xD0              size (buf[1] + 1) * 2 + 2
    dummy    0xE0 0xE8         size 3

The FT2232H side mirrors ``software/host/fastftdi.c`` (ReadStreamCallback): every
512-byte USB packet carries a 2-byte modem-status header that is stripped.
"""

import argparse
import collections
import struct
import sys

# --- constants, from LibOV.py --------------------------------------------------
MAX_PACKET_SIZE = 1027
HF0_TRUNC = 0x08

# --- constants, from fastftdi.h ----------------------------------------------
FTDI_PACKET_SIZE = 512
FTDI_HEADER_SIZE = 2

# usbmon "s_mon_get" mmapped header: 64 bytes, then the (possibly truncated)
# data payload. Field layout per Documentation/usb/usbmon.rst.
_USBMON_HDR = "QBBBBHBBqiiII"          # id, type, xfer, epnum, devnum, busnum,
#                                        setup_flag, data_flag, ts_sec, ts_usec,
#                                        status, urb_len, data_len   (40 bytes)


def read_pcap_records(path):
    """Yield raw (link-layer) record bytes from a classic pcap file."""
    with open(path, "rb") as f:
        blob = f.read()

    magic = blob[:4]
    if magic in (b"\xa1\xb2\xc3\xd4", b"\xa1\xb2\x3c\x4d"):
        endian = ">"
    elif magic in (b"\xd4\xc3\xb2\xa1", b"\x4d\x3c\xb2\xa1"):
        endian = "<"
    else:
        sys.exit("%s: not a pcap file (magic %s)" % (path, magic.hex()))

    _maj, _min, _tz, _sig, snaplen, linktype = struct.unpack(
        endian + "HHiIII", blob[4:24])
    if linktype != 220:
        sys.exit("%s: link type %d, need 220 (LINKTYPE_USB_LINUX_MMAPPED). "
                 "Capture with: tcpdump -i usbmonN -w cap.pcap" % (path, linktype))

    off = 24
    n = len(blob)
    truncated = False
    while off + 16 <= n:
        _s, _u, incl, orig = struct.unpack(endian + "IIII", blob[off:off + 16])
        off += 16
        rec = blob[off:off + incl]
        off += incl
        if incl < orig:
            truncated = True
        if len(rec) >= 40:
            yield endian, rec
    if truncated:
        sys.stderr.write("warning: capture was snapped short of full payloads; "
                         "re-run tcpdump with -s 0\n")


def iter_bulk_in(records):
    """Yield (busnum, devnum, payload) for every bulk-IN completion with data."""
    for endian, rec in records:
        (urb_id, ev_type, xfer, epnum, devnum, busnum, _setup_flag, _data_flag,
         _ts_s, _ts_u, status, _urb_len, data_len) = struct.unpack(
            endian + _USBMON_HDR, rec[:40])

        if xfer != 3:                       # bulk only
            continue
        if not (epnum & 0x80):              # IN only
            continue
        if ev_type != 0x43:                # 'C' -- completion carries IN data
            continue
        if status != 0:
            continue
        payload = rec[64:64 + data_len]
        if payload:
            yield busnum, devnum, payload


def strip_ftdi(payload):
    """Drop the 2-byte FT2232H status header from each 512-byte USB packet,
    exactly as fastftdi.c ReadStreamCallback does for one URB completion."""
    out = bytearray()
    left = len(payload)
    pos = 0
    while left > 0:
        plen = FTDI_PACKET_SIZE if left > FTDI_PACKET_SIZE else left
        out += payload[pos + FTDI_HEADER_SIZE:pos + plen]
        pos += plen
        left -= plen
    return bytes(out)


# --- LibOV outer service framing (see module docstring) ---------------------
_INCOMPLETE = -1


def frame_size(b):
    """(name, size) for the service matching b[0].

    size >= 1  : a complete frame of that length
    _INCOMPLETE: magic matched but b is too short (only legitimate at EOF)
    name '?'   : no service magic matches b[0]  -> an unmatched byte
    """
    m = b[0]
    n = len(b)

    if m == 0x55:                                       # io
        return "io", (5 if n >= 5 else _INCOMPLETE)

    if m == 0xAA:                                       # lfsr
        if n < 2:
            return "lfsr", _INCOMPLETE
        sz = b[1] + 2
        return "lfsr", (sz if n >= sz else _INCOMPLETE)

    if m in (0xA1, 0xAC, 0xAD, 0xA0, 0xA2):             # rxcsniff
        if m == 0xA1:
            return "rxcsniff", 1
        if m in (0xAC, 0xAD):
            return "rxcsniff", (2 if n >= 2 else _INCOMPLETE)
        if n < 4:                                       # need flags + len bytes
            return "rxcsniff", _INCOMPLETE
        flags = b[1]
        delta_ts_len = (b[3] >> 5) + 1
        orig_len = (b[3] & 0x1F) << 8 | b[2]
        sz = (MAX_PACKET_SIZE + 4 + delta_ts_len) if (flags & HF0_TRUNC) \
            else (orig_len + 4 + delta_ts_len)
        return "rxcsniff", (sz if n >= sz else _INCOMPLETE)

    if m == 0xD0:                                       # sdram_read
        if n < 2:
            return "sdram", _INCOMPLETE
        sz = (b[1] + 1) * 2 + 2
        return "sdram", (sz if n >= sz else _INCOMPLETE)

    if m in (0xE0, 0xE8):                               # dummy
        return "dummy", (3 if n >= 3 else _INCOMPLETE)

    return "?", None


def _locks_here(stream, start, frames=6):
    """True if `frames` consecutive frames parse cleanly from `start`."""
    c = start
    n = len(stream)
    for _ in range(frames):
        if c >= n:
            return True
        _name, sz = frame_size(stream[c:c + MAX_PACKET_SIZE + 8])
        if sz is None or sz == _INCOMPLETE:
            return False
        c += sz
    return True


def find_first_lock(stream):
    """Offset of the first byte from which framing holds for several frames.

    A usbmon capture almost always starts mid-frame, so the first handful of
    bytes are the tail of a frame whose header predates the capture. That is
    expected and is reported separately from a real mid-stream desync.
    """
    n = len(stream)
    for c in range(min(n, 4096)):
        if stream[c] in (0x55, 0xAA, 0xA0, 0xA1, 0xA2, 0xAC, 0xAD, 0xD0, 0xE0,
                         0xE8) and _locks_here(stream, c):
            return c
    return 0


def walk(stream, skip_startup=True):
    n = len(stream)
    start = find_first_lock(stream) if skip_startup else 0

    counts = collections.Counter()
    unmatched = []
    c = start
    while c < n:
        name, sz = frame_size(stream[c:c + MAX_PACKET_SIZE + 8])
        if sz is None:
            unmatched.append((c, stream[c]))
            c += 1
            continue
        if sz == _INCOMPLETE:
            break                       # trailing partial frame -- normal
        counts[name] += 1
        c += sz

    return {
        "counts": dict(counts),
        "unmatched": unmatched,
        "lead_skipped": start,
        "trailing": n - c,
        "total": n,
    }


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("pcap")
    ap.add_argument("--bus", type=int, help="usbmon bus number to keep")
    ap.add_argument("--dev", type=int, help="USB device address to keep")
    ap.add_argument("--dump-stream", metavar="FILE",
                    help="write the reframed (FT2232H-stripped) byte stream")
    ap.add_argument("--no-skip-startup", action="store_true",
                    help="do not hunt for the first framing lock")
    args = ap.parse_args()

    records = list(read_pcap_records(args.pcap))

    # First pass: tally bulk-IN bytes per (bus, dev) so we can auto-pick.
    tally = collections.Counter()
    for bus, dev, payload in iter_bulk_in(records):
        tally[(bus, dev)] += len(payload)
    if not tally:
        sys.exit("no bulk-IN completions with data in %s" % args.pcap)

    if args.bus is None and args.dev is None:
        (bus, dev), _ = tally.most_common(1)[0]
        if len(tally) > 1:
            sys.stderr.write("multiple devices in capture: %s\n" % dict(tally))
            sys.stderr.write("picking the busiest: bus %d dev %d "
                             "(override with --bus/--dev)\n" % (bus, dev))
    else:
        bus, dev = args.bus, args.dev

    # Second pass: concatenate that device's completions in capture order and
    # strip FT2232H status bytes per URB.
    chunks = []
    for b, d, payload in iter_bulk_in(records):
        if (args.bus is None or b == bus) and (args.dev is None or d == dev):
            if b == bus and d == dev:
                chunks.append(strip_ftdi(payload))
    stream = b"".join(chunks)

    if args.dump_stream:
        with open(args.dump_stream, "wb") as f:
            f.write(stream)

    res = walk(stream, skip_startup=not args.no_skip_startup)

    print("device            bus %d dev %d" % (bus, dev))
    print("reframed stream   %d bytes  (%d URB completions)"
          % (res["total"], len(chunks)))
    print("lead bytes skipped %d  (start-of-capture partial frame)"
          % res["lead_skipped"])
    print("frames parsed     %s  (total %d)"
          % (res["counts"], sum(res["counts"].values())))
    print("trailing bytes    %d  (partial frame at EOF)" % res["trailing"])

    um = res["unmatched"]
    if not um:
        print()
        print("VERDICT: CLEAN -- the bytes the kernel delivered reframe without "
              "a single desync.")
        return 0

    off0, byte0 = um[0]
    ctx = stream[max(0, off0 - 16):off0 + 16]
    print()
    print("VERDICT: DESYNC -- %d unmatched byte(s); first at offset %d (0x%02x)"
          % (len(um), off0, byte0))
    print("  context [-16..+16]: %s" % ctx.hex(" "))
    return 1


if __name__ == "__main__":
    sys.exit(main())
