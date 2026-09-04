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
    ./reframe.py cap.pcap --dump-blips results/blips  # per-desync context dump

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
import bisect
import collections
import datetime
import json
import os
import struct
import sys

import blip_classify

# --- constants, from LibOV.py --------------------------------------------------
MAX_PACKET_SIZE = 1027
HF0_ERR = 0x01
HF0_OVF = 0x02          # RX Path Overflow -- inserted in-band by ovf_insert.py
HF0_CLIP = 0x04
HF0_TRUNC = 0x08
HF0_FIRST = 0x10
HF0_LAST = 0x20
HF0_SPEED_MASK = 0xC0
# LibOV's own "PERR" counter (__RXCSniffService.consume): any problem flag,
# i.e. everything except FIRST/LAST/speed. Matching it exactly so a count
# from a pcap is directly comparable to what LibOV would have logged live.
HF0_PERR_MASK = HF0_ERR | HF0_OVF | HF0_CLIP | HF0_TRUNC

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
    """Yield (busnum, devnum, ts_sec, ts_usec, payload) for every bulk-IN
    completion with data. ts is the usbmon *completion* wall-clock time, i.e.
    the kernel's clock at capture time -- not a device-side timestamp."""
    for endian, rec in records:
        (urb_id, ev_type, xfer, epnum, devnum, busnum, _setup_flag, _data_flag,
         ts_s, ts_u, status, _urb_len, data_len) = struct.unpack(
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
            yield busnum, devnum, ts_s, ts_u, payload


def group_runs(unmatched):
    """Group a flat `unmatched` list (each entry a single skipped byte, offsets
    strictly increasing by however far walk() had to skip) into contiguous
    runs -- one per distinct desync *event*. With longer captures a single
    pcap can easily contain more than one event; each needs its own blip
    dump, not just the first/last byte of the whole capture conflated
    together."""
    if not unmatched:
        return []
    runs = [[unmatched[0]]]
    for prev, item in zip(unmatched, unmatched[1:]):
        if item[0] == prev[0] + 1:
            runs[-1].append(item)
        else:
            runs.append([item])
    return runs


def wallclock_at(chunk_meta, offset):
    """usbmon completion wall-clock time (epoch seconds) of the URB covering
    byte `offset` of the reframed outer stream, or None if out of range.
    chunk_meta: parallel to the `chunks` list -- (start, end, ts_sec, ts_usec)
    in outer-stream-offset space, in capture order. This is the *host kernel's*
    clock at completion time, not a device-side timestamp -- see the note in
    iter_bulk_in."""
    if not chunk_meta:
        return None
    starts = [m[0] for m in chunk_meta]
    i = bisect.bisect_right(starts, offset) - 1
    if i < 0:
        return None
    start, end, ts_s, ts_u = chunk_meta[i]
    if not (start <= offset < end):
        return None
    return ts_s + ts_u / 1e6


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


def walk(stream, skip_startup=True, collect_magic=None, context_frames=8):
    """Walk `stream` with the LibOV outer service framing.

    collect_magic: if set (e.g. 0xD0), also return the concatenated payloads of
    every frame with that magic, minus its 2-byte header -- i.e. the inner
    whacker byte stream that LibOV's SDRAMReadService feeds to rxcsniff. Also
    returns `subpayload_segments`: (inner_start, inner_end, outer_start) for
    every appended slice, so a byte offset in the inner stream can be mapped
    back to where it lived in the outer stream (see outer_offset_of_inner).

    For each *run* of unmatched bytes, records the `context_frames` cleanly
    parsed frames immediately preceding it in `unmatched_context`, and the
    `context_frames` immediately following re-lock in `unmatched_post_context`
    -- both (offset, name, size), keyed by the offset of the run's first byte.
    Lets a caller show the packet pattern on both sides of a desync, not just
    what preceded it.
    """
    n = len(stream)
    start = find_first_lock(stream) if skip_startup else 0

    counts = collections.Counter()
    unmatched = []
    unmatched_context = {}
    unmatched_post_context = {}
    recent = collections.deque(maxlen=context_frames)
    in_run = False
    run_start = None
    post_for = None
    post_count = 0
    subpayload = bytearray() if collect_magic is not None else None
    subpayload_segments = [] if collect_magic is not None else None
    c = start
    clean_frames_since_unmatched = 0
    while c < n:
        name, sz = frame_size(stream[c:c + MAX_PACKET_SIZE + 8])
        if sz is None:
            if not in_run:
                unmatched_context[c] = list(recent)
                unmatched_post_context[c] = []
                in_run = True
                run_start = c
            unmatched.append((c, stream[c]))
            clean_frames_since_unmatched = 0
            c += 1
            continue
        if sz == _INCOMPLETE:
            break                       # trailing partial frame -- normal
        if in_run:
            in_run = False
            post_for, post_count = run_start, 0
        counts[name] += 1
        clean_frames_since_unmatched += 1
        recent.append((c, name, sz))
        if post_for is not None:
            unmatched_post_context[post_for].append((c, name, sz))
            post_count += 1
            if post_count >= context_frames:
                post_for = None
        if subpayload is not None and stream[c] == collect_magic:
            seg_start = len(subpayload)
            subpayload += stream[c + 2:c + sz]
            subpayload_segments.append((seg_start, len(subpayload), c + 2))
        c += sz

    return {
        "counts": dict(counts),
        "unmatched": unmatched,
        "unmatched_context": unmatched_context,
        "unmatched_post_context": unmatched_post_context,
        "lead_skipped": start,
        "trailing": n - c,
        "total": n,
        # "recovered": framing was clean for a good stretch after the last slip
        "recovered": bool(unmatched) and clean_frames_since_unmatched > 50,
        "clean_frames_after_last_unmatched": clean_frames_since_unmatched,
        "subpayload": bytes(subpayload) if subpayload is not None else None,
        "subpayload_segments": subpayload_segments,
    }


def outer_offset_of_inner(subpayload_segments, inner_offset):
    """Map a byte offset in the inner (concatenated 0xD0-payload) stream back
    to the position it came from in the outer stream -- so an inner-layer
    event's wall-clock time can be looked up via the same usbmon chunk index
    used for the outer layer. None if out of range (shouldn't happen)."""
    if not subpayload_segments:
        return None
    starts = [s[0] for s in subpayload_segments]
    i = bisect.bisect_right(starts, inner_offset) - 1
    if i < 0:
        return None
    seg_start, seg_end, outer_start = subpayload_segments[i]
    if not (seg_start <= inner_offset < seg_end):
        return None
    return outer_start + (inner_offset - seg_start)


def inner_frame_size(b):
    """Sizing for the inner whacker stream: rxcsniff records only (0xA0-0xAD).
    LibOV's SDRAMReadService feeds this to [rxcsniff.service] alone."""
    m = b[0]
    if m not in (0xA0, 0xA1, 0xA2, 0xAC, 0xAD):
        return "?", None
    return frame_size(b)


def walk_inner(stream, context_frames=8):
    """Walk the concatenated 0xD0 payloads as a pure rxcsniff record stream.
    Same pre-/post-context tracking as walk() -- see its docstring.

    Also tallies HF0_OVF (RX-path overflow, per ovf_insert.py) and the
    broader "PERR" mask (any problem flag) LibOV's own consume() checks,
    from the flags byte 0xA0/0xA2 records carry (buf[1]) -- an in-band
    marker present in the wire bytes themselves, independent of what the
    live client did with them (a "clean reference" client with its handlers
    disabled still has this in the usbmon capture; it just never looked).
    This is the recommended way to get an overflow count for a pcap
    captured before overflow tracking existed at all -- reprocess.py re-runs
    this walk against the *already-stored* .pcap, no hardware needed.

    Frank's 2026-09-05 question -- with the overflow count looking high for
    a --filter-nak run, is it real (missed traffic) or inflated (spuriously
    flagged)? Confirmed from the gateware source: ovf_insert.py's
    OverflowInserter sits UPSTREAM of the whole Whacker (producer -> filter_
    nak -> filter_sof -> consumer, per whacker.py), triggered purely by
    "the producer wasn't ready for the next ULPI byte right now" -- nothing
    about filter_nak enters into it, so it firing under --filter-nak isn't
    surprising by itself. What CAN be checked here: for every HF0_OVF packet,
    the USB SOF frame-number gap either side of it (>1 = a real microframe
    of traffic is unaccounted for, not just a marker; 0 or 1 = no
    macroscopic loss signature at this point), and whether events cluster
    late in the run (a "buffer fills up over time" pattern) or are steady
    throughout (more consistent with a per-burst front-end limit,
    independent of run length) -- overflow_quartile_counts splits the run
    into 4 equal byte-offset quartiles and counts events in each.
    """
    n = len(stream)
    start = 0
    for c in range(min(n, 8192)):
        if stream[c] in (0xA0, 0xA1, 0xA2, 0xAC, 0xAD):
            _n, sz = inner_frame_size(stream[c:c + MAX_PACKET_SIZE + 8])
            if sz not in (None, _INCOMPLETE):
                start = c
                break
    counts = collections.Counter()
    unmatched = []
    unmatched_context = {}
    unmatched_post_context = {}
    recent = collections.deque(maxlen=context_frames)
    in_run = False
    run_start = None
    post_for = None
    post_count = 0
    packets_total = overflow_packets = perr_packets = 0
    last_sof_num = None
    pending_ovf = []           # overflow events awaiting the NEXT sof to resolve their gap
    ovf_gap_counts = collections.Counter()   # {0: n, 1: n, ">1": n} -- >1 is the loss signature
    ovf_gap_max = None
    ovf_unresolved = 0         # no SOF seen again before EOF -- can't resolve, not evidence either way
    ovf_offsets = []           # for the quartile/temporal-distribution check below
    c = start
    clean_since = 0
    while c < n:
        name, sz = inner_frame_size(stream[c:c + MAX_PACKET_SIZE + 8])
        if sz is None:
            if not in_run:
                unmatched_context[c] = list(recent)
                unmatched_post_context[c] = []
                in_run = True
                run_start = c
            unmatched.append((c, stream[c]))
            clean_since = 0
            c += 1
            continue
        if sz == _INCOMPLETE:
            break
        if in_run:
            in_run = False
            post_for, post_count = run_start, 0
        counts[name] += 1
        clean_since += 1
        recent.append((c, name, sz))
        if stream[c] in (0xA0, 0xA2):        # full packet records carry flags @ b[1]
            packets_total += 1
            flags = stream[c + 1]
            pkt = blip_classify.decode_frame_packet(stream[c:c + sz])
            sof_num = pkt.get("sof_frame_num") if pkt else None
            if sof_num is not None:
                for pend_sof in pending_ovf:
                    gap = (sof_num - pend_sof) % 2048 if pend_sof is not None else None
                    ovf_gap_counts[gap if gap in (0, 1) else (">1" if gap is not None else "?")] += 1
                    if gap is not None:
                        ovf_gap_max = gap if ovf_gap_max is None else max(ovf_gap_max, gap)
                pending_ovf = []
                last_sof_num = sof_num
            if flags & HF0_OVF:
                overflow_packets += 1
                ovf_offsets.append(c)
                pending_ovf.append(last_sof_num)
            if flags & HF0_PERR_MASK:
                perr_packets += 1
        if post_for is not None:
            unmatched_post_context[post_for].append((c, name, sz))
            post_count += 1
            if post_count >= context_frames:
                post_for = None
        c += sz
    # Any overflow events still waiting for a following SOF at EOF simply
    # ran out of stream to resolve against -- not evidence either way.
    ovf_unresolved += len(pending_ovf)

    # Temporal distribution: 4 equal byte-offset quartiles of the parsed
    # range, each event counted by where its offset falls. Roughly even
    # counts across quartiles argues for a steady, per-burst front-end
    # limit (independent of how long the run has been going); counts that
    # grow quartile-over-quartile would argue for something actually
    # filling up over the run's duration.
    span = max(1, n - start)
    quartile_counts = [0, 0, 0, 0]
    for off in ovf_offsets:
        q = min(3, int(4 * (off - start) / span))
        quartile_counts[q] += 1

    return {
        "counts": dict(counts), "unmatched": unmatched,
        "unmatched_context": unmatched_context,
        "unmatched_post_context": unmatched_post_context, "lead_skipped": start,
        "trailing": n - c, "total": n,
        "recovered": bool(unmatched) and clean_since > 50,
        "clean_frames_after_last_unmatched": clean_since,
        "packets_total": packets_total,
        # Loss-vs-inflated check for HF0_OVF events specifically (2026-09-05,
        # Frank): "overflow_sof_gap_gt1" is the count with real evidence of
        # missing traffic (a real USB sequence-number gap); "_le1" is the
        # count with no such evidence (doesn't prove nothing was lost --
        # SOF-gap can only see whole-microframe-scale loss -- just that
        # nothing macroscopic was). "_unresolved" ran out of stream (no
        # following SOF) before it could be checked either way.
        "overflow_sof_gap_gt1": ovf_gap_counts[">1"],
        "overflow_sof_gap_le1": ovf_gap_counts[0] + ovf_gap_counts[1],
        "overflow_sof_gap_unresolved": ovf_unresolved,
        "overflow_sof_gap_max": ovf_gap_max,
        "overflow_quartile_counts": quartile_counts,
        "overflow_packets": overflow_packets,
        "perr_packets": perr_packets,
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
    ap.add_argument("--dump-blips", metavar="DIR",
                    help="for every desync run, write the preceding frame "
                         "pattern + surrounding hex to DIR/<layer>_blip_<off>.txt "
                         "(#25: 'is there a packet stream pattern where it "
                         "happens')")
    ap.add_argument("--blip-window", type=int, default=256,
                    help="bytes of hex context on each side of a blip (default 256)")
    ap.add_argument("--json-summary", metavar="FILE",
                    help="write a one-line JSON verdict summary to FILE, for "
                         "run_bisect.sh to fold into results/manifest.jsonl")
    args = ap.parse_args()

    records = list(read_pcap_records(args.pcap))

    # First pass: tally bulk-IN bytes per (bus, dev) so we can auto-pick.
    tally = collections.Counter()
    for bus, dev, _ts_s, _ts_u, payload in iter_bulk_in(records):
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
    # strip FT2232H status bytes per URB. chunk_meta tracks each completion's
    # byte range in `stream` plus its usbmon wall-clock time, for wallclock_at.
    chunks = []
    chunk_meta = []
    pos = 0
    for b, d, ts_s, ts_u, payload in iter_bulk_in(records):
        if (args.bus is None or b == bus) and (args.dev is None or d == dev):
            if b == bus and d == dev:
                c = strip_ftdi(payload)
                chunks.append(c)
                chunk_meta.append((pos, pos + len(c), ts_s, ts_u))
                pos += len(c)
    stream = b"".join(chunks)

    if args.dump_stream:
        with open(args.dump_stream, "wb") as f:
            f.write(stream)

    res = walk(stream, skip_startup=not args.no_skip_startup, collect_magic=0xD0)

    print("device            bus %d dev %d" % (bus, dev))
    print("reframed stream   %d bytes  (%d URB completions)"
          % (res["total"], len(chunks)))
    print("lead bytes skipped %d  (start-of-capture partial frame)"
          % res["lead_skipped"])
    print("frames parsed     %s  (total %d)"
          % (res["counts"], sum(res["counts"].values())))
    print("trailing bytes    %d  (partial frame at EOF)" % res["trailing"])

    if args.dump_blips:
        os.makedirs(args.dump_blips, exist_ok=True)
    # Run identifier for blip filenames: run_bisect.sh names the pcap
    # "<mode>-<timestamp>.pcap", so the basename IS the run tag -- put it in
    # the filename so a directory listing alone tells you which run each
    # blip came from, not just its (layer, offset).
    run_label = os.path.splitext(os.path.basename(args.pcap))[0]

    def dump_one_event(layer_tag, buf, off0, offL, klen, is_last, tag,
                        to_outer_offset, pre, post):
        outer_off0 = to_outer_offset(off0)
        wc = wallclock_at(chunk_meta, outer_off0) if outer_off0 is not None else None
        wc_str = (datetime.datetime.fromtimestamp(wc).isoformat(timespec="microseconds")
                  if wc is not None else "unknown")
        print("%-14s DESYNC (%s) -- %d unmatched; first@%d last@%d; wallclock %s"
              % (layer_tag + ":", tag, klen, off0, offL, wc_str))
        print("               ctx first: %s"
              % buf[max(0, off0 - 12):off0 + 12].hex(" "))

        # Classification is cheap (only touches the small window around the
        # trip point) so compute it regardless of --dump-blips; only writing
        # the sidecar files to disk is conditional on that flag.
        w = args.blip_window
        lo, hi = max(0, off0 - w), min(len(buf), off0 + w)
        window = buf[lo:hi]
        trip_idx = off0 - lo
        cls = blip_classify.classify_event(window, trip_idx, klen, window_lo=lo,
                                           pre_frames=pre, post_frames=post)
        dup_of_preceding = cls["dup_of_preceding"]
        sof_gap = cls["sof_frame_gap"]
        print("               loss-vs-insertion: dup_pre=%s dup_post=%s  "
              "last_pre_pid=%s first_post_pid=%s (valid=%s)  "
              "SOF frame gap=%s  device-time gap=%s us (typical ~%s us)"
              % (cls["dup_of_preceding"], cls["dup_of_following"],
                 cls["last_pre_pid"], cls["first_post_pid"],
                 cls["first_post_pid_valid"],
                 sof_gap if sof_gap is not None else "no SOF nearby",
                 "%.1f" % cls["gap_delta_ts_us"] if cls["gap_delta_ts_us"] is not None else "?",
                 "%.1f" % cls["typical_delta_ts_us"] if cls["typical_delta_ts_us"] is not None else "?"))

        if args.dump_blips:
            base = os.path.join(args.dump_blips,
                                 "%s_%s_blip_%d" % (run_label, layer_tag, off0))
            with open(base + ".txt", "w") as f:
                f.write("pcap: %s\n" % args.pcap)
                f.write("layer: %s  offset (exact byte, this layer's stream): "
                        "%d  outer-stream offset: %s  run length: %d bytes  "
                        "verdict: %s  wallclock: %s\n"
                        % (layer_tag, off0, outer_off0, klen, tag, wc_str))
                f.write("skipped-run duplicates the %d bytes immediately "
                        "preceding it: %s / immediately following it (post "
                        "re-lock): %s  (loss-vs-insertion hint -- True leans "
                        "'stale re-read / duplicate', False is uninformative "
                        "either way, not evidence of loss)\n"
                        % (klen, cls["dup_of_preceding"], cls["dup_of_following"]))
                f.write("last PID before gap: %s -- first PID after gap: %s "
                        "(structurally valid PID byte: %s; False means this "
                        "isn't a genuine packet boundary -- either a false-"
                        "positive relock, or the payload is corrupted past "
                        "just the framing)\n"
                        % (cls["last_pre_pid"], cls["first_post_pid"],
                           cls["first_post_pid_valid"]))
                f.write("SOF frame-number gap across the gap: %s  (a real "
                        "USB sequence number, increments by 1 every 125us; "
                        "1 = nothing macroscopic missing here, >1 lower-"
                        "bounds how many microframes of real traffic did)\n"
                        % (sof_gap if sof_gap is not None else "n/a (no SOF "
                           "packet within the saved window on one or both sides)"))
                f.write("device-clock time from the last pre-gap packet to "
                        "the first post-gap one: %s us (typical inter-packet "
                        "gap nearby: ~%s us) -- from each packet's own "
                        "delta-timestamp, independent of how many bytes were "
                        "skipped to get here\n\n"
                        % ("%.2f" % cls["gap_delta_ts_us"] if cls["gap_delta_ts_us"] is not None else "?",
                           "%.2f" % cls["typical_delta_ts_us"] if cls["typical_delta_ts_us"] is not None else "?"))
                f.write("preceding %d parsed frames (offset, name, size):\n"
                        % len(pre))
                for o, name, sz in pre:
                    f.write("  %8d  %-10s %d\n" % (o, name, sz))
                f.write("\n>>> framer trips here: offset %d <<<\n\n" % off0)
                f.write("following %d parsed frames after re-lock "
                        "(offset, name, size):\n" % len(post))
                for o, name, sz in post:
                    f.write("  %8d  %-10s %d\n" % (o, name, sz))
                f.write("\nhex, %d bytes before .. %d bytes after offset %d "
                        "(trip point marked |><|):\n"
                        % (off0 - lo, hi - off0, off0))
                f.write(buf[lo:off0].hex(" ") + "  |><|  " + buf[off0:hi].hex(" ") + "\n")
            # Small JSON sidecar carrying the same window + frame lists, for
            # classify_blips.py to re-run classify_event() on later (e.g. a
            # new heuristic) WITHOUT touching this .pcap again -- the sidecar
            # is a few hundred bytes; the pcap can be gigabytes.
            with open(base + ".json", "w") as f:
                json.dump({
                    "pcap": args.pcap, "layer": layer_tag, "run_label": run_label,
                    "offset": off0, "last_offset": offL, "outer_offset": outer_off0,
                    "run_length": klen, "verdict": tag, "wallclock": wc,
                    "pre_frames": pre, "post_frames": post,
                    "window_lo": lo, "window_hi": hi, "trip_idx": trip_idx,
                    "window_hex": window.hex(),
                    "classification": cls,
                }, f)
            print("               blip context: %s.{txt,json}  (dup-of-preceding: %s)"
                  % (base, dup_of_preceding))
        return {
            "first_offset": off0, "last_offset": offL, "unmatched": klen,
            "outer_offset": outer_off0,
            "first_offset_pct": round(100.0 * off0 / len(buf), 1) if buf else None,
            "wallclock": wc, "dup_of_preceding": dup_of_preceding,
            "dup_of_following": cls["dup_of_following"],
            "last_pre_pid": cls["last_pre_pid"], "first_post_pid": cls["first_post_pid"],
            "first_post_pid_valid": cls["first_post_pid_valid"],
            "sof_frame_gap": sof_gap,
            "gap_delta_ts_us": cls["gap_delta_ts_us"],
            "typical_delta_ts_us": cls["typical_delta_ts_us"],
        }

    def verdict(label, layer_tag, r, buf, to_outer_offset=lambda o: o):
        um = r["unmatched"]
        if not um:
            print("%-14s CLEAN" % label)
            return 0, {
                "verdict": "CLEAN", "unmatched": 0, "events": [],
                "packets_total": r.get("packets_total"),
                "overflow_packets": r.get("overflow_packets"),
                "perr_packets": r.get("perr_packets"),
            }

        runs = group_runs(um)
        tag = "RECOVERED" if r["recovered"] else "NEVER RECOVERED"
        if len(runs) > 1:
            print("%-14s %d separate desync events in this capture "
                  "(reporting each below)" % (label, len(runs)))
        events = []
        for i, run in enumerate(runs):
            off0, offL = run[0][0], run[-1][0]
            is_last = (i == len(runs) - 1)
            # every run except the last is inherently followed by at least
            # one successfully parsed frame (else it would have merged into
            # the next run) -- only the last run's fate is "recovered" vs
            # "never recovered" for the whole capture, per r["recovered"].
            run_tag = tag if is_last else "RECOVERED"
            pre = r.get("unmatched_context", {}).get(off0, [])
            post = r.get("unmatched_post_context", {}).get(off0, [])
            events.append(dump_one_event(layer_tag, buf, off0, offL, len(run),
                                          is_last, run_tag, to_outer_offset,
                                          pre, post))

        first = events[0]
        summary = {
            "verdict": "RECOVERED" if r["recovered"] else "NEVER_RECOVERED",
            "unmatched": len(um), "num_events": len(runs),
            "first_offset": first["first_offset"], "last_offset": offL,
            "first_offset_outer_offset": first["outer_offset"],
            "first_offset_pct": first["first_offset_pct"],
            "wallclock": first["wallclock"],
            "clean_frames_after_last": r["clean_frames_after_last_unmatched"],
            "events": events,
            # in-band overflow/PERR flag tally (inner layer only -- see
            # walk_inner's docstring); None for the outer layer, which
            # doesn't decode rxcsniff flags at all.
            "packets_total": r.get("packets_total"),
            "overflow_packets": r.get("overflow_packets"),
            "perr_packets": r.get("perr_packets"),
        }
        return (0 if r["recovered"] else 1), summary

    print()
    print("=== outer 0xD0 / service framing (the wire layer) ===")
    outer_rc, outer_summary = verdict("outer:", "outer", res, stream)

    inner = walk_inner(res["subpayload"] or b"")
    print()
    print("=== inner whacker framing (0xD0 payloads -> rxcsniff records) ===")
    print("inner stream   %d bytes; frames %s"
          % (inner["total"], inner["counts"]))
    print("in-band flags  %d packets, %d HF0_OVF, %d PERR (any problem flag)"
          % (inner["packets_total"], inner["overflow_packets"], inner["perr_packets"]))
    inner_rc, inner_summary = verdict(
        "inner:", "inner", inner, res["subpayload"] or b"",
        to_outer_offset=lambda o: outer_offset_of_inner(
            res.get("subpayload_segments"), o))

    if args.json_summary:
        with open(args.json_summary, "w") as f:
            json.dump({
                "pcap": args.pcap, "reframed_bytes": res["total"],
                "outer": outer_summary, "inner": inner_summary,
            }, f)

    print()
    if not outer_rc and not inner_rc:
        print("VERDICT: CLEAN (or self-recovered) at both layers -- the kernel-"
              "delivered bytes frame fine; a LibOV desync on this capture is in "
              "LibOV's own consumption, not the wire.")
        return 0
    print("VERDICT: DESYNC on the wire bytes themselves "
          "(%s%s) -- not a LibOV-only artifact."
          % ("outer " if outer_rc else "", "inner" if inner_rc else ""))
    return 1


if __name__ == "__main__":
    sys.exit(main())
