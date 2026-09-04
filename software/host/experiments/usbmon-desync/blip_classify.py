"""Pcap-free classification heuristics for one already-located desync event.

Takes only the small window reframe.py already saves around a trip point --
never the source .pcap (which can be gigabytes; a window is a few hundred
bytes). Import this from reframe.py (to classify at capture time) and from
classify_blips.py (to re-classify already-captured events after a heuristic
changes here) -- one place, so the two never drift apart.

Add new heuristics here as we learn more about the upsets. Each is cheap
enough to re-run over every blip ever captured in well under a second.
"""

# USB PID byte -> name. Every real PID is 4 bits + its own bitwise
# complement, packed low/high nibble -- a spec-mandated self-check every
# genuine captured packet's first byte satisfies (see pid_valid()).
USB_PID_NAMES = {
    0xE1: "OUT", 0x69: "IN", 0xA5: "SOF", 0x2D: "SETUP",
    0xC3: "DATA0", 0x4B: "DATA1", 0x87: "DATA2", 0x0F: "MDATA",
    0xD2: "ACK", 0x5A: "NAK", 0x1E: "STALL", 0x96: "NYET",
    0x3C: "PRE/ERR", 0x78: "SPLIT", 0xB4: "PING",
}

# delta_ts (every rxcsniff packet record's per-record timestamp field) is in
# 60MHz device-clock ticks -- confirmed via ovctl.py's own OutputCustom/
# OutputITI1480A, both of which divide by 60e6 to print seconds.
DEVICE_CLOCK_HZ = 60e6


def pid_valid(byte):
    """True if `byte` could be a genuine USB PID (low nibble == bitwise
    complement of high nibble). False means whatever reframe.py landed on
    here is NOT a real packet boundary -- either its own byte-hunt found a
    coincidental false-positive header (not a genuine relock), or the
    payload itself is corrupted past just the framing."""
    lo, hi = byte & 0x0F, byte >> 4
    return lo == (~hi) & 0x0F


def decode_frame_packet(frame_bytes):
    """frame_bytes: the raw bytes of one rxcsniff record (magic byte through
    its end), sliced from a saved window. None for non-packet records
    (0xA1/0xAC/0xAD carry no PID/timestamp -- see reframe.py's frame_size).
    Mirrors LibOV.py's __RXCSniffService.consume() layout exactly."""
    if not frame_bytes or frame_bytes[0] not in (0xA0, 0xA2) or len(frame_bytes) < 4:
        return None
    delta_ts_len = (frame_bytes[3] >> 5) + 1
    pkt_start = 4 + delta_ts_len
    if len(frame_bytes) <= pkt_start:
        return None
    delta_ts = 0
    for i in range(delta_ts_len):
        delta_ts |= frame_bytes[4 + i] << (8 * i)
    pid_byte = frame_bytes[pkt_start]
    valid = pid_valid(pid_byte)
    out = {
        "pid_byte": pid_byte, "pid_name": USB_PID_NAMES.get(pid_byte),
        "pid_valid": valid,
        "delta_ts": delta_ts, "delta_ts_us": delta_ts / (DEVICE_CLOCK_HZ / 1e6),
    }
    # SOF: PID(1) + 11-bit frame number (byte0 + low 3 bits of byte1) +
    # CRC5 (top 5 bits of byte1). A real, protocol-level sequence number --
    # increments every 125us on the wire, and we don't filter SOF -- so its
    # continuity across a gap is checkable independent of anything the
    # capture framework itself tracks.
    if valid and pid_byte == 0xA5 and len(frame_bytes) >= pkt_start + 3:
        b1, b2 = frame_bytes[pkt_start + 1], frame_bytes[pkt_start + 2]
        out["sof_frame_num"] = b1 | ((b2 & 0x07) << 8)
    return out


def _decode_at(frame_tuple, window, window_lo):
    """frame_tuple: (offset, name, size) as saved in a blip sidecar's
    pre_frames/post_frames. None if it falls outside the saved window."""
    offset, _name, size = frame_tuple
    local = offset - window_lo
    if local < 0 or local + size > len(window):
        return None
    return decode_frame_packet(window[local:local + size])


def _nearest_sof(frames, window, window_lo, from_end):
    seq = reversed(frames) if from_end else frames
    for ft in seq:
        d = _decode_at(ft, window, window_lo)
        if d and d.get("sof_frame_num") is not None:
            return d
    return None


def classify_event(window, trip_idx, klen, window_lo=0,
                    pre_frames=None, post_frames=None):
    """window: bytes, the saved hex-context slice (buf[lo:hi] as reframe.py
    captured it). trip_idx: index of the trip point within `window` (i.e.
    off0 - lo). klen: the event's run length (number of skipped bytes).
    window_lo/pre_frames/post_frames: needed for the PID/SOF/timestamp
    checks below -- omit them to get just the duplicate-byte checks.

    Returns a dict of hints -- never a final verdict, these are inputs to a
    human (or a future stronger check) deciding loss vs. insertion, not a
    substitute for looking at the frame context too.
    """
    junk = window[trip_idx:trip_idx + klen]
    preceding = window[:trip_idx]
    following = window[trip_idx + klen:]

    # Loss vs. insertion, take 1: is the skipped run a literal repeat of the
    # bytes immediately before it (stale re-read / duplicate), or of the
    # bytes immediately after where it lands (the *next* legitimate data
    # got duplicated backwards)? Either leans "insertion", not "loss" -- a
    # true gap (real data missing) has no reason to look like a copy of its
    # neighbors. Absence of a match is NOT evidence of loss either way; it's
    # simply uninformative with this one check.
    dup_of_preceding = (bool(junk) and len(preceding) >= len(junk)
                        and junk == preceding[-len(junk):])
    dup_of_following = (bool(junk) and len(following) >= len(junk)
                        and junk == following[:len(junk)])

    result = {
        "junk_len": len(junk),
        "junk_truncated": len(junk) < klen,   # window was narrower than the run
        "dup_of_preceding": dup_of_preceding,
        "dup_of_following": dup_of_following,
    }

    pre_frames = pre_frames or []
    post_frames = post_frames or []

    # Take 2: does the packet the framer landed on right after the gap look
    # like a genuine USB packet (valid PID), and does the transaction that
    # was in progress right before the gap look complete? The USB-level
    # analogue of "PING got a NAK" (clean, transaction-complete) vs. "PING
    # with no reply visible" (something's missing) -- except here we're
    # checking framing/PID structure, not transaction semantics, since we
    # don't attempt to pair tokens with their handshakes.
    last_pre = _decode_at(pre_frames[-1], window, window_lo) if pre_frames else None
    first_post = _decode_at(post_frames[0], window, window_lo) if post_frames else None
    result["last_pre_pid"] = last_pre["pid_name"] if last_pre else None
    result["first_post_pid"] = first_post["pid_name"] if first_post else None
    result["first_post_pid_valid"] = first_post["pid_valid"] if first_post else None

    # Take 3: an actual protocol-level sequence number. SOF packets carry an
    # 11-bit frame number that increments every 125us; if it's numerically
    # CONTIGUOUS across the gap despite reframe.py having had to skip bytes
    # to re-lock, that's evidence nothing macroscopic (a whole frame's worth
    # of real device traffic) went missing -- consistent with a local
    # corruption/insertion, not a dropped chunk. A jump bigger than 1 means
    # real elapsed device time -- and very likely real traffic -- is
    # unaccounted for: lean loss, and the size of the jump lower-bounds how
    # much.
    sof_before = _nearest_sof(pre_frames, window, window_lo, from_end=True)
    sof_after = _nearest_sof(post_frames, window, window_lo, from_end=False)
    if sof_before and sof_after:
        result["sof_frame_gap"] = (
            (sof_after["sof_frame_num"] - sof_before["sof_frame_num"]) % 2048)
    else:
        result["sof_frame_gap"] = None   # no SOF in range on one or both sides

    # Take 4: elapsed device-clock time across the gap, from the delta-
    # timestamp every packet record carries (not just SOF) -- present
    # regardless of whether a SOF happened to be nearby. first_post's
    # delta_ts is the real device-clock time since the last packet actually
    # captured before it, independent of how many bytes were skipped to get
    # there. Compare against nearby pre-gap inter-packet gaps to judge
    # "normal" vs. "anomalously long" (i.e. did the device really go quiet).
    pre_deltas = [d["delta_ts_us"] for d in
                  (_decode_at(ft, window, window_lo) for ft in pre_frames)
                  if d is not None]
    result["gap_delta_ts_us"] = first_post["delta_ts_us"] if first_post else None
    result["typical_delta_ts_us"] = (sum(pre_deltas) / len(pre_deltas)
                                     if pre_deltas else None)

    return result
