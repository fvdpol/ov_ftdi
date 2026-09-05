#!/usr/bin/env python3
"""Decode the Ploytec playback (host -> DUT, "OUT") bit-plane wire format back
to S24_3LE, so a ramp signal played into the DUT can be read out of the
sniffed OUT packets (ov_ftdi #25).

The forward encoder here is a faithful copy of the structural derivation in
alsa-jockey3's tests/codec/ploytec_model.py (`_build_encode_map` /
`encode_frame`) -- same rule: 4 channels in two pairs (ch0,ch2) and (ch1,ch3),
each pair in a 24-byte block of three 8-byte planes, MSB plane first; within a
plane wire byte i carries bit (7-i) of the sample byte; the channel's index in
its pair picks the destination bit. `decode_playback_frame` is the exact
inverse, and `_selftest()` (run by `-m`/`main`) checks inverse(forward(x)) == x
on random data, and cross-checks against ploytec_model.py if that repo is on
the path.

Wire geometry: one USB OUT packet = PLAYBACK_FRAMES (10) playback frames of
PLAYBACK_FRAME_SIZE (48) wire bytes = 480 audio bytes; byte 480 onward is MIDI
/ padding. Each 48-byte frame decodes to 12 bytes S24_3LE = 4 ch * 3 bytes.
"""

import os
import random
import sys

PLAYBACK_FRAMES = 10
PLAYBACK_FRAME_SIZE = 48
PLAYBACK_CHANNELS = 4
PLAYBACK_PCM_FRAME_SIZE = 12          # 4 ch * 3 bytes
PLAYBACK_AUDIO_BYTES = PLAYBACK_FRAMES * PLAYBACK_FRAME_SIZE   # 480
BYTES_PER_SAMPLE = 3
PLANE_SIZE = 8
RAMP_WRAP = 1 << 24


def _plane_offset(sample_byte):
    return (BYTES_PER_SAMPLE - 1 - sample_byte) * PLANE_SIZE


def _build_encode_map():
    pairs = [(0, 2), (1, 3)]
    rows = []
    for pair_idx, channels in enumerate(pairs):
        block_base = pair_idx * (BYTES_PER_SAMPLE * PLANE_SIZE)
        for sample_byte in reversed(range(BYTES_PER_SAMPLE)):     # MSB plane first
            for dst_bit, channel in enumerate(channels):
                src_idx = channel * BYTES_PER_SAMPLE + sample_byte
                rows.append((src_idx, block_base + _plane_offset(sample_byte),
                             dst_bit))
    return tuple(rows)


ENCODE_MAP = _build_encode_map()


def encode_playback_frame(src12):
    """12-byte S24_3LE (4 ch) -> 48-byte wire frame. Reference direction."""
    dest = bytearray(PLAYBACK_FRAME_SIZE)
    for src_idx, dst_base, dst_bit in ENCODE_MAP:
        v = src12[src_idx]
        for i in range(PLANE_SIZE):
            dest[dst_base + i] |= ((v >> (7 - i)) & 1) << dst_bit
    return bytes(dest)


def decode_playback_frame(wire48):
    """48-byte wire frame -> 12-byte S24_3LE (4 ch). Exact inverse of encode."""
    src = bytearray(PLAYBACK_PCM_FRAME_SIZE)
    for src_idx, dst_base, dst_bit in ENCODE_MAP:
        v = 0
        for i in range(PLANE_SIZE):
            v |= ((wire48[dst_base + i] >> dst_bit) & 1) << (7 - i)
        src[src_idx] = v
    return bytes(src)


def channel_values(pcm12):
    """4 unsigned 24-bit channel samples from one 12-byte S24_3LE frame."""
    return tuple(pcm12[c * 3] | (pcm12[c * 3 + 1] << 8) | (pcm12[c * 3 + 2] << 16)
                for c in range(PLAYBACK_CHANNELS))


def decode_out_packet_ramp(payload):
    """payload: the DATA bytes of one playback OUT packet (>= 480). Returns the
    list of 10 per-frame ramp values (channel 0), plus a flag for whether all 4
    channels agreed in every frame (they should, for the ramp signal)."""
    vals = []
    all_ch_agree = True
    for f in range(PLAYBACK_FRAMES):
        w = payload[f * PLAYBACK_FRAME_SIZE:(f + 1) * PLAYBACK_FRAME_SIZE]
        if len(w) < PLAYBACK_FRAME_SIZE:
            break
        chs = channel_values(decode_playback_frame(w))
        vals.append(chs[0])
        if len(set(chs)) != 1:
            all_ch_agree = False
    return vals, all_ch_agree


def _selftest():
    rnd = random.Random(20260906)
    for _ in range(5000):
        src = bytes(rnd.getrandbits(8) for _ in range(PLAYBACK_PCM_FRAME_SIZE))
        if decode_playback_frame(encode_playback_frame(src)) != src:
            print("FAIL: inverse(forward(x)) != x for", src.hex())
            return 1
    print("OK: 5000 random frames round-trip through encode->decode")

    # cross-check the forward map against the real model, if available
    for p in ("~/jockey3_linux/alsa-jockey3/tests/codec",
              "../../../../jockey3_linux/alsa-jockey3/tests/codec"):
        pp = os.path.expanduser(p)
        if os.path.exists(os.path.join(pp, "ploytec_model.py")):
            sys.path.insert(0, pp)
            try:
                import ploytec_model as pm
                mism = 0
                for _ in range(2000):
                    src = bytes(rnd.getrandbits(8)
                                for _ in range(PLAYBACK_PCM_FRAME_SIZE))
                    if pm.encode_frame(src) != encode_playback_frame(src):
                        mism += 1
                if mism:
                    print("FAIL: %d/2000 frames disagree with ploytec_model.encode_frame"
                          % mism)
                    return 1
                print("OK: forward map matches ploytec_model.encode_frame (2000 frames)")
            except Exception as e:                       # noqa: BLE001
                print("note: could not cross-check against ploytec_model (%s)" % e)
            break
    else:
        print("note: ploytec_model.py not found -- skipped external cross-check")

    # ramp sanity: a frame built from index i decodes to i on all 4 channels
    for i in (0, 1, 255, 256, 0x7FFFFF, 0xFFFFFF, 0x123456):
        s = bytes((i & 0xFF, (i >> 8) & 0xFF, (i >> 16) & 0xFF)) * 4
        chs = channel_values(decode_playback_frame(encode_playback_frame(s)))
        if chs != (i, i, i, i):
            print("FAIL: ramp index %#x decoded to %r" % (i, chs))
            return 1
    print("OK: ramp index round-trips on all 4 channels")
    return 0


if __name__ == "__main__":
    sys.exit(_selftest())
