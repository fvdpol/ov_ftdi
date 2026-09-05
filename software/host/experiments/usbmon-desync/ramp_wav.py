#!/usr/bin/env python3
"""Generate a native-format S24_3LE ramp WAV to play continuously into the DUT
during a sniff, so the sniffed OUT packets carry a decodable serial number
(ov_ftdi #25, the "is the pre-onset data from a previous session" test).

Sample value = sample index mod 2**24, identical on every channel. One full
file is exactly one wrap period, so `aplay --loop` (or plain repetition)
produces a seamless free-running ramp: the last sample is 0xFFFFFF, the next
loop's first sample is 0x000000, which is the natural wrap.

    ./ramp_wav.py ramp96.wav                 # 96000 Hz, 4 ch, ~174.8 s
    ./ramp_wav.py --rate 44100 ramp44.wav    # ~380.4 s
    ./ramp_wav.py --channels 2 ramp.wav

Play it with EXACT-format passthrough -- no plughw, no softvol, 100% volume:

    aplay -D hw:<card>,<dev> -t raw -f S24_3LE -c 4 -r 96000 ramp96.wav
    # or, since it's a real WAV header:
    aplay -D hw:<card>,<dev> ramp96.wav

Any resample / format-convert / dither in the path destroys the ramp.
"""

import argparse
import struct
import sys

WRAP = 1 << 24          # 24-bit ramp period, in samples


def s24_3le(value):
    """3 little-endian bytes of a 24-bit unsigned value."""
    return bytes((value & 0xFF, (value >> 8) & 0xFF, (value >> 16) & 0xFF))


def _wav_header(rate, channels, data_len):
    """canonical 44-byte PCM WAV header, S24_3LE (wFormatTag=1, 24 bits)."""
    frame_bytes = 3 * channels
    byte_rate = rate * frame_bytes
    hdr = b"RIFF" + struct.pack("<I", 36 + data_len) + b"WAVE"
    hdr += b"fmt " + struct.pack("<IHHIIHH",
                                 16, 1, channels, rate, byte_rate,
                                 frame_bytes, 24)
    hdr += b"data" + struct.pack("<I", data_len)
    return hdr


def build(rate, channels):
    n = WRAP
    frame_bytes = 3 * channels
    data_len = n * frame_bytes
    hdr = _wav_header(rate, channels, data_len)

    try:
        import numpy as np
        idx = np.arange(n, dtype=np.uint32)
        b = np.empty((n, 3), dtype=np.uint8)
        b[:, 0] = idx & 0xFF
        b[:, 1] = (idx >> 8) & 0xFF
        b[:, 2] = (idx >> 16) & 0xFF
        frame = np.tile(b, (1, channels))          # (n, 3*channels), all ch equal
        return hdr + frame.tobytes()
    except ImportError:
        pass

    buf = bytearray(len(hdr) + data_len)
    buf[:len(hdr)] = hdr
    pos = len(hdr)
    for i in range(n):
        buf[pos:pos + frame_bytes] = s24_3le(i) * channels
        pos += frame_bytes
    return bytes(buf)


def main():
    ap = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("out")
    ap.add_argument("--rate", type=int, default=96000)
    ap.add_argument("--channels", type=int, default=4)
    args = ap.parse_args()

    data = build(args.rate, args.channels)
    with open(args.out, "wb") as f:
        f.write(data)
    dur = WRAP / args.rate
    print("wrote %s: %d ch, %d Hz, S24_3LE, %d samples = %.3f s (one wrap), %d bytes"
          % (args.out, args.channels, args.rate, WRAP, dur, len(data)))


if __name__ == "__main__":
    main()
