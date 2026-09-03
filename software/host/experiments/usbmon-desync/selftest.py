#!/usr/bin/env python3
"""Self-test for reframe.py: synthesize a usbmon pcap from a known frame stream
and check that reframe.py reconstructs it (clean case) and flags a deliberate
1-byte deletion (desync case). No hardware. stdlib only.

    ./selftest.py
"""
import os
import struct
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.realpath(__file__))
REFRAME = os.path.join(HERE, "reframe.py")

FTDI_PACKET_SIZE = 512
FTDI_DATA_PER_PACKET = FTDI_PACKET_SIZE - 2


def sdram_frame(words):
    # 0xD0, n  where size = (n+1)*2 + 2; body zeros, like the real whacker
    # silent-audio stream (which is why a desync there never re-locks).
    n = words - 1
    return bytes([0xD0, n]) + bytes((n + 1) * 2)


def io_frame():
    b = [0x55, 0x12, 0x34, 0x56]
    b.append(sum(b) & 0xFF)
    return bytes(b)


def dummy_frame():
    return bytes([0xE0, 0xE1, 0xE2])


def build_stream():
    frames, kinds = [], []
    pattern = ([sdram_frame(w) for w in (1, 4, 9, 2, 17)]
               + [io_frame(), dummy_frame(), sdram_frame(6)])
    labels = ["sdram"] * 5 + ["io", "dummy", "sdram"]
    for _ in range(40):
        frames += pattern
        kinds += labels
    from collections import Counter
    return b"".join(frames), Counter(kinds)


def add_ftdi_headers(stream):
    out = bytearray()
    for i in range(0, len(stream), FTDI_DATA_PER_PACKET):
        out += b"\x01\x60" + stream[i:i + FTDI_DATA_PER_PACKET]
    return bytes(out)


def write_pcap(path, wire, urb_bytes=4096):
    with open(path, "wb") as f:
        f.write(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 262144, 220))
        for k, i in enumerate(range(0, len(wire), urb_bytes)):
            payload = wire[i:i + urb_bytes]
            hdr = struct.pack("<QBBBBHBBqiiII", 1000 + k, 0x43, 3, 0x86, 7, 3,
                              0x2D, 0, 0, 0, 0, len(payload), len(payload))
            hdr += b"\x00" * (64 - len(hdr))
            rec = hdr + payload
            f.write(struct.pack("<IIII", 0, k, len(rec), len(rec)) + rec)


def reframe(path):
    p = subprocess.run([sys.executable, REFRAME, path],
                       capture_output=True, text=True)
    return p.returncode, p.stdout + p.stderr


def main():
    stream, kinds = build_stream()
    captured = stream[29:]                       # start-of-capture partial

    d = tempfile.mkdtemp(prefix="reframe-selftest-")
    clean = os.path.join(d, "clean.pcap")
    write_pcap(clean, add_ftdi_headers(captured))
    rc, out = reframe(clean)
    assert rc == 0 and "VERDICT: CLEAN" in out, out
    print("clean case  : CLEAN  (%d frames: %s)"
          % (sum(kinds.values()), dict(kinds)))

    cut = int(len(captured) * 0.6)
    corrupt = os.path.join(d, "corrupt.pcap")
    write_pcap(corrupt, add_ftdi_headers(captured[:cut] + captured[cut + 1:]))
    rc, out = reframe(corrupt)
    assert rc == 1 and "VERDICT: DESYNC" in out, out
    print("corrupt case: DESYNC (1-byte deletion detected)")

    print("\nOK")


if __name__ == "__main__":
    main()
