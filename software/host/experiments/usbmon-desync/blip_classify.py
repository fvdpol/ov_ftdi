"""Pcap-free classification heuristics for one already-located desync event.

Takes only the small window reframe.py already saves around a trip point --
never the source .pcap (which can be gigabytes; a window is a few hundred
bytes). Import this from reframe.py (to classify at capture time) and from
classify_blips.py (to re-classify already-captured events after a heuristic
changes here) -- one place, so the two never drift apart.

Add new heuristics here as we learn more about the upsets. Each is cheap
enough to re-run over every blip ever captured in well under a second.
"""


def classify_event(window, trip_idx, klen):
    """window: bytes, the saved hex-context slice (buf[lo:hi] as reframe.py
    captured it). trip_idx: index of the trip point within `window` (i.e.
    off0 - lo). klen: the event's run length (number of skipped bytes).

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

    return {
        "junk_len": len(junk),
        "junk_truncated": len(junk) < klen,   # window was narrower than the run
        "dup_of_preceding": dup_of_preceding,
        "dup_of_following": dup_of_following,
    }
