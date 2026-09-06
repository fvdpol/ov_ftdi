# Evidence snapshot — ov_ftdi #25 `--filter-nak` desync

Point-in-time raw data behind `../issue25-report.md`. The large artifacts
(`.pcap`, reframed streams) are not in git — they are ~1 GB per run and live on
the test rig. What is here is enough to check the report's numbers.

## `manifest.jsonl`

One JSON object per sniff run — the append-only ledger the whole analysis is
built from. Snapshot taken **2026-09-05** (ramp collection still in progress at
snapshot time). Key fields:

- `scenario` — `<client>_<gateware>_<reload|noload>_nak<0|1>_sof<0|1>_<secs>s[_drain1]`
- `batch` — which collection run it belongs to
- `inner_verdict` — `CLEAN` / `RECOVERED` (framer tripped once, re-locked) /
  `NEVER_RECOVERED`
- `inner_first_offset` — byte offset in the reframed inner stream where framing
  first breaks (the "seam")
- `reframed_bytes` — total reframed size; a few KB here means the capture was
  against a disconnected DUT and the row is not a valid sample
- `preR` / `postR` etc. — see `../sof_continuity.py`

Regenerate the report's scenario table from this with
`../gen_report_tables.py`.

## `blips/`

Per-event context dumps (`../reframe.py --dump-blips`, ±256 byte window): the
raw bytes and parsed frames on each side of the framing break, plus the
loss-vs-insertion heuristics. `.txt` is human-readable, `.json` the same data
for tooling.

- `ovctl-20260905T161234Z_inner_blip_7195244` — a **ramp-signal** run
  (`20260905-ramp` batch), seam ~7.2 MB in. The ramp decode across this seam
  jumps +48.8 s (see `ramp-seam-steps.txt`).
- `ovctl-20260905T161840Z_inner_blip_263` — a ramp run whose seam is at byte
  263 (ring near-empty at start); the ramp is continuous through the capture.
- `ovctl-20260904T164128Z_inner_blip_14396843`,
  `ovctl-20260904T173057Z_inner_blip_36302966` — two of the original 12
  no-load desync events (no ramp), from the batch analysed in depth in §3 of
  the report.

## `ramp-seam-steps.txt`

`../decode_out_ramp.py` output for the ramp runs: the decoded ramp value each
side of the seam, and the step across it. This is the direct confirmation that
the pre-seam bytes are a previous session's data.

## whyfn15 experiment ("Why the desync needs `--filter-nak`" chapter)

`manifest.jsonl` also carries the 36 rows of batches `20260905-whyfn15`
(15 s captures, 3 filter conditions) and the 5 stray `20260905-whyfilternak`
240 s rows. These are **excluded from the report's §2 scenario table**
(`gen_report_tables.py --exclude-batch 20260905-whyfn15 --exclude-batch
20260905-whyfilternak`) and summarised in the last chapter instead.

- `ovctl-20260905T205750Z_inner_blip_16145112` — a `--filter-nak` desync from
  that batch; the ramp decode across this seam jumps +12.3 s (see
  `ramp-seam-steps.txt`).

Per-run `HF0_FIRST` / `HF0_OVF` detail is derived live from each
`results/<tag>.reframe.json`; it is not snapshotted here.
