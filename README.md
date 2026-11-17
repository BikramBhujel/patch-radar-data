# patch-radar-data

Data for [Patch Radar](https://www.bikrambhujel.com.np/p/patch-radar.html).

A GitHub Action checks the [CISA Known Exploited Vulnerabilities](https://www.cisa.gov/known-exploited-vulnerabilities-catalog)
list every 30 minutes and, when it changes, commits:

| File | What it is |
|---|---|
| `kev-recent.json` | Entries added in the last 400 days with the fields Patch Radar uses, plus `vendorUrl` and `firstSeen` (when this robot first saw the entry, UTC). About 1/10 the size of CISA's full file. |
| `first-seen.json` | `firstSeen` for every entry ever seen, kept between runs. |

Served by GitHub Pages at `https://bikrambhujel.github.io/patch-radar-data/kev-recent.json`.
CISA's data is public domain (US government work). This repo relays it as published.

Run locally: `python scripts/build.py`.
