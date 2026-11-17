"""Fetch CISA's Known Exploited Vulnerabilities list and write a small file for Patch Radar.

Writes, in the repo root:
  kev-recent.json  entries added in the last 400 days, trimmed to the fields the page uses,
                   plus firstSeen: when this robot first saw each entry (UTC, ISO 8601)
  first-seen.json  CVE -> firstSeen for every entry ever seen (kept between runs)

The workflow commits only when a file changed. Standard library only.
"""
import json
import pathlib
import sys
import urllib.request
from datetime import datetime, timedelta, timezone

SOURCES = [
    "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
    "https://raw.githubusercontent.com/cisagov/kev-data/main/known_exploited_vulnerabilities.json",
]
KEEP_DAYS = 400
ROOT = pathlib.Path(__file__).resolve().parent.parent
FIELDS = ("cveID", "vendorProject", "product", "vulnerabilityName", "dateAdded", "dueDate",
          "knownRansomwareCampaignUse", "shortDescription")


def fetch():
    last = None
    for url in SOURCES:
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "patch-radar-data/1.0 (+github actions)"})
            with urllib.request.urlopen(req, timeout=60) as r:
                data = json.load(r)
            if data.get("vulnerabilities"):
                return data, url
        except Exception as e:  # try the next source
            last = e
            print(f"warn: {url}: {e}", file=sys.stderr)
    raise SystemExit(f"no source answered: {last}")


def vendor_url(notes):
    for part in (notes or "").split(";"):
        part = part.strip()
        if part.startswith("http") and "cisa.gov" not in part and "nvd.nist.gov" not in part:
            return part
    return ""


def main():
    data, used = fetch()
    now = datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")

    seen_path = ROOT / "first-seen.json"
    seen = json.loads(seen_path.read_text(encoding="utf-8")) if seen_path.exists() else {}
    first_run = not seen

    vulns = data["vulnerabilities"]
    for v in vulns:
        cve = v["cveID"]
        if cve not in seen:
            # On the very first run we did not watch these appear, so use CISA's date.
            seen[cve] = v["dateAdded"] + "T00:00:00Z" if first_run else now

    cutoff = (datetime.now(timezone.utc) - timedelta(days=KEEP_DAYS)).date().isoformat()
    recent = []
    for v in vulns:
        if v.get("dateAdded", "") < cutoff:
            continue
        item = {k: v.get(k, "") for k in FIELDS}
        item["vendorUrl"] = vendor_url(v.get("notes"))
        item["firstSeen"] = seen[v["cveID"]]
        recent.append(item)
    recent.sort(key=lambda x: (x["dateAdded"], x["cveID"]), reverse=True)

    out = {
        "catalogVersion": data.get("catalogVersion"),
        "dateReleased": data.get("dateReleased"),
        "count": data.get("count", len(vulns)),
        "keptDays": KEEP_DAYS,
        "vulnerabilities": recent,
    }
    old_path = ROOT / "kev-recent.json"
    old = json.loads(old_path.read_text(encoding="utf-8")) if old_path.exists() else {}
    changed = {k: v for k, v in old.items() if k != "updatedAt"} != out
    out["updatedAt"] = now if changed else old.get("updatedAt", now)

    old_path.write_text(json.dumps(out, ensure_ascii=True, separators=(",", ":")), encoding="utf-8")
    seen_path.write_text(json.dumps(dict(sorted(seen.items())), ensure_ascii=True, indent=0), encoding="utf-8")
    print(f"catalog {out['catalogVersion']} from {used}: {len(recent)} recent of {out['count']}, changed={changed}")


if __name__ == "__main__":
    main()
