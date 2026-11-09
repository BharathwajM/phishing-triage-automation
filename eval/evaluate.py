"""Measure phishtriage against public email corpora.

Phishing:   Nazario phishing corpus, 2024 and 2025 mailboxes (CC BY 4.0)
            https://monkey.org/~jose/phishing/
Legitimate: SpamAssassin public corpus, easy_ham and hard_ham (2003)
            https://spamassassin.apache.org/old/publiccorpus/

The corpora are not stored in this repo. Download them once, then run:

    python eval/evaluate.py --download --data corpus/
    python eval/evaluate.py --data corpus/

The 2024 mailbox and easy_ham are the development set used to design changes.
The 2025 mailbox and hard_ham are the held-out test set.

Messages are read straight from the mbox files and tar archives, nothing is
extracted or executed, and live enrichment is never called. Only aggregate
numbers are written to eval/results.json.
"""
from __future__ import annotations

import argparse
import collections
import hashlib
import json
import mailbox
import pathlib
import sys
import tarfile
import urllib.request

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from phishtriage.auth import analyze_auth  # noqa: E402
from phishtriage.indicators import collect_indicators  # noqa: E402
from phishtriage.parser import parse_email  # noqa: E402
from phishtriage.scoring import score  # noqa: E402

CORPORA = {
    "phishing-2024": ("https://monkey.org/~jose/phishing/phishing-2024",
                      "60afa40a2757170093a2bde31ec9cda4e54d33992203ce04bfbbc86d2e5e5b99", "phishing", "dev"),
    "phishing-2025": ("https://monkey.org/~jose/phishing/phishing-2025",
                      "f1fa7e0fe35c9a16f36d9aa20ade7e1d3908d1d0c1d917b8c53c8aa799ec1c8f", "phishing", "test"),
    "20030228_easy_ham.tar.bz2": ("https://spamassassin.apache.org/old/publiccorpus/20030228_easy_ham.tar.bz2",
                                  "2b7b65904bcfcc31d2b5f51946f2d261370b257402cbbd62930b46ab83367438", "legitimate", "dev"),
    "20030228_hard_ham.tar.bz2": ("https://spamassassin.apache.org/old/publiccorpus/20030228_hard_ham.tar.bz2",
                                  "ce2ce67880643dbde65ea7f85bffbfe4417349c4bd80b6b0de56262ae6b0a9c9", "legitimate", "test"),
}
FLAGGED = {"MALICIOUS", "SUSPICIOUS"}
LABELS = ["MALICIOUS", "SUSPICIOUS", "LIKELY BENIGN", "BENIGN"]


def sha256(path: pathlib.Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def download(data: pathlib.Path) -> None:
    data.mkdir(parents=True, exist_ok=True)
    for name, (url, digest, _, _) in CORPORA.items():
        dest = data / name
        if not dest.exists():
            print(f"downloading {url}")
            req = urllib.request.Request(url, headers={"User-Agent": "phishtriage-eval"})
            with urllib.request.urlopen(req, timeout=300) as r:
                dest.write_bytes(r.read())
        if sha256(dest) != digest:
            raise SystemExit(f"{name}: SHA-256 does not match the version this evaluation used")


def messages(path: pathlib.Path):
    """Yield raw message bytes from an mbox file or a SpamAssassin tar.bz2."""
    if path.name.endswith(".tar.bz2"):
        with tarfile.open(path, "r:bz2") as tar:
            for m in tar:
                if m.isfile() and not m.name.endswith("/cmds"):
                    yield tar.extractfile(m).read()
    else:
        box = mailbox.mbox(str(path), create=False)
        for key in box.keys():
            yield box.get_bytes(key)


def triage(raw: bytes) -> dict:
    pe = parse_email(raw)
    v = score(collect_indicators(pe, analyze_auth(pe)))
    return {"label": v.label, "score": v.score,
            "indicators": sorted({i.id for i in v.indicators}),
            "has_url": bool(pe.urls), "has_attachment": bool(pe.attachments)}


def evaluate(data: pathlib.Path) -> dict:
    per_corpus, groups = {}, collections.defaultdict(list)
    for name, (_, digest, cls, split) in CORPORA.items():
        path = data / name
        if sha256(path) != digest:
            raise SystemExit(f"{name}: unexpected file, run with --download first")
        rows, errors = [], 0
        for raw in messages(path):
            try:
                rows.append(triage(raw))
            except Exception:  # count, but never stop the run on one malformed message
                errors += 1
        labels = collections.Counter(r["label"] for r in rows)
        per_corpus[name] = {"class": cls, "split": split, "messages": len(rows), "parse_errors": errors,
                            "labels": {k: labels.get(k, 0) for k in LABELS}}
        groups[(split, cls)].extend(rows)
        groups[("all", cls)].extend(rows)

    summary = collections.defaultdict(dict)
    for (split, cls), rows in sorted(groups.items()):
        n = len(rows)
        flagged = [r for r in rows if r["label"] in FLAGGED]
        missed = [r for r in rows if r["label"] not in FLAGGED]
        ind = collections.Counter(i for r in rows for i in r["indicators"])
        summary[split][cls] = {
            "messages": n,
            "flagged": len(flagged),
            "flagged_pct": round(100 * len(flagged) / n, 1) if n else 0.0,
            "malicious": sum(r["label"] == "MALICIOUS" for r in rows),
            "indicator_share_pct": {k: round(100 * c / n, 1) for k, c in ind.most_common()},
            "not_flagged": {
                "count": len(missed),
                "no_url_no_attachment": sum(not r["has_url"] and not r["has_attachment"] for r in missed),
                "no_indicators": sum(not r["indicators"] for r in missed),
            },
        }
        if cls == "legitimate":
            summary[split][cls]["false_positive_indicators"] = dict(collections.Counter(
                i for r in flagged for i in r["indicators"]).most_common())
    return {"corpora": per_corpus, "summary": summary}


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--data", required=True, type=pathlib.Path, help="folder holding the corpus files")
    ap.add_argument("--download", action="store_true", help="download and verify the corpora into --data")
    ap.add_argument("--out", default="eval/results.json", help="where to write the JSON results (relative to the repo)")
    args = ap.parse_args()
    if args.download:
        download(args.data)
    result = evaluate(args.data)
    out = ROOT / args.out
    out.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    for split in ("dev", "test", "all"):
        p, l = result["summary"][split]["phishing"], result["summary"][split]["legitimate"]
        print(f"{split:5} phishing flagged {p['flagged']}/{p['messages']} ({p['flagged_pct']}%) | "
              f"legitimate flagged {l['flagged']}/{l['messages']} ({l['flagged_pct']}%)")
    print(f"wrote {out.relative_to(ROOT)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
