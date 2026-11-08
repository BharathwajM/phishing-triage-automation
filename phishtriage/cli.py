"""Command line entrypoint. Triage one .eml, several, or a whole folder,
and write a Markdown + HTML analyst report for each.

    python -m phishtriage samples/*.eml
    python -m phishtriage --format html --out reports samples/
    python -m phishtriage --json samples/paypal_credphish.eml
"""
from __future__ import annotations

import argparse
import json
import pathlib
import sys

from .auth import analyze_auth
from .enrich import Enrichment, enrich
from .indicators import collect_indicators
from .parser import parse_email
from .report import build_html, build_markdown
from .scoring import score
from .utils import registered_domain, url_host


def _gather(paths: list[str]) -> list[pathlib.Path]:
    out: list[pathlib.Path] = []
    for p in paths:
        pp = pathlib.Path(p)
        if pp.is_dir():
            out.extend(sorted(pp.glob("*.eml")))
        elif pp.is_file():
            out.append(pp)
        else:
            print(f"warning: {p} not found", file=sys.stderr)
    return out


def triage_one(path: pathlib.Path, do_enrich: bool):
    pe = parse_email(path.read_bytes())
    auth = analyze_auth(pe)
    indicators = collect_indicators(pe, auth)
    verdict = score(indicators)
    if do_enrich:
        hashes = [a.sha256 for a in pe.attachments]
        domains = sorted({registered_domain(url_host(u)) for u in pe.urls})
        enr = enrich(pe.urls, domains, hashes)
    else:
        enr = Enrichment(enabled=False, skipped_reason="Live enrichment is off. Use --enrich to opt in.")
    return pe, auth, verdict, enr


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="phishtriage",
                                 description="Automated phishing email triage for SOC analysts.")
    ap.add_argument("emails", nargs="+", help=".eml files or directories to triage")
    ap.add_argument("--out", default="reports", help="output directory for reports (default: reports)")
    ap.add_argument("--format", choices=["md", "html", "both"], default="both",
                    help="report format to write (default: both)")
    ap.add_argument("--json", action="store_true", help="print a machine-readable JSON summary to stdout")
    enrichment = ap.add_mutually_exclusive_group()
    enrichment.add_argument("--enrich", action="store_true", dest="enrich",
                            help="send indicators to configured threat-intel services")
    enrichment.add_argument("--no-enrich", action="store_false", dest="enrich",
                            help="run offline (default)")
    ap.set_defaults(enrich=False)
    args = ap.parse_args(argv)

    files = _gather(args.emails)
    if not files:
        print("No .eml files to triage.", file=sys.stderr)
        return 2

    out_dir = pathlib.Path(args.out)
    out_dir.mkdir(parents=True, exist_ok=True)
    results = []

    for f in files:
        try:
            pe, auth, verdict, enr = triage_one(f, do_enrich=args.enrich)
        except Exception as e:
            print(f"ERROR triaging {f.name}: {e}", file=sys.stderr)
            continue

        stem = f.stem
        if args.format in ("md", "both"):
            (out_dir / f"{stem}.md").write_text(build_markdown(pe, auth, verdict, enr), encoding="utf-8")
        if args.format in ("html", "both"):
            (out_dir / f"{stem}.html").write_text(build_html(pe, auth, verdict, enr), encoding="utf-8")

        results.append({
            "file": f.name, "verdict": verdict.label, "score": verdict.score,
            "from": pe.from_addr, "subject": pe.subject,
            "indicators": len(verdict.indicators),
            "attack": verdict.attack_techniques,
        })
        if not args.json:
            tag = {"MALICIOUS": "x", "SUSPICIOUS": "!", "LIKELY BENIGN": "-", "BENIGN": "."}.get(verdict.label, "?")
            print(f"[{tag}] {verdict.label:<14} {verdict.score:>3}/100  {f.name}  "
                  f"({len(verdict.indicators)} indicators)")

    if args.json:
        print(json.dumps(results, indent=2))
    elif len(results) > 1:
        mal = sum(1 for r in results if r["verdict"] == "MALICIOUS")
        sus = sum(1 for r in results if r["verdict"] == "SUSPICIOUS")
        print(f"\n{len(results)} triaged · {mal} malicious · {sus} suspicious · "
              f"reports in {out_dir}/")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
