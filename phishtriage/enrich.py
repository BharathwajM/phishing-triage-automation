"""Optional threat-intel enrichment. The tool is fully useful WITHOUT this -
the CLI calls it with --enrich, and each service requires its API key:

    VT_API_KEY        VirusTotal (urls, domains, file hashes)   https://www.virustotal.com
    URLHAUS_API_KEY   abuse.ch URLhaus (malware URLs)           https://urlhaus.abuse.ch

`requests` is imported lazily so the core triage runs on a stock Python with no
pip install. If a key or the library is missing, enrichment is skipped cleanly
and the report says so.
"""
from __future__ import annotations

import os
from dataclasses import dataclass, field


@dataclass
class EnrichResult:
    source: str
    target: str
    malicious: int = 0
    suspicious: int = 0
    note: str = ""


@dataclass
class Enrichment:
    enabled: bool
    results: list[EnrichResult] = field(default_factory=list)
    skipped_reason: str = ""


def _requests():
    try:
        import requests  # noqa: PLC0415 - optional dependency, imported lazily
        return requests
    except ImportError:
        return None


def enrich(urls: list[str], domains: list[str], hashes: list[str]) -> Enrichment:
    vt_key = os.environ.get("VT_API_KEY", "").strip()
    uh_key = os.environ.get("URLHAUS_API_KEY", "").strip()
    if not vt_key and not uh_key:
        return Enrichment(enabled=False,
                          skipped_reason="No VT_API_KEY / URLHAUS_API_KEY set - live enrichment skipped.")
    requests = _requests()
    if requests is None:
        return Enrichment(enabled=False,
                          skipped_reason="`requests` not installed - live enrichment skipped "
                                         "(pip install requests to enable).")

    results: list[EnrichResult] = []

    if vt_key:
        hdr = {"x-apikey": vt_key}
        for h in hashes[:10]:
            try:
                r = requests.get(f"https://www.virustotal.com/api/v3/files/{h}", headers=hdr, timeout=15)
                if r.status_code == 200:
                    stats = r.json()["data"]["attributes"]["last_analysis_stats"]
                    results.append(EnrichResult("VirusTotal", h,
                                                stats.get("malicious", 0), stats.get("suspicious", 0)))
                elif r.status_code == 404:
                    results.append(EnrichResult("VirusTotal", h, note="not found"))
            except Exception as e:  # network/parse errors never break triage
                results.append(EnrichResult("VirusTotal", h, note=f"error: {e}"))

    if uh_key:
        for u in urls[:10]:
            try:
                r = requests.post("https://urlhaus-api.abuse.ch/v1/url/",
                                  data={"url": u}, headers={"Auth-Key": uh_key}, timeout=15)
                if r.status_code == 200:
                    j = r.json()
                    if j.get("query_status") == "ok":
                        results.append(EnrichResult("URLhaus", u, malicious=1,
                                                    note=j.get("threat", "listed")))
            except Exception as e:
                results.append(EnrichResult("URLhaus", u, note=f"error: {e}"))

    return Enrichment(enabled=True, results=results)
