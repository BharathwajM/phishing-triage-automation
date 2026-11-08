"""Render the triage result as a SOC analyst report - Markdown for a ticket,
or a standalone styled HTML page. IOCs are defanged so the report is safe to
paste into a ticket or email."""
from __future__ import annotations

import html
import re
from datetime import datetime, timezone

from .auth import AuthResult
from .enrich import Enrichment
from .parser import ParsedEmail
from .scoring import Verdict
from .utils import defang, registered_domain, url_host

_SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
_SEV_EMOJI = {"critical": "[CRIT]", "high": "[HIGH]", "medium": "[MED ]",
              "low": "[LOW ]", "info": "[INFO]"}
_AUTH_NOTICE = "Reported results are unverified. Confirm them in trusted mail gateway logs."


def _markdown_literal(value: str, *, in_table: bool = False) -> str:
    """Keep email-controlled text inside a single Markdown code span."""
    value = " ".join(value.splitlines()).strip() or "n/a"
    if in_table:
        # A literal pipe can split a GFM table cell before inline code is parsed.
        value = value.replace("|", r"\x7c")
    longest_run = max((len(run) for run in re.findall(r"`+", value)), default=0)
    delimiter = "`" * (longest_run + 1)
    return f"{delimiter} {value} {delimiter}"


def _recommendation(v: Verdict) -> list[str]:
    if v.label == "MALICIOUS":
        return ["Do not interact. Quarantine/delete from any inboxes that received it.",
                "Block the sender domain and all IOC domains/URLs at the mail gateway and proxy.",
                "Search mail logs for other recipients; pull the message org-wide.",
                "If links/attachments were opened, isolate the host and begin IR."]
    if v.label == "SUSPICIOUS":
        return ["Hold for analyst review; do not release to the user yet.",
                "Detonate links/attachments in a sandbox before any verdict.",
                "Confirm sender legitimacy out-of-band if it claims to be internal/a vendor."]
    return ["Confirm sender legitimacy and message context before releasing from quarantine.",
            "Verify requests for credentials, payment or data out of band."]


def _iocs(pe: ParsedEmail):
    domains = sorted({registered_domain(url_host(u)) for u in pe.urls if url_host(u)})
    return {
        "urls": pe.urls,
        "domains": [d for d in domains if d],
        "sender_domain": registered_domain(pe.domain_of(pe.from_addr)),
        "attachments": [(a.filename, a.sha256) for a in pe.attachments],
    }


def build_markdown(pe: ParsedEmail, auth: AuthResult, v: Verdict, enr: Enrichment) -> str:
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    ioc = _iocs(pe)
    L = []
    L.append(f"# Phishing Triage Report - {v.label}")
    L.append(f"*Generated {now} by phishtriage*\n")
    L.append(f"**Verdict:** {v.label}  |  **Risk score:** {v.score}/100")
    L.append(f"\n{v.summary}\n")

    L.append("## Email")
    sender = f"{pe.from_display} <{pe.from_addr or 'n/a'}>"
    L.append(f"- **From:** {_markdown_literal(sender)}")
    if pe.reply_to_addr:
        L.append(f"- **Reply-To:** {_markdown_literal(pe.reply_to_addr)}")
    L.append(f"- **Subject:** {_markdown_literal(pe.subject or '(none)')}")
    L.append(f"- **Date:** {_markdown_literal(pe.date or '(none)')}")
    L.append(f"- **Message-ID:** {_markdown_literal(pe.message_id or '(none)')}")

    L.append("\n## Authentication")
    L.append(f"- {_AUTH_NOTICE}")
    L.append(f"- SPF: {_markdown_literal(auth.spf or 'n/a')}  |  "
             f"DKIM: {_markdown_literal(auth.dkim or 'n/a')}  |  "
             f"DMARC: {_markdown_literal(auth.dmarc or 'n/a')}")
    for n in auth.notes:
        L.append(f"- {_markdown_literal(n)}")

    L.append("\n## Indicators")
    if not v.indicators:
        L.append("_No suspicious indicators detected._")
    else:
        L.append("| Severity | Finding | ATT&CK | Detail |")
        L.append("|---|---|---|---|")
        for i in sorted(v.indicators, key=lambda x: _SEV_ORDER.get(x.severity, 9)):
            detail = _markdown_literal(i.detail, in_table=True)
            L.append(f"| {i.severity.upper()} | {i.title} | {i.attack or '-'} | {detail} |")

    L.append("\n## Indicators of Compromise (defanged)")
    if ioc["sender_domain"]:
        L.append(f"- **Sender domain:** {_markdown_literal(defang(ioc['sender_domain']))}")
    for u in ioc["urls"]:
        L.append(f"- **URL:** {_markdown_literal(defang(u))}")
    for d in ioc["domains"]:
        L.append(f"- **Domain:** {_markdown_literal(defang(d))}")
    for fn, sha in ioc["attachments"]:
        L.append(f"- **Attachment:** {_markdown_literal(fn)} — sha256 `{sha}`")
    if not (ioc["urls"] or ioc["domains"] or ioc["attachments"]):
        L.append("_None extracted._")

    L.append("\n## Threat-intel enrichment")
    if not enr.enabled:
        L.append(f"_{enr.skipped_reason}_")
    elif not enr.results:
        L.append("_Enrichment ran; no hits returned._")
    else:
        for r in enr.results:
            verdict = ("malicious" if r.malicious else "suspicious" if r.suspicious else (r.note or "clean"))
            L.append(f"- **{r.source}** {_markdown_literal(defang(r.target))} → "
                     f"{_markdown_literal(verdict)}")

    L.append("\n## Recommended analyst actions")
    for a in _recommendation(v):
        L.append(f"- {a}")
    if v.attack_techniques:
        L.append("\n**MITRE ATT&CK:** " + ", ".join(v.attack_techniques))
    return "\n".join(L) + "\n"


_SEV_COLOR = {"critical": "#b3261e", "high": "#d9480f", "medium": "#b8860b",
              "low": "#2457a6", "info": "#5f6368"}
_VERDICT_COLOR = {"MALICIOUS": "#b3261e", "SUSPICIOUS": "#d9480f",
                  "LIKELY BENIGN": "#1a7f37", "BENIGN": "#1a7f37"}


def build_html(pe: ParsedEmail, auth: AuthResult, v: Verdict, enr: Enrichment) -> str:
    e = html.escape
    ioc = _iocs(pe)
    rows = ""
    for i in sorted(v.indicators, key=lambda x: _SEV_ORDER.get(x.severity, 9)):
        c = _SEV_COLOR.get(i.severity, "#444")
        rows += (f'<tr><td><span class="sev" style="background:{c}">{i.severity.upper()}</span></td>'
                 f'<td><b>{e(i.title)}</b><br><span class="muted">{e(i.detail)}</span></td>'
                 f'<td class="mono">{e(i.attack or "-")}</td></tr>')
    iocs = ""
    if ioc["sender_domain"]:
        iocs += f'<li>Sender domain: <code>{e(defang(ioc["sender_domain"]))}</code></li>'
    for u in ioc["urls"]:
        iocs += f'<li>URL: <code>{e(defang(u))}</code></li>'
    for fn, sha in ioc["attachments"]:
        iocs += f'<li>Attachment: <code>{e(fn)}</code> — sha256 <code>{e(sha)}</code></li>'
    recs = "".join(f"<li>{e(a)}</li>" for a in _recommendation(v))
    vc = _VERDICT_COLOR.get(v.label, "#444")
    enr_txt = (e(enr.skipped_reason) if not enr.enabled else
               ("no hits" if not enr.results else
                "<br>".join(f'{e(r.source)} <code>{e(defang(r.target))}</code> → '
                            f'{"malicious" if r.malicious else "suspicious" if r.suspicious else e(r.note or "clean")}'
                            for r in enr.results)))
    return f"""<!doctype html><html><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Phishing Triage - {e(v.label)}</title><style>
:root{{color-scheme:light}} body{{font:14px/1.5 -apple-system,Segoe UI,Roboto,sans-serif;
max-width:860px;margin:24px auto;padding:0 16px;color:#1f2328}}
h1{{font-size:20px;margin:0 0 4px}} .banner{{background:{vc};color:#fff;padding:14px 18px;border-radius:10px;margin-bottom:16px}}
.banner .score{{opacity:.9;font-size:13px}} h2{{font-size:15px;border-bottom:2px solid #2457a6;color:#2457a6;padding-bottom:3px;margin-top:22px}}
table{{border-collapse:collapse;width:100%}} td{{border-top:1px solid #e3e6ea;padding:8px;vertical-align:top}}
.sev{{color:#fff;border-radius:5px;padding:2px 7px;font-size:11px;font-weight:700;white-space:nowrap}}
.muted{{color:#5f6368}} .mono,code{{font-family:ui-monospace,Consolas,monospace;font-size:12px}}
code{{background:#f3f4f6;padding:1px 5px;border-radius:4px}} ul{{margin:6px 0;padding-left:20px}}
.kv li{{list-style:none;margin-left:-20px}}</style></head><body>
<div class="banner"><h1>Phishing Triage — {e(v.label)}</h1>
<div class="score">Risk score {v.score}/100 · {e(v.summary)}</div></div>
<h2>Email</h2><ul class="kv">
<li><b>From:</b> {e(pe.from_display)} &lt;{e(pe.from_addr or 'n/a')}&gt;</li>
{'<li><b>Reply-To:</b> '+e(pe.reply_to_addr)+'</li>' if pe.reply_to_addr else ''}
<li><b>Subject:</b> {e(pe.subject or '(none)')}</li>
<li><b>Reported SPF/DKIM/DMARC (unverified):</b> <code>{e(auth.spf or 'n/a')}</code> / <code>{e(auth.dkim or 'n/a')}</code> / <code>{e(auth.dmarc or 'n/a')}</code></li>
<li class="muted">{e(_AUTH_NOTICE)}</li>
</ul>
<h2>Indicators</h2><table>{rows or '<tr><td>No suspicious indicators detected.</td></tr>'}</table>
<h2>Indicators of Compromise (defanged)</h2><ul>{iocs or '<li>None extracted.</li>'}</ul>
<h2>Threat-intel enrichment</h2><p class="muted">{enr_txt}</p>
<h2>Recommended analyst actions</h2><ul>{recs}</ul>
<p class="muted">MITRE ATT&amp;CK: {e(', '.join(v.attack_techniques) or '-')}</p>
</body></html>"""
