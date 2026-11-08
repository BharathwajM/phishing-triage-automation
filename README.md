# Phishing Triage Automation

A command-line tool that does a SOC analyst's **first-pass triage of a suspicious email** automatically. Point it at a `.eml` file and it parses the headers, checks sender authentication, hunts for the tells of a phish, scores the risk, maps the findings to MITRE ATT&CK, and writes an analyst-ready report with a verdict and recommended actions.

Triaging reported phishing is one of the highest-volume jobs in a SOC. This tool does the repetitive part — extract, analyse, score, document — so the analyst spends their time on the judgement call, not the copy-paste.

**Pure Python standard library — clone and run, nothing to install.** Live threat-intel enrichment (VirusTotal, abuse.ch) is optional and switches on only if you add an API key.

```
$ python -m phishtriage samples/
[x] MALICIOUS      100/100  ato_refund_scam.eml  (6 indicators)
[x] MALICIOUS       80/100  invoice_macro.eml  (4 indicators)
[.] BENIGN           0/100  legit_github_notification.eml  (0 indicators)
[.] BENIGN           0/100  legit_internal_hr.eml  (0 indicators)
[x] MALICIOUS      100/100  microsoft365_password.eml  (5 indicators)
[!] SUSPICIOUS      48/100  parcel_reschedule.eml  (3 indicators)
[x] MALICIOUS      100/100  paypal_credphish.eml  (10 indicators)

7 triaged · 4 malicious · 1 suspicious · reports in reports/
```

The bundled samples include two **legitimate emails as negative controls** — the tool leaves them BENIGN, which is as important as catching the phish.

---

## What it checks

| Category | Examples of what it catches | ATT&CK |
|---|---|---|
| **Sender authentication** | SPF / DKIM / DMARC fail or missing; Return-Path not aligned with From | T1566 |
| **Identity spoofing** | display name impersonates a brand; a brand "sent" from free webmail | T1656 Impersonation |
| **Look-alike domains** | typo-squats and **homoglyphs** (`paypa1-secure.com`, `0ffice365-login.com`) | T1583.001 |
| **Reply-To redirection** | replies routed to a different domain to collect victims out of band | T1534 |
| **Malicious links** | raw-IP URLs, `@` in the authority, URL shorteners, brand buried in an unrelated domain, high-abuse TLDs, **link text that lies about its destination** | T1566.002 |
| **Dangerous attachments** | executables, macro-enabled Office docs, archives, **double extensions** (`invoice.pdf.exe`) | T1566.001 / T1036.007 |
| **Social-engineering lures** | urgency/threat language, credential-harvest asks, payment/refund pretexts | T1566 |

Each finding carries a severity; the score sums them (a single critical finding alone is enough for MALICIOUS). The weighting is deliberately transparent — the report shows exactly **why** a verdict was reached.

## Usage

```bash
python -m phishtriage SUSPICIOUS.eml                 # one email
python -m phishtriage samples/                       # a whole folder
python -m phishtriage --json samples/paypal_credphish.eml   # machine-readable
python -m phishtriage --format html --out reports samples/  # HTML reports
```

Each email produces a Markdown **and** an HTML report (see [`reports/`](reports/) for the bundled samples' output). IOCs in the report are **defanged** (`hxxps://`, `[.]`) so it is safe to paste into a ticket.

### Optional enrichment

Set either key and the tool adds live reputation lookups (it still works fully without them):

```bash
export VT_API_KEY=...        # VirusTotal: URL / domain / file-hash reputation
export URLHAUS_API_KEY=...   # abuse.ch URLhaus: known-malware URLs
pip install requests         # only needed for enrichment
```

## How it's built

```
phishtriage/
  parser.py       .eml -> headers, identities, auth headers, body, URLs, attachments
  auth.py         SPF / DKIM / DMARC results + alignment checks
  indicators.py   the detection logic (spoofing, look-alikes, URLs, attachments, lures)
  scoring.py      weighted indicators -> risk score + verdict + ATT&CK roll-up
  enrich.py       optional VirusTotal / URLhaus enrichment (graceful if no key)
  report.py       Markdown + standalone HTML analyst reports
  cli.py          batch triage of files/folders
```

## Tests

```bash
python -m unittest discover -s tests -v
```

The suite asserts that every phishing sample is flagged, the borderline one lands SUSPICIOUS, and the legitimate controls are **not** flagged — so a change that breaks detection, or that starts crying wolf on clean mail, fails the build.

---

*Part of my security portfolio, alongside an [AD attack & detection lab](https://github.com/BharathwajM/ad-attack-detection-lab) and a [SOC monitoring lab](https://github.com/BharathwajM/soc-portfolio-lab). All sample emails are synthetic; no real malware or live payloads are included.*
