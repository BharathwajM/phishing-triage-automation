# Phishing Triage Automation

[![Tests](https://github.com/BharathwajM/phishing-triage-automation/actions/workflows/tests.yml/badge.svg)](https://github.com/BharathwajM/phishing-triage-automation/actions/workflows/tests.yml)

A command-line tool that does a SOC analyst's **first-pass triage of a suspicious email** automatically. Point it at a `.eml` file and it parses the headers, extracts reported sender authentication results, hunts for the tells of a phish, scores the risk, maps the findings to MITRE ATT&CK, and writes an analyst-ready report with a verdict and recommended actions.

Reported phishing is one of the most common tickets in a SOC queue. The tool handles the repetitive steps (extracting indicators, checking them, scoring and writing the report), which leaves the analyst to make the final call.

**Uses only the Python standard library, so there is nothing to install.** The default run is offline, even when VirusTotal or URLhaus API keys are set.

```
$ python -m phishtriage samples/
[x] MALICIOUS       93/100  ato_refund_scam.eml  (4 indicators)
[!] SUSPICIOUS      48/100  invoice_macro.eml  (3 indicators)
[.] BENIGN           0/100  legit_github_notification.eml  (0 indicators)
[.] BENIGN           0/100  legit_internal_hr.eml  (0 indicators)
[x] MALICIOUS      100/100  microsoft365_password.eml  (5 indicators)
[!] SUSPICIOUS      36/100  parcel_reschedule.eml  (3 indicators)
[x] MALICIOUS      100/100  paypal_credphish.eml  (8 indicators)

7 triaged · 3 malicious · 2 suspicious · reports in reports/
```

The seven synthetic samples include two benign controls. The macro invoice is marked suspicious so an analyst can review it. The sample outcomes demonstrate the rules against known inputs.

---

## What it checks

| Category | Examples of what it catches | ATT&CK |
|---|---|---|
| **Sender headers** | Return-Path domain differs from From; reported SPF, DKIM, and DMARC results shown separately | T1566 |
| **Identity spoofing** | display name impersonates a brand, including names disguised with look-alike Unicode letters (`Chаse` with a Cyrillic `а`); a brand "sent" from free webmail | T1656 Impersonation |
| **Look-alike domains** | typo-squats and **homoglyphs** (`paypa1-secure.com`, `0ffice365-login.com`) | T1583.001 |
| **Reply-To redirection** | replies routed to a different domain to collect victims out of band | T1566 |
| **Malicious links** | raw-IP URLs, `@` in the authority, URL shorteners, brand buried in an unrelated domain, high-abuse TLDs, **link text that lies about its destination** | T1566.002 |
| **Phishing page hosting** | links to IPFS gateways and free developer hosting (`*.pages.dev`, `*.r2.dev`, `*.vercel.app`) | T1583.006 |
| **Dangerous attachments** | executables, macro-enabled Office docs, archives, **HTML attachments** (fake login pages, HTML smuggling), **double extensions** (`invoice.pdf.exe`) | T1566.001 / T1036.007 |
| **Social-engineering lures** | urgency/threat language, credential-harvest asks, payment/refund pretexts | T1566 |

Each finding carries a severity and the score sums them. One critical finding is enough for MALICIOUS, and one high finding is enough for SUSPICIOUS. The report lists every finding and its weight, so you can see **why** a verdict was reached.

## Accuracy on public email corpora

The bundled samples are synthetic, so I also measured the tool on real email: 884 phishing messages from 2024 and 2025 and 2,750 legitimate messages. I tuned the rules on a development set, then ran a held-out test set once.

| Set | Phishing flagged | Legitimate flagged (false alarms) |
|---|---|---|
| Dev, before changes | 22.6% (91 of 403) | 18.2% (455 of 2,500) |
| Dev, after changes | **41.9%** (169 of 403) | **0.3%** (8 of 2,500) |
| Test, before changes | 19.1% (92 of 481) | 20.4% (51 of 250) |
| Test, after changes | **29.3%** (141 of 481) | **15.6%** (39 of 250) |

"Flagged" means a SUSPICIOUS or MALICIOUS verdict. The test set's legitimate mail is the harder half of the corpus, and most of its false alarms came from one rule: newsletters and vendors with a brand word in their own domain, such as an Apple newsletter on `applecore.lockergnome.com`. The tool still misses most phishing that has no link, attachment or sender tell to score, so it is a first-pass triage aid and not a filter. Method, data sources and limitations are in [`eval/`](eval/README.md).

## Usage

```bash
python -m phishtriage SUSPICIOUS.eml                 # one email
python -m phishtriage samples/                       # a whole folder
python -m phishtriage --json samples/paypal_credphish.eml   # machine-readable
python -m phishtriage --format html --out reports samples/  # HTML reports
```

Each email produces a Markdown **and** an HTML report (see [`reports/`](reports/) for the bundled samples' output). IOCs in the report are **defanged** (`hxxps://`, `[.]`). Email-controlled text is rendered literally in Markdown and escaped in HTML.

Authentication claims in an `.eml` are **unverified** and do not contribute to the score. Check them in trusted gateway logs before using them in a triage decision. A low score means the tool found few or no matching indicators. Confirm message context before release.

### Optional enrichment

Set a key and pass `--enrich` to run live reputation lookups.

```bash
export VT_API_KEY=...        # VirusTotal: attachment SHA-256 reputation
export URLHAUS_API_KEY=...   # abuse.ch URLhaus: known-malware URLs
pip install requests         # only needed for enrichment
python -m phishtriage --enrich samples/
```

With `--enrich`, URLhaus receives full extracted URLs, including query parameters. VirusTotal receives attachment SHA-256 hashes. Use the default offline mode or pass `--no-enrich` when these indicators need to stay local.

## How it's built

```
phishtriage/
  parser.py       .eml -> headers, identities, auth headers, body, URLs, attachments
  auth.py         reported SPF / DKIM / DMARC + sender domain comparison
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

Tests cover sample verdicts, the newer detectors, the false-positive fixes from the accuracy test, forged authentication claims, email markup in reports, and the CLI's offline default with API keys present.

---

*Part of my security portfolio. See also: [Splunk BOTS v3 breach investigation](https://github.com/BharathwajM/splunk-bots-v3-investigation) · [SOC monitoring lab (Sentinel)](https://github.com/BharathwajM/soc-portfolio-lab) · [AD attack & detection lab (Splunk)](https://github.com/BharathwajM/ad-attack-detection-lab) · [Essential Eight hardening lab (PowerShell)](https://github.com/BharathwajM/essential-eight-lab). All sample emails are synthetic; no real malware or live payloads are included.*
