# Phishing Triage Report - SUSPICIOUS
*Generated 2026-11-08 09:42 UTC by phishtriage*

**Verdict:** SUSPICIOUS  |  **Risk score:** 48/100

3 indicator(s) (1 high, 2 low); risk score 48/100 -> SUSPICIOUS.

## Email
- **From:** ` Accounts Payable <billing@invoices-globex.com> `
- **Reply-To:** ` billing@invoices-globex.com `
- **Subject:** ` Overdue invoice #4471 - immediate payment required `
- **Date:** ` Thu, 06 Nov 2026 14:41:09 +0000 `
- **Message-ID:** ` <inv4471@invoices-globex.com> `

## Authentication
- Reported results are unverified. Confirm them in trusted mail gateway logs.
- SPF: ` softfail `  |  DKIM: ` none `  |  DMARC: ` none `

## Indicators
| Severity | Finding | ATT&CK | Detail |
|---|---|---|---|
| HIGH | Macro-enabled Office attachment | T1566.001 Spearphishing Attachment | ` Invoice_4471.docm (.docm) can carry auto-executing macros. ` |
| LOW | Urgency / threat language | T1566 Phishing | ` Pressure to act fast is a core social-engineering tactic. ` |
| LOW | Financial / payment lure | T1566 Phishing | ` Invoice, refund or payment themes are common pretexts. ` |

## Indicators of Compromise (defanged)
- **Sender domain:** ` invoices-globex[.]com `
- **Attachment:** ` Invoice_4471.docm ` — sha256 `9bb9673e635e72b6e9f28aada43d8031b86598339ce0e80f91c5fdaf083dec04`

## Threat-intel enrichment
_Live enrichment is off. Use --enrich to opt in._

## Recommended analyst actions
- Hold for analyst review; do not release to the user yet.
- Detonate links/attachments in a sandbox before any verdict.
- Confirm sender legitimacy out-of-band if it claims to be internal/a vendor.

**MITRE ATT&CK:** T1566.001 Spearphishing Attachment, T1566 Phishing
