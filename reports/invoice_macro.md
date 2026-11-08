# Phishing Triage Report - MALICIOUS
*Generated 2026-11-08 08:15 UTC by phishtriage*

**Verdict:** MALICIOUS  |  **Risk score:** 80/100

4 indicator(s) (2 high, 2 low); risk score 80/100 -> MALICIOUS.

## Email
- **From:** Accounts Payable <billing@invoices-globex.com>
- **Reply-To:** billing@invoices-globex.com
- **Subject:** Overdue invoice #4471 - immediate payment required
- **Date:** Thu, 06 Nov 2026 14:41:09 +0000
- **Message-ID:** <inv4471@invoices-globex.com>

## Authentication
- SPF: `softfail`  |  DKIM: `none`  |  DMARC: `none`

## Indicators
| Severity | Finding | ATT&CK | Detail |
|---|---|---|---|
| HIGH | Sender authentication failed | T1566.002 Spearphishing Link / T1534 | The receiving server could not verify the sender: SPF=softfail, DKIM=none, DMARC=none. A legitimate bulk sender almost always passes SPF, DKIM and DMARC. |
| HIGH | Macro-enabled Office attachment | T1566.001 Spearphishing Attachment | Invoice_4471.docm (.docm) can carry auto-executing macros. |
| LOW | Urgency / threat language | T1566 Phishing | Pressure to act fast is a core social-engineering tactic. |
| LOW | Financial / payment lure | T1566 Phishing | Invoice, refund or payment themes are common pretexts. |

## Indicators of Compromise (defanged)
- **Sender domain:** `invoices-globex[.]com`
- **Attachment:** `Invoice_4471.docm` — sha256 `9bb9673e635e72b6e9f28aada43d8031b86598339ce0e80f91c5fdaf083dec04`

## Threat-intel enrichment
_Enrichment disabled (--no-enrich)._

## Recommended analyst actions
- Do not interact. Quarantine/delete from any inboxes that received it.
- Block the sender domain and all IOC domains/URLs at the mail gateway and proxy.
- Search mail logs for other recipients; pull the message org-wide.
- If links/attachments were opened, isolate the host and begin IR.

**MITRE ATT&CK:** T1566.002 Spearphishing Link / T1534, T1566.001 Spearphishing Attachment, T1566 Phishing
