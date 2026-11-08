# Phishing Triage Report - MALICIOUS
*Generated 2026-11-08 09:42 UTC by phishtriage*

**Verdict:** MALICIOUS  |  **Risk score:** 100/100

5 indicator(s) (2 critical, 1 high, 2 low); risk score 100/100 -> MALICIOUS.

## Email
- **From:** ` Australian Taxation Office <refunds@ato-myrefund.net> `
- **Reply-To:** ` refunds@ato-myrefund.net `
- **Subject:** ` You have a pending tax refund of $1,284.50 - confirm your details `
- **Date:** ` Fri, 07 Nov 2026 22:10:55 +1100 `
- **Message-ID:** ` <refund9981@ato-myrefund.net> `

## Authentication
- Reported results are unverified. Confirm them in trusted mail gateway logs.
- SPF: ` fail `  |  DKIM: ` fail `  |  DMARC: ` fail `

## Indicators
| Severity | Finding | ATT&CK | Detail |
|---|---|---|---|
| CRITICAL | Sender domain looks like a known brand | T1583.001 Domain Registration | ` Sending domain ato-myrefund.net imitates ato (real domain ato.gov.au). ` |
| CRITICAL | Link domain imitates a brand | T1583.001 Domain Registration | ` ato-myrefund.net imitates ato (real domain ato.gov.au). ` |
| HIGH | Brand name buried in an unrelated domain | T1566.002 Spearphishing Link | ` "ato" appears in my-gov.ato-myrefund.net, but the real domain is ato-myrefund.net. ` |
| LOW | Urgency / threat language | T1566 Phishing | ` Pressure to act fast is a core social-engineering tactic. ` |
| LOW | Financial / payment lure | T1566 Phishing | ` Invoice, refund or payment themes are common pretexts. ` |

## Indicators of Compromise (defanged)
- **Sender domain:** ` ato-myrefund[.]net `
- **URL:** ` hxxp://my-gov[.]ato-myrefund[.]net/refund/claim `
- **Domain:** ` ato-myrefund[.]net `

## Threat-intel enrichment
_Enrichment disabled (--no-enrich)._

## Recommended analyst actions
- Do not interact. Quarantine/delete from any inboxes that received it.
- Block the sender domain and all IOC domains/URLs at the mail gateway and proxy.
- Search mail logs for other recipients; pull the message org-wide.
- If links/attachments were opened, isolate the host and begin IR.

**MITRE ATT&CK:** T1583.001 Domain Registration, T1566.002 Spearphishing Link, T1566 Phishing
