# Phishing Triage Report - MALICIOUS
*Generated 2026-11-08 08:15 UTC by phishtriage*

**Verdict:** MALICIOUS  |  **Risk score:** 100/100

10 indicator(s) (2 critical, 5 high, 2 medium, 1 low); risk score 100/100 -> MALICIOUS.

## Email
- **From:** PayPal Service <service@paypa1-secure.com>
- **Reply-To:** recover@mail-paypai.ru
- **Subject:** Your account has been limited - action required within 24 hours
- **Date:** Tue, 04 Nov 2026 03:14:22 +0000
- **Message-ID:** <a71c9f2e@paypa1-secure.com>

## Authentication
- SPF: `fail`  |  DKIM: `none`  |  DMARC: `fail`

## Indicators
| Severity | Finding | ATT&CK | Detail |
|---|---|---|---|
| CRITICAL | Sender domain looks like a known brand | T1583.001 Domain Registration | Sending domain paypa1-secure.com imitates paypal (real domain paypal.com). |
| CRITICAL | Link domain imitates a brand | T1583.001 Domain Registration | verify-id.ru imitates paypal (real domain paypal.com). |
| HIGH | Sender authentication failed | T1566.002 Spearphishing Link / T1534 | The receiving server could not verify the sender: SPF=fail, DKIM=none, DMARC=fail. A legitimate bulk sender almost always passes SPF, DKIM and DMARC. |
| HIGH | Display name impersonates a brand | T1656 Impersonation | From shows "PayPal Service" but the real sending domain is paypa1-secure.com, not paypal.com. |
| HIGH | Link text hides its real destination | T1566.002 Spearphishing Link | A link displayed as "https://www.paypal.com/signin" actually points to 198.51.100.23. |
| HIGH | Brand name buried in an unrelated domain | T1566.002 Spearphishing Link | "paypal" appears in account-paypal.verify-id.ru, but the real domain is verify-id.ru. |
| HIGH | Link points to a raw IP address | T1566.002 Spearphishing Link | 198.51.100.23 - legitimate brands use named domains, not bare IPs. |
| MEDIUM | Reply-To redirects to a different domain | T1534 Internal Spearphishing | Replies would go to mail-paypai.ru, not the sender domain paypa1-secure.com - a common way to collect victim replies out of band. |
| MEDIUM | Credential-harvest lure with a link | T1566.002 Spearphishing Link | Asks the recipient to log in / verify via a link - classic credential theft. |
| LOW | Urgency / threat language | T1566 Phishing | Pressure to act fast is a core social-engineering tactic. |

## Indicators of Compromise (defanged)
- **Sender domain:** `paypa1-secure[.]com`
- **URL:** `hxxp://account-paypal[.]verify-id[.]ru/login`
- **URL:** `hxxp://198[.]51[.]100[.]23/ppl/secure`
- **Domain:** `198[.]51[.]100[.]23`
- **Domain:** `verify-id[.]ru`

## Threat-intel enrichment
_Enrichment disabled (--no-enrich)._

## Recommended analyst actions
- Do not interact. Quarantine/delete from any inboxes that received it.
- Block the sender domain and all IOC domains/URLs at the mail gateway and proxy.
- Search mail logs for other recipients; pull the message org-wide.
- If links/attachments were opened, isolate the host and begin IR.

**MITRE ATT&CK:** T1566.002 Spearphishing Link / T1534, T1656 Impersonation, T1534 Internal Spearphishing, T1583.001 Domain Registration, T1566.002 Spearphishing Link, T1566 Phishing
