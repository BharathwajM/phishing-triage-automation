# Phishing Triage Report - MALICIOUS
*Generated 2026-11-09 15:10 UTC by phishtriage*

**Verdict:** MALICIOUS  |  **Risk score:** 100/100

5 indicator(s) (2 high, 1 medium, 2 low); risk score 100/100 -> MALICIOUS.

## Email
- **From:** ` Microsoft 365 Support <no-reply@gmail.com> `
- **Reply-To:** ` helpdesk@0ffice365-login.com `
- **Subject:** ` [Action Required] Your Microsoft password expires today `
- **Date:** ` Wed, 05 Nov 2026 09:02:11 +0000 `
- **Message-ID:** ` <98fa12@gmail.com> `

## Authentication
- Reported results are unverified. Confirm them in trusted mail gateway logs.
- SPF: ` pass `  |  DKIM: ` pass `  |  DMARC: ` pass `

## Indicators
| Severity | Finding | ATT&CK | Detail |
|---|---|---|---|
| HIGH | Display name impersonates a brand | T1656 Impersonation | ` From shows "Microsoft 365 Support" but the real sending domain is gmail.com, not microsoft.com. ` |
| HIGH | Brand sent from a free webmail account | T1656 Impersonation | ` A message claiming to be microsoft was sent from a personal gmail.com address - brands do not send from free webmail. ` |
| MEDIUM | Credential-harvest lure with a link | T1566.002 Spearphishing Link | ` Asks the recipient to log in / verify via a link - classic credential theft. ` |
| LOW | Reply-To redirects to a different domain | T1566 Phishing | ` Replies would go to 0ffice365-login.com, not the sender domain gmail.com - a common way to collect victim replies out of band. ` |
| LOW | Urgency / threat language | T1566 Phishing | ` Pressure to act fast is a core social-engineering tactic. ` |

## Indicators of Compromise (defanged)
- **Sender domain:** ` gmail[.]com `
- **URL:** ` hxxps://0ffice365-login[.]com/owa/auth `
- **Domain:** ` 0ffice365-login[.]com `

## Threat-intel enrichment
_Live enrichment is off. Use --enrich to opt in._

## Recommended analyst actions
- Do not interact. Quarantine/delete from any inboxes that received it.
- Block the sender domain and all IOC domains/URLs at the mail gateway and proxy.
- Search mail logs for other recipients; pull the message org-wide.
- If links/attachments were opened, isolate the host and begin IR.

**MITRE ATT&CK:** T1656 Impersonation, T1566 Phishing, T1566.002 Spearphishing Link
