# Phishing Triage Report - SUSPICIOUS
*Generated 2026-11-08 08:15 UTC by phishtriage*

**Verdict:** SUSPICIOUS  |  **Risk score:** 48/100

3 indicator(s) (2 medium, 1 low); risk score 48/100 -> SUSPICIOUS.

## Email
- **From:** Parcel Delivery <notice@deliveries-notice.com>
- **Reply-To:** support@parcel-support-team.net
- **Subject:** Your parcel could not be delivered - reschedule within 24 hours
- **Date:** Sat, 08 Nov 2026 06:30:00 +0000
- **Message-ID:** <trk7781@deliveries-notice.com>

## Authentication
- SPF: `pass`  |  DKIM: `pass`  |  DMARC: `pass`

## Indicators
| Severity | Finding | ATT&CK | Detail |
|---|---|---|---|
| MEDIUM | Reply-To redirects to a different domain | T1534 Internal Spearphishing | Replies would go to parcel-support-team.net, not the sender domain deliveries-notice.com - a common way to collect victim replies out of band. |
| MEDIUM | URL shortener hides the destination | T1566.002 Spearphishing Link | bit.ly - the true landing page is concealed until clicked. |
| LOW | Urgency / threat language | T1566 Phishing | Pressure to act fast is a core social-engineering tactic. |

## Indicators of Compromise (defanged)
- **Sender domain:** `deliveries-notice[.]com`
- **URL:** `hxxps://bit[.]ly/4a-reschedule`
- **Domain:** `bit[.]ly`

## Threat-intel enrichment
_Enrichment disabled (--no-enrich)._

## Recommended analyst actions
- Hold for analyst review; do not release to the user yet.
- Detonate links/attachments in a sandbox before any verdict.
- Confirm sender legitimacy out-of-band if it claims to be internal/a vendor.

**MITRE ATT&CK:** T1534 Internal Spearphishing, T1566.002 Spearphishing Link, T1566 Phishing
