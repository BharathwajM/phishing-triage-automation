"""phishtriage - automated phishing email triage for SOC analysts.

Parses a suspicious .eml, checks sender authentication (SPF/DKIM/DMARC),
flags spoofing and look-alike domains, extracts and defangs URLs, hashes
attachments, scores the risk into a verdict, maps findings to MITRE ATT&CK,
and writes an analyst report. Pure standard library; optional threat-intel
enrichment activates only if an API key is configured.
"""
__version__ = "1.0.0"
