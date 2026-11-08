"""Small domain/URL helpers used across the triage modules. Standard library only.

registered_domain() does public-suffix-aware extraction without the external
`tldextract` dependency, using a built-in shortlist of common multi-label
suffixes. It is good enough for triage (and documented as such); swap in
tldextract if you need the full Public Suffix List.
"""
from __future__ import annotations

import ipaddress
from urllib.parse import urlparse

# Common multi-label public suffixes. Not exhaustive - covers the ones that
# actually matter for look-alike checks on everyday phishing.
_MULTI_SUFFIXES = {
    "co.uk", "org.uk", "gov.uk", "ac.uk", "me.uk",
    "com.au", "net.au", "org.au", "edu.au", "gov.au",
    "co.nz", "co.jp", "co.in", "co.za", "com.br", "com.sg", "com.mx",
    "com.cn", "com.hk", "com.tr", "com.tw",
}


def registered_domain(host: str) -> str:
    """Return the registrable domain (eTLD+1) for a host or domain string."""
    host = (host or "").strip().lower().rstrip(".")
    if not host or "." not in host:
        return host
    # An IP literal is its own "domain" - never truncate it to the last two octets.
    try:
        ipaddress.ip_address(host)
        return host
    except ValueError:
        pass
    labels = host.split(".")
    last2 = ".".join(labels[-2:])
    last3 = ".".join(labels[-3:]) if len(labels) >= 3 else ""
    if last2 in _MULTI_SUFFIXES and len(labels) >= 3:
        return ".".join(labels[-3:])
    return last2 if not (last3 in _MULTI_SUFFIXES and len(labels) >= 4) else ".".join(labels[-4:])


def url_host(url: str) -> str:
    try:
        return (urlparse(url).hostname or "").lower()
    except ValueError:
        return ""


def defang(value: str) -> str:
    """Make a URL/domain safe to drop into a report or ticket (no live click)."""
    if not value:
        return value
    return (value.replace("http://", "hxxp://")
                 .replace("https://", "hxxps://")
                 .replace(".", "[.]"))
