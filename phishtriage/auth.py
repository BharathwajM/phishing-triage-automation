"""Parse sender-authentication results (SPF / DKIM / DMARC) from the headers
a receiving mail server stamps on. These are the first thing a SOC analyst
reads on a suspicious email: did it really come from where it claims?"""
from __future__ import annotations

import re
from dataclasses import dataclass

from .parser import ParsedEmail
from .utils import registered_domain

# e.g.  spf=pass  dkim=fail  dmarc=none  (header values vary by provider)
_RESULT_RE = {
    "spf": re.compile(r"\bspf=(\w+)", re.IGNORECASE),
    "dkim": re.compile(r"\bdkim=(\w+)", re.IGNORECASE),
    "dmarc": re.compile(r"\bdmarc=(\w+)", re.IGNORECASE),
}

# How each mechanism's result maps to concern. "pass" is good; everything
# else ranges from unknown to outright failure.
_BAD = {"fail", "softfail", "permerror", "temperror", "none", "neutral"}


@dataclass
class AuthResult:
    spf: str
    dkim: str
    dmarc: str
    from_domain: str
    notes: list[str]

    def failing(self) -> list[str]:
        out = []
        for name, val in (("SPF", self.spf), ("DKIM", self.dkim), ("DMARC", self.dmarc)):
            if val and val.lower() in _BAD:
                out.append(f"{name}={val}")
        return out


def analyze_auth(pe: ParsedEmail) -> AuthResult:
    blob = " ".join([pe.auth_results_raw, pe.received_spf_raw])
    results = {}
    for mech, rx in _RESULT_RE.items():
        m = rx.search(blob)
        results[mech] = (m.group(1).lower() if m else "")

    notes: list[str] = []
    if not blob.strip():
        notes.append("No Authentication-Results header present - cannot confirm sender authenticity.")

    # DMARC alignment: the visible From domain should align with the authenticated domain.
    from_dom = registered_domain(pe.domain_of(pe.from_addr))
    rp_dom = registered_domain(pe.domain_of(pe.return_path_addr))
    if from_dom and rp_dom and from_dom != rp_dom:
        notes.append(f"Return-Path domain ({rp_dom}) does not align with From domain ({from_dom}).")

    return AuthResult(
        spf=results["spf"], dkim=results["dkim"], dmarc=results["dmarc"],
        from_domain=from_dom, notes=notes,
    )
