"""Extract authentication claims from an .eml without trusting its headers.

A raw message alone cannot establish who inserted an authentication result.
The reports show those claims for an analyst to check against gateway logs.
"""
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

@dataclass
class AuthResult:
    spf: str
    dkim: str
    dmarc: str
    from_domain: str
    notes: list[str]


def analyze_auth(pe: ParsedEmail) -> AuthResult:
    blob = " ".join([pe.auth_results_raw, pe.received_spf_raw])
    results = {}
    for mech, rx in _RESULT_RE.items():
        m = rx.search(blob)
        results[mech] = (m.group(1).lower() if m else "")

    notes: list[str] = []
    # Compare visible header domains separately from the reported authentication claims.
    from_dom = registered_domain(pe.domain_of(pe.from_addr))
    rp_dom = registered_domain(pe.domain_of(pe.return_path_addr))
    if from_dom and rp_dom and from_dom != rp_dom:
        notes.append(f"Return-Path domain ({rp_dom}) differs from From domain ({from_dom}).")

    return AuthResult(
        spf=results["spf"], dkim=results["dkim"], dmarc=results["dmarc"],
        from_domain=from_dom, notes=notes,
    )
