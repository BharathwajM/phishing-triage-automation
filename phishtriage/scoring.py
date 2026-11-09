"""Turn the list of indicators into a single risk score (0-100) and a verdict,
and roll up the distinct MITRE ATT&CK techniques seen. The weighting is
transparent on purpose - an analyst can read exactly why a verdict was reached."""
from __future__ import annotations

from dataclasses import dataclass

from .indicators import Indicator, SEVERITY_POINTS

# Score bands -> verdict. A single critical indicator alone is enough to land
# in MALICIOUS, and a single high one (32 points) in SUSPICIOUS so an analyst
# reviews it. Lower bands are reached by accumulation.
VERDICT_BANDS = [
    (70, "MALICIOUS"),
    (30, "SUSPICIOUS"),
    (1, "LIKELY BENIGN"),
    (0, "BENIGN"),
]


@dataclass
class Verdict:
    score: int
    label: str
    indicators: list[Indicator]
    attack_techniques: list[str]
    summary: str


def score(indicators: list[Indicator]) -> Verdict:
    raw = sum(SEVERITY_POINTS.get(i.severity, 0) for i in indicators)
    total = min(100, raw)

    # A critical finding forces at least MALICIOUS regardless of the additive total.
    has_critical = any(i.severity == "critical" for i in indicators)
    if has_critical:
        total = max(total, 75)

    label = next(v for threshold, v in VERDICT_BANDS if total >= threshold)

    techniques: list[str] = []
    for i in indicators:
        if i.attack and i.attack not in techniques:
            techniques.append(i.attack)

    by_sev = {}
    for i in indicators:
        by_sev[i.severity] = by_sev.get(i.severity, 0) + 1
    counts = ", ".join(f"{n} {sev}" for sev, n in
                       sorted(by_sev.items(), key=lambda kv: -SEVERITY_POINTS.get(kv[0], 0)))
    summary = (f"{len(indicators)} indicator(s) ({counts or 'none'}); "
               f"risk score {total}/100 -> {label}.")

    return Verdict(score=total, label=label, indicators=indicators,
                   attack_techniques=techniques, summary=summary)
