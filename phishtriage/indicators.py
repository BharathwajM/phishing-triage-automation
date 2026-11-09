"""Detection logic: turn a parsed email into a list of weighted indicators.

Each indicator is an observation an analyst would make by hand - sender
spoofing, a look-alike domain, a link whose text lies about its target, a
dangerous attachment, a credential-harvest lure - with a severity and the
MITRE ATT&CK technique it maps to. scoring.py turns these into a verdict.
"""
from __future__ import annotations

import difflib
import re
import unicodedata
from dataclasses import dataclass

from .auth import AuthResult
from .parser import ParsedEmail
from .utils import registered_domain, url_host

# Severity -> points. Scoring sums these (capped) to a 0-100 risk score.
SEVERITY_POINTS = {"info": 0, "low": 8, "medium": 20, "high": 32, "critical": 45}


@dataclass
class Indicator:
    id: str
    title: str
    severity: str          # info | low | medium | high | critical
    detail: str
    attack: str = ""       # MITRE ATT&CK technique id/name
    evidence: str = ""


# Brands attackers impersonate most, with their real registrable domains.
BRANDS = {
    "microsoft": "microsoft.com", "office365": "microsoft.com", "outlook": "microsoft.com",
    "paypal": "paypal.com", "apple": "apple.com", "icloud": "apple.com",
    "amazon": "amazon.com", "google": "google.com", "netflix": "netflix.com",
    "docusign": "docusign.com", "dropbox": "dropbox.com", "linkedin": "linkedin.com",
    "facebook": "facebook.com", "instagram": "instagram.com", "adobe": "adobe.com",
    "chase": "chase.com", "wellsfargo": "wellsfargo.com", "bankofamerica": "bankofamerica.com",
    "fedex": "fedex.com", "ups": "ups.com", "dhl": "dhl.com", "auspost": "auspost.com.au",
    "ato": "ato.gov.au", "mygov": "my.gov.au", "commbank": "commbank.com.au",
}
FREEMAIL = {"gmail.com", "outlook.com", "hotmail.com", "yahoo.com", "icloud.com",
            "aol.com", "proton.me", "protonmail.com", "mail.com", "gmx.com"}
SHORTENERS = {"bit.ly", "tinyurl.com", "goo.gl", "t.co", "ow.ly", "is.gd",
              "buff.ly", "rebrand.ly", "cutt.ly", "shorturl.at", "rb.gy"}
RISKY_TLDS = {"zip", "mov", "top", "xyz", "gq", "tk", "ml", "cf", "ga", "country",
              "click", "link", "work", "fit", "review", "kim", "men", "loan"}
DANGEROUS_EXT = {"exe", "scr", "pif", "com", "bat", "cmd", "js", "jse", "vbs",
                 "vbe", "wsf", "hta", "ps1", "jar", "msi", "iso", "img", "lnk"}
MACRO_EXT = {"docm", "xlsm", "pptm", "dotm", "xlam", "xll"}
ARCHIVE_EXT = {"zip", "rar", "7z", "gz", "tar", "iso", "img"}
# HTML-type attachments open a local web page, often a fake login form (HTML smuggling).
HTML_EXT = {"html", "htm", "shtml", "xhtml", "svg", "mht", "mhtml"}
# IPFS gateways: content is hard to take down and almost never linked from business email.
IPFS_HOSTS = {"ipfs.io", "dweb.link", "cloudflare-ipfs.com", "w3s.link", "nftstorage.link"}
# Free developer hosting with instant HTTPS subdomains, heavily abused for phishing pages.
FREE_HOSTING = {"r2.dev", "workers.dev", "pages.dev", "vercel.app", "glitch.me", "on-fleek.app",
                "netlify.app", "web.app", "firebaseapp.com", "000webhostapp.com"}

_URGENCY = re.compile(r"\b(urgent|immediately|within 24 hours|action required|final notice|"
                      r"suspend(ed|ing)?|deactivat(e|ed)|verify (your|now)|confirm your|"
                      r"unusual (activity|sign.?in)|account (locked|limited|on hold)|"
                      r"password (expir|reset)|re-?authenticate|avoid (suspension|closure))\b",
                      re.IGNORECASE)
_CRED = re.compile(r"\b(log ?in|sign ?in|verify your (account|identity)|update your (details|password)|"
                   r"confirm your (password|credentials)|enter your (password|pin))\b", re.IGNORECASE)
_PAYMENT = re.compile(r"\b(invoice|payment|wire transfer|bank details|gift card|bitcoin|"
                      r"outstanding balance|refund|tax (refund|return)|overdue)\b", re.IGNORECASE)


# Characters attackers swap in to fake a brand name while staying registrable.
_HOMOGLYPHS = str.maketrans({"0": "o", "1": "l", "3": "e", "4": "a", "5": "s",
                             "7": "t", "9": "g", "$": "s", "@": "a"})


# Cyrillic and Greek letters that look like Latin ones ("Chаse" with a Cyrillic "а").
_CONFUSABLES = str.maketrans({
    "а": "a", "в": "b", "с": "c", "ԁ": "d", "е": "e", "һ": "h", "і": "i", "ј": "j", "к": "k",
    "ӏ": "l", "м": "m", "н": "h", "о": "o", "р": "p", "ԛ": "q", "ѕ": "s", "т": "t", "υ": "u",
    "ѵ": "v", "ԝ": "w", "х": "x", "у": "y", "α": "a", "β": "b", "ε": "e", "ι": "i", "κ": "k",
    "ν": "v", "ο": "o", "ρ": "p", "τ": "t", "χ": "x", "γ": "y",
})
# Invisible characters inserted to break up a brand name ("Pay​Pal").
_INVISIBLE = dict.fromkeys(map(ord, "­͏​‌‍⁠﻿"))


def _fold_lookalikes(text: str) -> str:
    """Map full-width forms, look-alike letters and invisible characters to plain Latin text."""
    return unicodedata.normalize("NFKC", text).translate(_INVISIBLE).lower().translate(_CONFUSABLES)


def _normalize(token: str) -> str:
    """Fold common homoglyphs so paypa1 -> paypal, g00gle -> google, etc."""
    return token.translate(_HOMOGLYPHS).replace("rn", "m").replace("vv", "w")


def _labels(host: str) -> list[str]:
    """Whole-word tokens of a host name: groups.msn.com -> ["groups", "msn", "com"]."""
    return host.lower().replace("-", ".").split(".")


def _brand_in(text: str, brand: str) -> bool:
    """Brand name inside a host or display name.

    Short names (ups, ato, dhl) must be a whole word, or "ups" would match groups.google.com.
    Longer names only need to start a word, so "Microsoft365 Support" and
    microsoftonline-verify.com still match."""
    tail = r"\b" if len(brand) < 5 else ""
    return re.search(rf"\b{re.escape(brand)}{tail}", text.replace("-", " ")) is not None


def _is_official(host: str, official: str) -> bool:
    return host == official or host.endswith("." + official)


def _looks_like_brand(domain: str, include_labels: bool = True) -> tuple[str, str] | None:
    """Return (brand, official_domain) if `domain` impersonates a brand, else None.

    include_labels=False skips the "brand is a whole label" case, so link checks do not
    double-count what URL_SUBDOMAIN_BRAND already reports."""
    reg = registered_domain(domain)
    if not reg:
        return None
    # tokens from the registrable label (paypa1-secure -> ["paypa1","secure"])
    core = reg.split(".")[0]
    tokens = core.split("-")
    norm_tokens = [_normalize(t) for t in tokens]
    all_labels = _labels(domain)
    for brand, official in BRANDS.items():
        if reg == official or _is_official(domain, official):
            return None  # it IS the brand (or a real subdomain of it)
        # brand name appears as a whole label but the domain is not the official one
        if include_labels and brand in all_labels:
            return (brand, official)
        # homoglyph / typo-squat on any token of the registrable label
        for tok, ntok in zip(tokens, norm_tokens):
            if ntok == brand and tok != brand:
                return (brand, official)
            # Fuzzy matching on short names (ups, ato) matches ordinary words, so skip it.
            if (len(brand) >= 5 and ntok != brand
                    and difflib.SequenceMatcher(None, ntok, brand).ratio() >= 0.85):
                return (brand, official)
    return None


def collect_indicators(pe: ParsedEmail, auth: AuthResult) -> list[Indicator]:
    ind: list[Indicator] = []
    from_dom = pe.domain_of(pe.from_addr)
    from_reg = registered_domain(from_dom)

    # Score visible header discrepancies. Authentication claims are report-only.
    # Low weight: mailing lists and bulk-mail services use a separate bounce domain all the time.
    for n in auth.notes:
        ind.append(Indicator("AUTH_NOTE", "Return-Path domain differs from From", "low", n,
                             "T1585 Establish Accounts"))

    # --- Display-name / identity spoofing ---
    # Check every brand in the name, not just the first: "Chase Bank (via Google Drive)" is sent
    # by google.com, so Google is genuine there but Chase is not.
    named = [b for b in BRANDS if _brand_in(_fold_lookalikes(pe.from_display), b)]
    disguised = next((b for b in named if not _brand_in(pe.from_display.lower(), b)), None)
    if disguised:
        # The brand only appears once look-alike letters are folded: a deliberate disguise.
        ind.append(Indicator(
            "DISPLAY_HOMOGLYPH", "Brand name in the display name uses look-alike characters", "high",
            f'"{pe.from_display}" spells {disguised} with look-alike or invisible characters, '
            "which no real company does.",
            "T1656 Impersonation", evidence=pe.from_display.encode("unicode_escape").decode("ascii")[:200]))
    brand_in_name = next((b for b in named if from_reg != BRANDS[b]), None)
    if brand_in_name and registered_domain(from_dom) != BRANDS[brand_in_name]:
        ind.append(Indicator(
            "DISPLAY_SPOOF", "Display name impersonates a brand", "high",
            f'From shows "{pe.from_display}" but the real sending domain is '
            f'{from_reg or "(none)"}, not {BRANDS[brand_in_name]}.',
            "T1656 Impersonation", evidence=pe.headers.get("From", "")))
    if from_reg in FREEMAIL and pe.from_display and brand_in_name:
        ind.append(Indicator(
            "FREEMAIL_BRAND", "Brand sent from a free webmail account", "high",
            f"A message claiming to be {brand_in_name} was sent from a personal "
            f"{from_reg} address - brands do not send from free webmail.",
            "T1656 Impersonation"))

    # --- Reply-To / Return-Path redirection ---
    if pe.reply_to_addr:
        rt = registered_domain(pe.domain_of(pe.reply_to_addr))
        if rt and from_reg and rt != from_reg:
            # Mailing lists set Reply-To to the list, so only a free-webmail Reply-To scores high.
            ind.append(Indicator(
                "REPLYTO_MISMATCH", "Reply-To redirects to a different domain",
                "medium" if rt in FREEMAIL else "low",
                f"Replies would go to {rt}, not the sender domain {from_reg} - a common "
                "way to collect victim replies out of band.",
                "T1566 Phishing", evidence=pe.reply_to_addr))

    # --- Look-alike / typo-squat sender ---
    lk = _looks_like_brand(from_dom)
    if lk:
        ind.append(Indicator(
            "LOOKALIKE_SENDER", "Sender domain looks like a known brand", "critical",
            f"Sending domain {from_reg} imitates {lk[0]} (real domain {lk[1]}).",
            "T1583.001 Domain Registration", evidence=from_dom))

    # --- URL analysis ---
    html_links = getattr(pe, "html_links", [])
    for href, text in html_links:
        th = url_host(text) if text and "." in text and " " not in text else ""
        hh = url_host(href)
        if th and hh and registered_domain(th) != registered_domain(hh):
            ind.append(Indicator(
                "URL_TEXT_MISMATCH", "Link text hides its real destination", "high",
                f'A link displayed as "{text}" actually points to {registered_domain(hh)}.',
                "T1566.002 Spearphishing Link", evidence=href[:200]))

    seen_hosting: set[str] = set()
    for u in pe.urls:
        host = url_host(u)
        reg = registered_domain(host)
        if not host:
            continue
        if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", host):
            ind.append(Indicator("URL_IP", "Link points to a raw IP address", "high",
                                 f"{host} - legitimate brands use named domains, not bare IPs.",
                                 "T1566.002 Spearphishing Link", evidence=u[:200]))
        if "@" in u.split("//", 1)[-1].split("/", 1)[0]:
            ind.append(Indicator("URL_AT", "Credential-style '@' in URL authority", "high",
                                 "Everything before '@' is ignored by the browser - used to disguise the real host.",
                                 "T1566.002 Spearphishing Link", evidence=u[:200]))
        if reg in SHORTENERS:
            ind.append(Indicator("URL_SHORTENER", "URL shortener hides the destination", "medium",
                                 f"{reg} - the true landing page is concealed until clicked.",
                                 "T1566.002 Spearphishing Link", evidence=u[:120]))
        tld = reg.rsplit(".", 1)[-1] if "." in reg else ""
        if tld in RISKY_TLDS:
            ind.append(Indicator("URL_TLD", f"Link uses a high-abuse TLD (.{tld})", "low",
                                 f"{reg} - this TLD is disproportionately used for abuse.",
                                 "T1566.002 Spearphishing Link", evidence=u[:120]))
        lk_u = _looks_like_brand(host, include_labels=False)
        if lk_u:
            ind.append(Indicator("URL_LOOKALIKE", "Link domain imitates a brand", "critical",
                                 f"{reg} imitates {lk_u[0]} (real domain {lk_u[1]}).",
                                 "T1583.001 Domain Registration", evidence=u[:200]))
        # brand name buried in a subdomain of an unrelated domain (paypal.com.secure-login.ru).
        for brand, official in BRANDS.items():
            if _brand_in(host, brand) and reg != official and not _is_official(host, official):
                ind.append(Indicator("URL_SUBDOMAIN_BRAND", "Brand name buried in an unrelated domain",
                                     "high",
                                     f'"{brand}" appears in {host}, but the real domain is {reg}.',
                                     "T1566.002 Spearphishing Link", evidence=u[:200]))
                break
        ipfs = next((p for p in IPFS_HOSTS if _is_official(host, p)), None)
        if ipfs and ipfs not in seen_hosting:
            seen_hosting.add(ipfs)
            ind.append(Indicator("URL_IPFS", "Link to an IPFS gateway", "high",
                                 f"{host} serves files from IPFS, which phishing kits use because "
                                 "pages there are hard to take down.",
                                 "T1583.006 Web Services", evidence=u[:200]))
        free = next((p for p in FREE_HOSTING if _is_official(host, p)), None)
        if free and free not in seen_hosting:
            seen_hosting.add(free)
            ind.append(Indicator("URL_FREE_HOSTING", "Link to free developer hosting", "medium",
                                 f"{host} is on {free}, a free hosting platform where anyone can "
                                 "publish a page in minutes.",
                                 "T1583.006 Web Services", evidence=u[:200]))

    # --- Attachments ---
    for att in pe.attachments:
        name = att.filename.lower()
        parts = name.rsplit(".", 1)
        ext = parts[-1] if len(parts) == 2 else ""
        double = re.search(r"\.(pdf|doc|docx|xls|xlsx|jpg|png|invoice|receipt)\.[a-z0-9]{2,4}$", name)
        if ext in DANGEROUS_EXT:
            ind.append(Indicator("ATT_EXE", "Dangerous executable attachment", "critical",
                                 f"{att.filename} (.{ext}) can run code directly.",
                                 "T1566.001 Spearphishing Attachment",
                                 evidence=f"sha256={att.sha256}"))
        elif ext in MACRO_EXT:
            ind.append(Indicator("ATT_MACRO", "Macro-enabled Office attachment", "high",
                                 f"{att.filename} (.{ext}) can carry auto-executing macros.",
                                 "T1566.001 Spearphishing Attachment",
                                 evidence=f"sha256={att.sha256}"))
        elif ext in ARCHIVE_EXT:
            ind.append(Indicator("ATT_ARCHIVE", "Archive attachment", "medium",
                                 f"{att.filename} (.{ext}) can smuggle an executable past filters.",
                                 "T1566.001 Spearphishing Attachment",
                                 evidence=f"sha256={att.sha256}"))
        elif ext in HTML_EXT or (name and att.content_type.lower() == "text/html"):
            ind.append(Indicator("ATT_HTML", "HTML file attachment", "high",
                                 f"{att.filename} opens as a local web page, a common way to deliver "
                                 "a fake login form or smuggle a file past the mail filter.",
                                 "T1566.001 Spearphishing Attachment",
                                 evidence=f"sha256={att.sha256}"))
        if double:
            ind.append(Indicator("ATT_DOUBLE_EXT", "Double extension disguises the file type", "high",
                                 f"{att.filename} hides its real type behind a fake first extension.",
                                 "T1036.007 Double File Extension",
                                 evidence=f"sha256={att.sha256}"))

    # --- Body lures (content heuristics) ---
    body = (pe.body_text + " " + re.sub(r"<[^>]+>", " ", pe.body_html))
    if _URGENCY.search(body):
        ind.append(Indicator("LURE_URGENCY", "Urgency / threat language", "low",
                             "Pressure to act fast is a core social-engineering tactic.",
                             "T1566 Phishing", evidence=(_URGENCY.search(body).group(0))))
    if _CRED.search(body) and pe.urls:
        ind.append(Indicator("LURE_CRED", "Credential-harvest lure with a link", "medium",
                             "Asks the recipient to log in / verify via a link - classic credential theft.",
                             "T1566.002 Spearphishing Link", evidence=(_CRED.search(body).group(0))))
    if _PAYMENT.search(body):
        ind.append(Indicator("LURE_PAYMENT", "Financial / payment lure", "low",
                             "Invoice, refund or payment themes are common pretexts.",
                             "T1566 Phishing", evidence=(_PAYMENT.search(body).group(0))))

    return ind
