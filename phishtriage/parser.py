"""Parse a .eml file into the structured pieces an analyst triages:
headers, sender identities, authentication results, body, URLs and attachments.
Standard library only (email, hashlib, re)."""
from __future__ import annotations

import email
import hashlib
import re
from dataclasses import dataclass, field
from email.message import Message
from email.utils import parseaddr, getaddresses
from html.parser import HTMLParser

# URL regex for plain-text bodies (http/https). HTML links are pulled separately.
_URL_RE = re.compile(r"""https?://[^\s<>"'\)\]}]+""", re.IGNORECASE)


@dataclass
class Attachment:
    filename: str
    content_type: str
    size: int
    sha256: str
    md5: str


@dataclass
class ParsedEmail:
    # raw headers of interest
    headers: dict[str, str]
    subject: str
    date: str
    message_id: str
    # identities
    from_display: str
    from_addr: str
    reply_to_addr: str
    return_path_addr: str
    to_addrs: list[str]
    # auth
    auth_results_raw: str
    received_spf_raw: str
    received_chain: list[str]
    # content
    body_text: str
    body_html: str
    urls: list[str] = field(default_factory=list)
    attachments: list[Attachment] = field(default_factory=list)

    def domain_of(self, addr: str) -> str:
        return addr.split("@", 1)[1].lower().strip(">") if "@" in addr else ""


class _LinkExtractor(HTMLParser):
    """Collect href targets and the visible anchor text (to catch URL/text mismatch)."""

    def __init__(self) -> None:
        super().__init__()
        self.links: list[tuple[str, str]] = []  # (href, visible_text)
        self._href: str | None = None
        self._text: list[str] = []

    def handle_starttag(self, tag, attrs):
        if tag.lower() == "a":
            for k, v in attrs:
                if k.lower() == "href" and v:
                    self._href = v
                    self._text = []

    def handle_data(self, data):
        if self._href is not None:
            self._text.append(data)

    def handle_endtag(self, tag):
        if tag.lower() == "a" and self._href is not None:
            self.links.append((self._href, "".join(self._text).strip()))
            self._href = None
            self._text = []


def _decode(part: Message) -> str:
    payload = part.get_payload(decode=True)
    if payload is None:
        return ""
    charset = part.get_content_charset() or "utf-8"
    try:
        return payload.decode(charset, errors="replace")
    except (LookupError, TypeError):
        return payload.decode("utf-8", errors="replace")


def parse_email(raw: bytes) -> ParsedEmail:
    msg = email.message_from_bytes(raw)

    want = ("From", "Reply-To", "Return-Path", "To", "Subject", "Date",
            "Message-ID", "Authentication-Results", "Received-SPF")
    headers = {h: msg.get(h, "") for h in want}

    from_display, from_addr = parseaddr(msg.get("From", ""))
    _, reply_to_addr = parseaddr(msg.get("Reply-To", ""))
    _, return_path_addr = parseaddr(msg.get("Return-Path", ""))
    to_addrs = [a for _, a in getaddresses(msg.get_all("To", []))]

    received_chain = [str(h) for h in msg.get_all("Received", [])]

    body_text, body_html, attachments = "", "", []
    for part in msg.walk():
        if part.is_multipart():
            continue
        ctype = part.get_content_type()
        disp = str(part.get("Content-Disposition", ""))
        if "attachment" in disp.lower() or part.get_filename():
            data = part.get_payload(decode=True) or b""
            attachments.append(Attachment(
                filename=part.get_filename() or "(unnamed)",
                content_type=ctype,
                size=len(data),
                sha256=hashlib.sha256(data).hexdigest(),
                md5=hashlib.md5(data).hexdigest(),
            ))
        elif ctype == "text/plain":
            body_text += _decode(part)
        elif ctype == "text/html":
            body_html += _decode(part)

    # Collect URLs: HTML hrefs first (with anchor text), then plain-text URLs.
    urls: list[str] = []
    if body_html:
        lx = _LinkExtractor()
        try:
            lx.feed(body_html)
        except Exception:
            pass
        urls.extend(h for h, _ in lx.links if h.lower().startswith("http"))
    urls.extend(_URL_RE.findall(body_text))
    # de-dup, preserve order
    seen, deduped = set(), []
    for u in urls:
        u = u.rstrip(".,);]'\"")
        if u not in seen:
            seen.add(u)
            deduped.append(u)

    pe = ParsedEmail(
        headers=headers,
        subject=msg.get("Subject", ""),
        date=msg.get("Date", ""),
        message_id=msg.get("Message-ID", ""),
        from_display=from_display,
        from_addr=from_addr.lower(),
        reply_to_addr=reply_to_addr.lower(),
        return_path_addr=return_path_addr.lower(),
        to_addrs=[a.lower() for a in to_addrs],
        auth_results_raw=msg.get("Authentication-Results", ""),
        received_spf_raw=msg.get("Received-SPF", ""),
        received_chain=received_chain,
        body_text=body_text,
        body_html=body_html,
        urls=deduped,
        attachments=attachments,
    )
    # keep the anchor-text pairs for the URL/text mismatch check
    pe.html_links = lx.links if body_html else []  # type: ignore[attr-defined]
    return pe
