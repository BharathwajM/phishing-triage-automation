"""End-to-end checks: the sample phishing emails must be caught and the
legitimate controls must not be flagged. Run with: python -m unittest discover -s tests -v
Pure standard library - no pytest needed."""
import io
import os
import pathlib
import sys
import unittest
from contextlib import redirect_stdout
from tempfile import TemporaryDirectory
from unittest.mock import patch

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))

from phishtriage.auth import analyze_auth
from phishtriage.cli import main
from phishtriage.enrich import Enrichment
from phishtriage.indicators import collect_indicators
from phishtriage.parser import parse_email
from phishtriage.report import build_html, build_markdown
from phishtriage.scoring import score
from phishtriage.utils import registered_domain

SAMPLES = pathlib.Path(__file__).resolve().parents[1] / "samples"


def verdict_for(name: str):
    pe = parse_email((SAMPLES / name).read_bytes())
    auth = analyze_auth(pe)
    return score(collect_indicators(pe, auth))


class TestVerdicts(unittest.TestCase):
    def test_phishing_samples_flagged(self):
        for name in ("paypal_credphish.eml", "microsoft365_password.eml",
                     "ato_refund_scam.eml"):
            with self.subTest(sample=name):
                self.assertEqual(verdict_for(name).label, "MALICIOUS")

    def test_borderline_is_suspicious(self):
        for name in ("parcel_reschedule.eml", "invoice_macro.eml"):
            with self.subTest(sample=name):
                self.assertEqual(verdict_for(name).label, "SUSPICIOUS")

    def test_legitimate_controls_not_flagged(self):
        for name in ("legit_github_notification.eml", "legit_internal_hr.eml"):
            with self.subTest(sample=name):
                self.assertIn(verdict_for(name).label, ("BENIGN", "LIKELY BENIGN"))


class TestDetectors(unittest.TestCase):
    def test_registered_domain(self):
        self.assertEqual(registered_domain("a.b.example.com"), "example.com")
        self.assertEqual(registered_domain("foo.co.uk"), "foo.co.uk")
        self.assertEqual(registered_domain("x.foo.co.uk"), "foo.co.uk")
        self.assertEqual(registered_domain("198.51.100.23"), "198.51.100.23")

    def test_lookalike_sender_is_critical(self):
        v = verdict_for("paypal_credphish.eml")
        ids = {i.id for i in v.indicators}
        self.assertIn("LOOKALIKE_SENDER", ids | {i.id for i in v.indicators})
        self.assertTrue(any(i.severity == "critical" for i in v.indicators))

    def test_macro_attachment_detected(self):
        v = verdict_for("invoice_macro.eml")
        self.assertIn("ATT_MACRO", {i.id for i in v.indicators})

    def test_html_attachment_is_suspicious(self):
        v = triage_text(
            "From: billing@example.invalid\nSubject: Remittance\nMIME-Version: 1.0\n"
            "Content-Type: text/html\n"
            'Content-Disposition: attachment; filename="Remittance_0412.shtml"\n\n<html></html>')
        self.assertIn("ATT_HTML", {i.id for i in v.indicators})
        self.assertEqual(v.label, "SUSPICIOUS")

    def test_ipfs_and_free_hosting_links(self):
        v = triage_text(
            "From: it@example.invalid\nSubject: Mailbox\n\n"
            "Open https://ipfs.io/ipfs/bafybeexample/index.html and "
            "https://login-portal.pages.dev/ and https://other.pages.dev/x")
        ids = [i.id for i in v.indicators]
        self.assertIn("URL_IPFS", ids)
        self.assertEqual(ids.count("URL_FREE_HOSTING"), 1)  # one finding per platform

    def test_short_brand_names_need_a_whole_word(self):
        # "ups" in groups.google.com and "ato" in usatoday.com are not brand impersonation
        v = triage_text(
            "From: Groups Digest <digest@example.invalid>\nSubject: Digest\n\n"
            "See https://groups.google.com/g/test and https://www.usatoday.com/story")
        ids = {i.id for i in v.indicators}
        self.assertFalse(ids & {"URL_SUBDOMAIN_BRAND", "URL_LOOKALIKE", "DISPLAY_SPOOF"})

    def test_brand_buried_in_unrelated_domain_still_detected(self):
        v = triage_text("From: a@example.invalid\nSubject: x\n\n"
                        "https://ups.com.track-parcel.example.net/ and "
                        "https://microsoftonline-verify.example.net/")
        found = [i for i in v.indicators if i.id == "URL_SUBDOMAIN_BRAND"]
        self.assertEqual(len(found), 2)

    def test_encoded_display_name_is_decoded(self):
        pe = parse_email(b"From: =?utf-8?b?w4lsb2RpZSBNYXJ0aW4=?= <e@example.org>\n"
                         b"Subject: =?utf-8?q?Konto_gesperrt?=\n\nHallo")
        self.assertEqual(pe.from_display, "Élodie Martin")
        self.assertEqual(pe.subject, "Konto gesperrt")

    def test_lookalike_characters_in_display_name(self):
        # Cyrillic "a", a zero-width space and full-width letters, each hiding a brand name
        for header in ("=?utf-8?q?Ch=D0=B0se_Bank?=", "=?utf-8?q?Pay=E2=80=8BPal?=",
                       "=?utf-8?q?=EF=BC=B0ay=EF=BD=90al?="):
            with self.subTest(header=header):
                v = triage_text(f"From: {header} <alerts@example.invalid>\nSubject: x\n\nhi")
                ids = {i.id for i in v.indicators}
                self.assertIn("DISPLAY_HOMOGLYPH", ids)
                self.assertIn("DISPLAY_SPOOF", ids)

    def test_brand_shared_through_a_real_service(self):
        # Sent by Google Drive's sharing feature: Google is genuine, the Chase name is not
        shared = "From: =?utf-8?q?Ch=D0=B0se_Bank_=28via_Google_Drive=29?= <drive-shares-dm-noreply@google.com>\n"
        ids = {i.id for i in triage_text(shared + "Subject: x\n\nhi").indicators}
        self.assertTrue({"DISPLAY_HOMOGLYPH", "DISPLAY_SPOOF"} <= ids)
        plain = "From: Alex (via Google Drive) <drive-shares-dm-noreply@google.com>\nSubject: x\n\nhi"
        self.assertEqual(triage_text(plain).label, "BENIGN")

    def test_plain_brand_name_is_not_a_homoglyph(self):
        v = triage_text("From: PayPal <service@paypal.com>\nSubject: Receipt\n\nThanks")
        self.assertEqual(v.label, "BENIGN")

    def test_mailing_list_headers_alone_are_not_flagged(self):
        # Separate bounce domain and list Reply-To are normal for mailing lists
        v = triage_text(
            "From: Alice <alice@example.org>\nReturn-Path: <bounce-list@lists.example.net>\n"
            "Reply-To: discuss@lists.example.net\nSubject: Re: meeting\n\nSee you there.")
        self.assertIn(v.label, ("BENIGN", "LIKELY BENIGN"))


def triage_text(message: str):
    pe = parse_email(message.encode())
    return score(collect_indicators(pe, analyze_auth(pe)))


class TestUntrustedReports(unittest.TestCase):
    def test_authentication_claims_are_unverified_and_do_not_change_score(self):
        for result in ("pass", "fail"):
            with self.subTest(result=result):
                message = (
                    "From: test@example.invalid\n"
                    f"Authentication-Results: untrusted.invalid; spf={result} "
                    f"dkim={result} dmarc={result}\n"
                    "Subject: Test\n\nTest"
                )
                pe = parse_email(message.encode())
                auth = analyze_auth(pe)
                verdict = score(collect_indicators(pe, auth))
                enr = Enrichment(enabled=False, skipped_reason="Disabled for tests.")
                self.assertEqual((auth.spf, auth.dkim, auth.dmarc), (result,) * 3)
                self.assertEqual(verdict.score, 0)
                for report in (build_markdown(pe, auth, verdict, enr),
                               build_html(pe, auth, verdict, enr)):
                    self.assertIn("Reported results are unverified", report)
                    self.assertIn(result, report)

    def test_report_displays_email_markup_as_literal_text(self):
        subject = '` `` ![pixel](https://example.invalid/pixel) <img src="x">'
        filename = '` ![track](https://example.invalid/track) | invoice.xlsm'
        message = (
            "From: test@example.invalid\n"
            f"Subject: {subject}\n"
            "MIME-Version: 1.0\n"
            "Content-Type: application/octet-stream\n"
            f'Content-Disposition: attachment; filename="{filename}"\n\n'
            "Synthetic attachment"
        )
        pe = parse_email(message.encode())
        auth = analyze_auth(pe)
        verdict = score(collect_indicators(pe, auth))
        enr = Enrichment(enabled=False, skipped_reason="Disabled for tests.")
        markdown = build_markdown(pe, auth, verdict, enr)
        self.assertIn(f"- **Subject:** ``` {subject} ```\n", markdown)
        self.assertIn(f"- **Attachment:** `` {filename} ``", markdown)
        self.assertIn(r"\x7c invoice.xlsm", markdown)
        html = build_html(pe, auth, verdict, enr)
        self.assertIn("&lt;img", html)
        self.assertNotIn("<img", html)


class TestCliEnrichment(unittest.TestCase):
    def test_default_and_no_enrich_skip_external_services_with_keys_present(self):
        for flags in ([], ["--no-enrich"]):
            with self.subTest(flags=flags), TemporaryDirectory() as out:
                with patch.dict(os.environ, {"VT_API_KEY": "test", "URLHAUS_API_KEY": "test"}):
                    with patch("phishtriage.cli.enrich") as lookup, redirect_stdout(io.StringIO()):
                        result = main([str(SAMPLES / "paypal_credphish.eml"), "--out", out, *flags])
                self.assertEqual(result, 0)
                lookup.assert_not_called()
                report = pathlib.Path(out) / "paypal_credphish.md"
                self.assertIn("Live enrichment is off", report.read_text(encoding="utf-8"))

    def test_enrich_flag_calls_the_lookup(self):
        with TemporaryDirectory() as out, redirect_stdout(io.StringIO()):
            with patch("phishtriage.cli.enrich", return_value=Enrichment(enabled=True)) as lookup:
                result = main([str(SAMPLES / "paypal_credphish.eml"), "--out", out, "--enrich"])
        self.assertEqual(result, 0)
        lookup.assert_called_once()


if __name__ == "__main__":
    unittest.main(verbosity=2)
