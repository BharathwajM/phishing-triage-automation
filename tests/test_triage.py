"""End-to-end checks: the sample phishing emails must be caught and the
legitimate controls must not be flagged. Run with:  python -m unittest -v
Pure standard library - no pytest needed."""
import pathlib
import sys
import unittest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))

from phishtriage.auth import analyze_auth
from phishtriage.indicators import collect_indicators
from phishtriage.parser import parse_email
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
                     "invoice_macro.eml", "ato_refund_scam.eml"):
            with self.subTest(sample=name):
                self.assertEqual(verdict_for(name).label, "MALICIOUS")

    def test_borderline_is_suspicious(self):
        self.assertEqual(verdict_for("parcel_reschedule.eml").label, "SUSPICIOUS")

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


if __name__ == "__main__":
    unittest.main(verbosity=2)
