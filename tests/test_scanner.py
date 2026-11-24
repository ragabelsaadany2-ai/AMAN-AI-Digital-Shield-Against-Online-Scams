import csv
import json
import os
import shutil
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, os.path.dirname(__file__))
from fake_web import start  # noqa: E402

from altum.scanner import infra, listings, scan_url, watch  # noqa: E402
from altum.scanner.evidence import append_takedown, takedown_row, write_package  # noqa: E402

RDAP_SAMPLE = {
    "objectClassName": "domain", "ldhName": "tamm-fines-pay.top",
    "events": [{"eventAction": "registration", "eventDate": "2026-11-20T08:00:00Z"},
               {"eventAction": "expiration", "eventDate": "2027-11-20T08:00:00Z"}],
    "nameservers": [{"ldhName": "NS1.EXAMPLE-DNS.COM"}, {"ldhName": "ns2.example-dns.com"}],
    "entities": [{"roles": ["registrar"], "vcardArray": ["vcard", [["version", {}, "text", "4.0"], ["fn", {}, "text", "Example Registrar Ltd"]]],
                  "entities": [{"roles": ["abuse"], "vcardArray": ["vcard", [["email", {}, "text", "abuse@registrar.example"]]]}]}],
}


class OfflineTests(unittest.TestCase):
    def test_uae_impersonation_flagged(self):
        for u in ["https://tamm-fines-pay.top/login", "uaepass-verify.online/auth", "https://salik-ae-topup.shop",
                  "https://www.emiratesnbd.com.account-verify.info/secure", "https://rta-fine-payment.web.app/pay"]:
            self.assertEqual(scan_url(u, online=False)["label"], "phishing", u)

    def test_official_and_news_not_flagged(self):
        for u in ["https://www.tamm.abudhabi/en/aspects-of-life", "https://uaepass.ae/", "https://online.adcb.com/",
                  "https://www.dewa.gov.ae/en/consumer/billing/easy-pay", "https://www.liv.me/", "https://www.googleadservices.com/",
                  "https://www.khaleejtimes.com/uae/how-to-pay-traffic-fines-with-uae-pass"]:
            r = scan_url(u, online=False)
            self.assertEqual(r["label"], "safe", u)
            self.assertEqual(r["impersonates"], "", u)

    def test_every_flag_has_bilingual_reasons(self):
        r = scan_url("https://adcb-secure-update.xyz/login", online=False)
        self.assertTrue(r["signals"])
        for s in r["signals"]:
            self.assertTrue(s["ar"] and s["en"] and isinstance(s["w"], int))

    def test_evaluation_sets(self):
        root = Path(__file__).resolve().parents[1] / "eval"
        for name, min_recall in (("urls_labeled.csv", 0.9), ("holdout.csv", 0.9)):
            with open(root / name, encoding="utf-8") as f:
                rows = list(csv.DictReader(f))
            fp = sum(1 for r in rows if r["label"] == "legit" and scan_url(r["url"], online=False)["label"] == "phishing")
            ph = [r for r in rows if r["label"] == "phishing"]
            tp = sum(1 for r in ph if scan_url(r["url"], online=False)["label"] == "phishing")
            self.assertEqual(fp, 0, name)
            self.assertGreaterEqual(tp / len(ph), min_recall, name)

    def test_user_content_platforms(self):
        # A page on sites.google.com does not inherit Google's trust, and Google's own name is not impersonation.
        self.assertEqual(scan_url("https://sites.google.com/view/tamm-fines-payment", online=False)["label"], "phishing")
        self.assertEqual(scan_url("https://sites.google.com/view/my-bakery", online=False)["label"], "safe")
        self.assertEqual(scan_url("https://accounts.google.com/", online=False)["label"], "safe")

    def test_idn_homographs_and_arabic_domains(self):
        for u in ("https://xn--tmm-qla.com/", "https://xn--tmm-pay-2fg.com/", "https://xn--dcb-5cd.com/login"):  # tämm, tаmm (Cyrillic а), аdcb
            self.assertEqual(scan_url(u, online=False)["label"], "phishing", u)
        self.assertEqual(scan_url("https://xn--ngbn6f.xn--mgbaam7a8h/", online=False)["label"], "safe")  # دبي.امارات

    def test_rdap_parsing(self):
        orig = infra._get_json
        infra._get_json = lambda url, timeout=8.0: RDAP_SAMPLE
        try:
            w = infra.rdap_domain("tamm-fines-pay.top")
        finally:
            infra._get_json = orig
        self.assertEqual(w["created"], "2026-11-20T08:00:00Z")
        self.assertEqual(w["registrar"], "Example Registrar Ltd")
        self.assertEqual(w["abuse_email"], "abuse@registrar.example")
        self.assertEqual(w["nameservers"], ["ns1.example-dns.com", "ns2.example-dns.com"])
        self.assertIsInstance(w["age_days"], int)
        self.assertEqual(infra.signals({"whois": {"age_days": 3, "created": "x"}}, False)[0]["code"], "new_domain")

    def test_watch_and_feed(self):
        perms = watch.permutations("adcb.com")
        self.assertIn("adcb-pay.online", perms)
        self.assertNotIn("adcb.com", perms)
        hits = watch.filter_feed(["example.com", "tamm-fines-pay.top", "uaepass-login.site", "mybakery.ae"])
        self.assertEqual({h["domain"] for h in hits}, {"tamm-fines-pay.top", "uaepass-login.site"})

    def test_listings(self):
        self.assertEqual(listings.check_listing({"name": "ADCB Customer Care", "phone": "0551234567"})["label"], "fake")
        self.assertEqual(listings.check_listing({"name": "Emirates NBD Help", "website": "enbd-support-help.com"})["label"], "fake")
        self.assertEqual(listings.check_listing({"name": "Al Noor Grocery", "phone": "0551234567", "website": "alnoor.ae"})["label"], "ok")


class OnlineFakeWebTests(unittest.TestCase):
    """Runs against a local fake internet (see fake_web.py); needs the *.test names in /etc/hosts (README)."""

    @classmethod
    def setUpClass(cls):
        import socket
        try:
            socket.gethostbyname("short.test")
        except OSError:
            raise unittest.SkipTest("add '127.0.0.1 short.test tamm-fines.test collector.test news.test bounce.test' to /etc/hosts")
        cls.srv, cls.port = start()

    def test_redirects_cloaking_and_content(self):
        r = scan_url(f"http://short.test:{self.port}/abc", online=True, timeout=3)
        codes = {s["code"] for s in r["signals"]}
        self.assertEqual(r["label"], "phishing")
        self.assertTrue({"claims_brand", "cloaking", "form_offsite", "borrowed_assets", "redirect_offsite"} <= codes)
        self.assertEqual(len(r["chain"]), 3)

    def test_news_page_mentioning_brand_is_safe(self):
        self.assertEqual(scan_url(f"http://news.test:{self.port}/guide", online=True, timeout=3)["label"], "safe")

    def test_evidence_package(self):
        r = scan_url(f"http://short.test:{self.port}/abc", online=True, timeout=3)
        tmp = tempfile.mkdtemp()
        try:
            d = write_package(r, tmp, shot=False)
            data = json.loads((d / "report.json").read_text(encoding="utf-8"))
            self.assertIn("page.html", data["evidence_files"])
            self.assertTrue((d / "report.html").exists())
            append_takedown([takedown_row(r, str(d))], Path(tmp) / "takedown.csv")
            with open(Path(tmp) / "takedown.csv", encoding="utf-8-sig") as f:
                row = next(csv.DictReader(f))
            self.assertEqual(row["label"], "phishing")
        finally:
            shutil.rmtree(tmp)


if __name__ == "__main__":
    unittest.main()
