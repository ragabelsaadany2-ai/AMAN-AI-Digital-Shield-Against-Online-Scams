import os
import tempfile
import unittest

from altum import haris
from altum.engine import Engine
from altum.store import Store


class HarisServerTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
        self.tmp.close()
        self.store = Store(self.tmp.name)

    def tearDown(self):
        for suffix in ("", "-wal", "-shm"):
            try:
                os.remove(self.tmp.name + suffix)
            except FileNotFoundError:
                pass

    def test_link_from_chat_is_known_to_haris(self):
        Engine(self.store).handle_scammer("t:1", "أكّد هنا https://www.falcon-pay.top/track?id=55", use_llm=False)
        r = haris.check(self.store, "http://falcon-pay.top/track")       # scheme, www and query ignored
        self.assertTrue(r["known"] and r["from_chat"])
        self.assertTrue(haris.check(self.store, "https://falcon-pay.top/other")["known"])   # same real domain
        self.assertFalse(haris.check(self.store, "https://example.org/track")["known"])

    def test_local_host_matches_exact_page_only(self):
        Engine(self.store).handle_scammer("t:1", "ادخل http://127.0.0.1:8080/demo/falcon-track", use_llm=False)
        self.assertTrue(haris.check(self.store, "http://127.0.0.1:8080/demo/falcon-track")["known"])
        self.assertFalse(haris.check(self.store, "http://127.0.0.1:8080/demo/falcon-clean")["known"])

    def test_report_links_to_chat_case_and_dedups(self):
        chat = Engine(self.store).handle_scammer("t:1", "ادخل http://127.0.0.1:8080/demo/falcon-track", use_llm=False)
        payload = {"url": "http://127.0.0.1:8080/demo/falcon-track", "brand": "فالكون إكسبريس", "category": "shipping",
                   "requested": ["email_password", "bogus"], "level": "high", "signals": ["known_threat"],
                   "reasons_ar": ["سبب"]}
        r = haris.report(self.store, payload)
        self.assertTrue(r["new"])
        self.assertEqual(r["linked"], [chat.case_id])
        self.assertFalse(haris.report(self.store, payload)["new"])          # same page again: same case
        alerts = haris.pending_alerts(self.store)
        self.assertEqual(len(alerts), 1)
        self.assertNotIn("bogus", alerts[0]["text"])
        self.assertEqual(haris.pending_alerts(self.store), [])               # each alert is sent once

    def test_report_rejects_garbage(self):
        self.assertFalse(haris.report(self.store, {"url": ""})["ok"])
        self.assertTrue(haris.report(self.store, {"url": "x.example/a", "requested": "not a list"})["ok"])


if __name__ == "__main__":
    unittest.main()
