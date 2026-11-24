import os
import random
import tempfile
import unittest

from altum.engine import Engine
from altum.extract import extract_all, iban_check_digits, iban_is_valid
from altum.store import Store


def types(text):
    return {(e.type, e.display) for e in extract_all(text)}


class ExtractTests(unittest.TestCase):
    def test_uae_iban_valid_and_invalid(self):
        self.assertTrue(iban_is_valid("AE070331234567890123456"))
        self.assertFalse(iban_is_valid("AE460331234567890123456"))
        self.assertEqual(iban_check_digits("AE", "0331234567890123456"), "07")
        ents = extract_all("حوّل على AE07 0331 2345 6789 0123 456 بسرعة")
        iban = [e for e in ents if e.type == "iban"][0]
        self.assertTrue(iban.valid)
        self.assertEqual(iban.value, "AE070331234567890123456")

    def test_iban_digits_not_read_as_phone(self):
        self.assertFalse(any(e.type == "phone" for e in extract_all("AE07 0331 2345 6789 0123 456")))

    def test_arabic_digits_and_phone_formats(self):
        found = types("كلمني ٠٥٠ ١٢٣ ٤٥٦٧ أو +971 4 555 1234 أو 00966501234567")
        self.assertIn(("phone", "+971 50 123 4567"), found)
        self.assertIn(("phone", "+971 4 555 1234"), found)
        self.assertIn(("phone", "+966501234567"), found)

    def test_small_amounts_are_not_phones(self):
        self.assertFalse(any(e.type == "phone" for e in extract_all("ادفع 500 درهم الحين")))

    def test_links_wallets_handles(self):
        found = extract_all("ادخل parcel-pay.xyz/track و https://t.me/fastjobs أو USDT على "
                            "TQ5n8m3Gx7yKkQ6Wb2dE4rT9uV1sZ3aB7c وكلم @fast_cash_ae أو pay.help@gmail.com")
        kinds = {e.type for e in found}
        self.assertTrue({"url", "wallet", "tg_handle", "email"} <= kinds)
        self.assertFalse(any(e.type == "url" and "gmail" in e.value for e in found))

    def test_beneficiary_name(self):
        self.assertIn(("beneficiary", "شركة الوهم للتجارة"), types("اكتب: شركة الوهم للتجارة. وبسرعة"))


class EngineTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
        self.tmp.close()
        self.store = Store(self.tmp.name)
        self.engine = Engine(self.store, rng=random.Random(1))

    def tearDown(self):
        for suffix in ("", "-wal", "-shm"):
            try:
                os.remove(self.tmp.name + suffix)
            except FileNotFoundError:
                pass

    def say(self, text):
        return self.engine.handle_scammer("t:1", text, use_llm=False)

    def test_bank_scam_flow(self):
        t = self.say("معك قسم الحماية في البنك، حسابك موقوف")
        self.assertEqual((t.goal, t.persona, t.scam_type), ("open", "أبو سالم", "bank"))
        t = self.say("حوّل 500 درهم على AE07 0331 2345 6789 0123 456")
        self.assertEqual(t.goal, "beneficiary")
        t = self.say("اكتب: شركة الوهم للتجارة")
        self.assertEqual(t.goal, "phone")
        t = self.say("ارسل الرمز اللي وصلك")
        self.assertEqual(t.goal, "code")
        t = self.say("كلمني على 0501234567")
        self.assertEqual(t.goal, "more")
        self.assertGreaterEqual(t.risk, 60)

    def test_real_english_job_scam(self):
        """Real messages a user received: English job scam moving the victim to Telegram."""
        t = self.say("Hii !! This is Catherine , I got your contact information from recruitment team , "
                     "who mentioned that you are interested in online Freelance work. Right ?")
        self.assertEqual((t.scam_type, t.persona, t.goal), ("job", "ريم", "open"))
        self.assertRegex(t.reply, r"[A-Za-z]{3}")          # answers in English
        t = self.say("Okay , I will forward your details to the concern team. The person will contact "
                     "you via Telegram and provide you with the full details about the job role.")
        self.assertEqual(t.goal, "details")                 # no money asked yet: do not offer to pay
        t = self.say("You like YouTube videos and earn 5 AED for each task.")
        self.assertEqual(t.goal, "phone")                   # earning is not a payment request
        t = self.say("Deposit 100 AED to TQ5n8m3Gx7yKkQ6Wb2dE4rT9uV1sZ3aB7c")
        self.assertEqual(t.goal, "iban")                    # push for a bank account even after a wallet

    def test_cases_are_linked_by_shared_iban(self):
        self.say("حسابك في البنك موقوف")
        first = self.say("حوّل على AE07 0331 2345 6789 0123 456").case_id
        self.store.close_active("t:1")
        self.engine.handle_scammer("t:2", "مبروك ربحت جائزة", use_llm=False)
        t = self.engine.handle_scammer("t:2", "ادفع الرسوم على AE070331234567890123456", use_llm=False)
        self.assertEqual(t.links[("iban", "AE070331234567890123456")], [first])

    def test_forwarded_report(self):
        t = self.engine.handle_report("t:9", "شحنتك في الجمارك ادفع على parcel-pay.xyz", origin="@scammer1")
        self.assertEqual(t.scam_type, "delivery")
        self.assertEqual({e.type for e in t.new_entities}, {"url", "tg_account"})

    def test_vet_blocks_leaks_and_giveaways(self):
        self.assertIsNone(Engine.vet("الرمز هو 4821"))
        self.assertIsNone(Engine.vet("أنا بوت تابع للشرطة"))
        self.assertIsNone(Engine.vet("ادخل على example.com"))
        self.assertEqual(Engine.vet("أبو سالم: طيب يا ولدي، شو أسوي؟"), "طيب يا ولدي، شو أسوي؟")


if __name__ == "__main__":
    unittest.main()
