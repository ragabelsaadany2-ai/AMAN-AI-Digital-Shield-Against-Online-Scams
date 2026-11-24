"""Extracts scammer identifiers from free text (Arabic or English).

Finds: IBANs (with mod-97 checksum validation), UAE and international phone
numbers, links, e-mails, crypto wallets, Telegram handles, requested amounts
and a likely beneficiary name.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field

TYPE_LABELS = {
    "iban": "آيبان",
    "beneficiary": "اسم المستفيد",
    "phone": "رقم هاتف",
    "url": "رابط",
    "email": "بريد إلكتروني",
    "wallet": "محفظة رقمية",
    "tg_handle": "حساب تيليجرام",
    "tg_account": "حساب المرسل",
    "amount": "مبلغ مذكور",
    "ip": "عنوان IP",
    "ns": "خادم أسماء",
}
# Types that identify a scammer and are linked across cases on the network map.
NETWORK_TYPES = {"iban", "beneficiary", "phone", "url", "email", "wallet", "tg_handle", "tg_account", "ip", "ns"}


@dataclass
class Entity:
    type: str
    value: str          # normalised value used for matching across cases
    display: str        # how it is shown to people
    valid: bool = True  # e.g. IBAN checksum passed
    extra: dict = field(default_factory=dict)

    @property
    def label(self) -> str:
        return TYPE_LABELS.get(self.type, self.type)

    @property
    def key(self) -> tuple:
        return (self.type, self.value)


# ---------------------------------------------------------------- normalising
_DIGITS = str.maketrans("٠١٢٣٤٥٦٧٨٩۰۱۲۳۴۵۶۷۸۹", "0123456789" * 2)
_INVISIBLE = re.compile(r"[​-‏‪-‮⁦-⁩﻿­]")


def normalize(text: str) -> str:
    text = _INVISIBLE.sub("", text or "")
    text = text.translate(_DIGITS)
    return text.replace("＋", "+").replace(" ", " ")


# ---------------------------------------------------------------------- IBAN
IBAN_LENGTHS = {
    "AE": 23, "SA": 24, "QA": 29, "KW": 30, "BH": 22, "OM": 23, "JO": 30,
    "EG": 29, "LB": 28, "IQ": 23, "PK": 24, "TR": 26, "GB": 22, "DE": 22,
    "FR": 27, "NL": 18, "IT": 27, "ES": 24, "CH": 21,
}
_IBAN_CAND = re.compile(r"(?<![A-Za-z0-9])([A-Za-z]{2}\s?\d{2}(?:[ \t\-]?[A-Za-z0-9]){10,32})")


def _mod97(s: str) -> int:
    return int("".join(str(int(ch, 36)) for ch in s)) % 97


def iban_is_valid(iban: str) -> bool:
    iban = iban.replace(" ", "").upper()
    if len(iban) < 15 or not iban[:2].isalpha() or not iban[2:4].isdigit():
        return False
    try:
        return _mod97(iban[4:] + iban[:4]) == 1
    except ValueError:
        return False


def iban_check_digits(country: str, bban: str) -> str:
    return f"{98 - _mod97(bban + country.upper() + '00'):02d}"


def format_iban(iban: str) -> str:
    return " ".join(iban[i:i + 4] for i in range(0, len(iban), 4))


def _find_ibans(text: str) -> tuple[list[Entity], str]:
    found, spans = [], []
    for m in _IBAN_CAND.finditer(text):
        compact = re.sub(r"[\s\-]", "", m.group(1)).upper()
        country = compact[:2]
        length = IBAN_LENGTHS.get(country)
        if length:
            if len(compact) < length:
                continue
            compact = compact[:length]
            if country == "AE" and not compact[2:].isdigit():
                continue
            valid = iban_is_valid(compact)
        else:
            if not (15 <= len(compact) <= 34) or not iban_is_valid(compact):
                continue
            valid = True
        found.append(Entity("iban", compact, format_iban(compact), valid,
                            {"country": country}))
        spans.append(m.span(1))
    # blank out IBANs so their digits are not read as phone numbers
    chars = list(text)
    for a, b in spans:
        for i in range(a, b):
            chars[i] = " "
    return found, "".join(chars)


# --------------------------------------------------------------------- phones
_PHONE_CAND = re.compile(r"(?<![\w+])(?:\+|00)?\s?\d[\d \t\-().]{6,18}\d(?!\w)")


def classify_phone(raw: str) -> tuple[str, str] | None:
    raw = raw.strip()
    digits = re.sub(r"\D", "", raw)
    intl = raw.startswith("+")
    if digits.startswith("00"):
        digits, intl = digits[2:], True
    if digits.startswith("971"):
        nat = digits[3:]
        if nat.startswith("0"):
            nat = nat[1:]
        if nat.startswith("5") and len(nat) == 9:
            return "+971" + nat, "uae_mobile"
        if len(nat) == 8 and nat[0] in "234679":
            return "+971" + nat, "uae_landline"
        return None
    if not intl:
        if digits.startswith("800") and 6 <= len(digits) <= 10:
            return "+971" + digits, "uae_tollfree"
        if digits.startswith("600") and len(digits) == 9:
            return "+971" + digits, "uae_600"
        if digits.startswith("05") and len(digits) == 10:
            return "+971" + digits[1:], "uae_mobile"
        if digits.startswith("5") and len(digits) == 9:
            return "+971" + digits, "uae_mobile"
        if digits.startswith("0") and len(digits) == 9 and digits[1] in "234679":
            return "+971" + digits[1:], "uae_landline"
        return None
    if 8 <= len(digits) <= 15:
        return "+" + digits, "intl"
    return None


def format_phone(e164: str) -> str:
    if e164.startswith("+9715") and len(e164) == 13:
        n = e164[4:]
        return f"+971 {n[:2]} {n[2:5]} {n[5:]}"
    if e164.startswith("+971") and len(e164) == 12:
        n = e164[4:]
        return f"+971 {n[:1]} {n[1:4]} {n[4:]}"
    return e164


def _find_phones(text: str) -> list[Entity]:
    out = []
    for m in _PHONE_CAND.finditer(text):
        res = classify_phone(m.group(0))
        if res:
            e164, kind = res
            out.append(Entity("phone", e164, format_phone(e164), True, {"kind": kind}))
    return out


# ------------------------------------------------------ links, mails, wallets
_EMAIL = re.compile(r"[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}")
_TLDS = ("com|net|org|ae|info|xyz|top|online|site|link|ly|me|io|co|shop|club|live|app|cc|vip|"
         "icu|buzz|tk|ml|ga|cf|gq|biz|pro|cn|ru|in|pk|store|click|win|bid|work|support|help")
_URL = re.compile(
    r"(?i)(?:https?://|www\.)[^\s<>\"'،]+"
    r"|(?<![\w@.\-])(?:[a-z0-9](?:[a-z0-9\-]{0,61}[a-z0-9])?\.)+(?:" + _TLDS + r")(?![\w\-])(?:/[^\s<>\"'،]*)?")
_ETH = re.compile(r"(?<!\w)0x[a-fA-F0-9]{40}(?!\w)")
_TRON = re.compile(r"(?<!\w)T[1-9A-HJ-NP-Za-km-z]{33}(?!\w)")
_BTC = re.compile(r"(?<!\w)(?:bc1[ac-hj-np-z02-9]{11,71}|[13][a-km-zA-HJ-NP-Z1-9]{25,34})(?!\w)")
_TG = re.compile(r"(?<![\w@])@([A-Za-z][A-Za-z0-9_]{4,31})(?!\w)")
_AMOUNT = re.compile(
    r"(?i)(?:(\d[\d,]*(?:\.\d+)?)\s*(درهم|دراهم|aed|dhs?|د\.إ|دولار|usd|\$|ريال|usdt)"
    r"|(aed|usd|\$)\s*(\d[\d,]*(?:\.\d+)?))")
_NAME = re.compile(
    r"(?:اسم\s+(?:المستفيد|صاحب\s+الحساب|الحساب|الشركة)|باسم|اكتب|المستفيد|beneficiary(?:\s+name)?|account\s+name)"
    r"\s*(?:هو|is)?\s*[:：\-]?\s*([^\n.،,!؟?:]{3,60})", re.IGNORECASE)
_NAME_STOP = re.compile(r"\s+(?:و?بسرعة|قبل|بعدين|لو سمحت|please|quickly)\b.*$", re.IGNORECASE)


def defang(url: str) -> str:
    return url.replace("http", "hxxp").replace(".", "[.]")


def normalize_url(url: str) -> tuple[str, str]:
    """Return (host/path, host) with scheme, www, query string and fragment removed.

    Al-Tu'm (links in chats) and Haris (pages in the browser) both use this,
    so the same link found by either side matches on the shared map.
    """
    url = url.strip().rstrip(".,!?)]}»\"'")
    norm = re.sub(r"^(?:https?://)?(?:www\.)?", "", url, flags=re.I)
    norm = norm.split("#")[0].split("?")[0].rstrip("/")
    host, _, path = norm.partition("/")
    host = host.lower()
    return host + ("/" + path if path else ""), host


def _find_urls(text: str) -> list[Entity]:
    out = []
    for m in _URL.finditer(text):
        url = m.group(0).rstrip(".,!?)]}»\"'")
        norm, host = normalize_url(url)
        if len(host) < 4:
            continue
        out.append(Entity("url", norm, defang(url), True, {"host": host}))
    return out


def _find_name(text: str) -> list[Entity]:
    out = []
    for m in _NAME.finditer(text):
        name = _NAME_STOP.sub("", m.group(1)).strip(" \"'«»")
        words = name.split()
        if not (1 <= len(words) <= 6) or re.search(r"\d", name):
            continue
        if re.match(r"(?:رقم|الرقم|الآيبان|الايبان|الحساب|هذا|هنا|التالي)$", words[0]):
            continue
        out.append(Entity("beneficiary", re.sub(r"\s+", " ", name).lower(), name, True))
    return out


# -------------------------------------------------------------------- public
def extract_all(text: str) -> list[Entity]:
    """Return every identifier found in ``text`` (duplicates removed)."""
    text = normalize(text)
    entities: list[Entity] = []

    ibans, rest = _find_ibans(text)
    entities += ibans

    for m in _EMAIL.finditer(rest):
        entities.append(Entity("email", m.group(0).lower(), m.group(0)))
    rest = _EMAIL.sub(" ", rest)

    for rx in (_ETH, _TRON, _BTC):
        for m in rx.finditer(rest):
            entities.append(Entity("wallet", m.group(0), m.group(0)))
        rest = rx.sub(" ", rest)

    urls = _find_urls(rest)
    entities += urls
    rest = _URL.sub(" ", rest)

    for m in _TG.finditer(rest):
        entities.append(Entity("tg_handle", m.group(1).lower(), "@" + m.group(1)))

    for m in _AMOUNT.finditer(rest):
        num = m.group(1) or m.group(4)
        cur = (m.group(2) or m.group(3) or "").lower()
        cur = {"aed": "درهم", "dh": "درهم", "dhs": "درهم", "د.إ": "درهم", "دراهم": "درهم",
               "usd": "دولار", "$": "دولار", "usdt": "USDT"}.get(cur, cur)
        entities.append(Entity("amount", f"{num.replace(',', '')} {cur}", f"{num} {cur}"))
    rest = _AMOUNT.sub(" ", rest)

    entities += _find_phones(rest)
    entities += _find_name(text)

    seen, unique = set(), []
    for e in entities:
        if e.key not in seen:
            seen.add(e.key)
            unique.append(e)
    return unique


def has_identifier_like(text: str) -> bool:
    """True if a text would leak something identifier-like (used to vet the bait's replies)."""
    t = normalize(text)
    if re.search(r"\d(?:[\s\-]?\d){3,}", t):  # 4+ digits: codes, cards, numbers
        return True
    if _EMAIL.search(t) or _URL.search(t) or _ETH.search(t):
        return True
    return False
