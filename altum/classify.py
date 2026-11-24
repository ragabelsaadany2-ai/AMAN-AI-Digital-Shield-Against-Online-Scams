"""Keyword classifier for the scam type, plus a simple risk score."""
from __future__ import annotations

import re

SCAM_TYPES: dict[str, tuple[str, list[str]]] = {
    "bank": ("انتحال صفة بنك", [
        "بنك", "البنك", "حسابك", "موقوف", "مجمد", "تحديث البيانات", "تحديث بيانات", "بطاقتك",
        "البطاقة", "الصراف", "قسم الحماية", "bank", "account", "card", "blocked", "suspended", "verify"]),
    "gov": ("انتحال صفة جهة حكومية", [
        "شرطة", "الشرطة", "مخالفة", "مخالفات", "قضية", "النيابة", "بلاغ ضدك", "الإقامة", "الاقامة",
        "الهوية", "إيقاف الإقامة", "police", "fine", "violation", "court", "visa"]),
    "job": ("وظيفة وهمية", [
        "وظيفة", "وظائف", "راتب", "دوام جزئي", "عمل من المنزل", "تقييم", "لايك", "مهام", "مهمة",
        "job", "salary", "part time", "part-time", "task", "hiring", "recruit", "freelance", "online work",
        "work from home", "daily income", "earn", "commission", "hr ", "interested in", "vacancy", "employer"]),
    "prize": ("جائزة وهمية", [
        "مبروك", "ربحت", "فزت", "جائزة", "سحب", "الفائز", "winner", "won", "prize",
        "congratulations", "lucky", "reward"]),
    "delivery": ("شحنة وهمية", [
        "شحنة", "شحنتك", "طرد", "طردك", "الجمارك", "جمارك", "توصيل", "رسوم الشحن", "parcel",
        "package", "delivery", "customs", "shipment"]),
    "investment": ("استثمار وهمي", [
        "استثمار", "أرباح", "ارباح", "تداول", "عملات رقمية", "بيتكوين", "مضاعفة", "invest",
        "profit", "trading", "crypto", "bitcoin", "usdt"]),
}
UNKNOWN = ("unknown", "احتيال غير مصنّف")

URGENCY = ["بسرعة", "فورا", "فوراً", "حالا", "حالاً", "اليوم", "خلال ساعة", "قبل ما", "قبل لا",
           "urgent", "immediately", "asap", "right now"]
# A request for the victim to pay (a currency on its own, e.g. "earn 5 AED", is not one).
PAYMENT = ["حوّل", "حول على", "تحويل", "ادفع", "دفع", "رسوم", "إيداع", "ايداع", "شحن الرصيد", "fee", "fees",
           "pay ", "payment", "deposit", "transfer", "usdt", "recharge", "top up", "top-up", "send money"]
PLATFORM_SWITCH = ["telegram", "whatsapp", "تيليجرام", "تلغرام", "تليجرام", "واتساب", "واتس"]
CODE_REQUEST = ["رمز", "الرمز", "كود", "الكود", "otp", "code", "الرقم السري", "pin", "كلمة السر",
                "كلمة المرور", "password", "cvv", "رقم البطاقة"]

PERSONA_FOR_TYPE = {
    "bank": "abu_salem", "gov": "abu_salem",
    "job": "reem", "prize": "reem", "investment": "reem",
    "delivery": "khalid", "unknown": "khalid",
}


def classify(text: str) -> tuple[str, str, int]:
    """Return (type key, Arabic label, keyword hits)."""
    t = (text or "").lower()
    best, hits = UNKNOWN[0], 0
    for key, (_, words) in SCAM_TYPES.items():
        n = sum(1 for w in words if w in t)
        if n > hits:
            best, hits = key, n
    return best, label_for(best), hits


def label_for(scam_type: str | None) -> str:
    if scam_type in SCAM_TYPES:
        return SCAM_TYPES[scam_type][0]
    return UNKNOWN[1]


def asks_for_code(text: str) -> bool:
    t = (text or "").lower()
    return any(w in t for w in CODE_REQUEST)


def mentions_payment(text: str) -> bool:
    t = (text or "").lower()
    return any(w in t for w in PAYMENT)


def is_english(text: str) -> bool:
    latin = len(re.findall(r"[A-Za-z]", text or ""))
    arabic = len(re.findall(r"[\u0600-\u06FF]", text or ""))
    return latin > 2 * arabic and latin >= 6


def risk_score(scam_type: str, all_text: str, entity_types: set[str]) -> int:
    t = (all_text or "").lower()
    score = 20 if scam_type != "unknown" else 5
    if "iban" in entity_types or "wallet" in entity_types:
        score += 35
    if "url" in entity_types:
        score += 15
    if "phone" in entity_types:
        score += 5
    if asks_for_code(t):
        score += 20
    if any(w in t for w in URGENCY):
        score += 10
    if any(w in t for w in PLATFORM_SWITCH):
        score += 15   # moving the victim to another app is a classic scam step
    if mentions_payment(t):
        score += 10
    return min(score, 100)


def risk_label(score: int) -> str:
    return "مرتفعة" if score >= 60 else "متوسطة" if score >= 35 else "منخفضة"
