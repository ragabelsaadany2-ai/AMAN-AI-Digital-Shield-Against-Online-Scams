"""Search and Maps coverage: check business listings (name, phone, website) for fake pages and fake helplines.

Input rows: {"source": "maps|search|ad", "name": "...", "phone": "...", "website": "...", "address": "..."}
"""
from __future__ import annotations

import re

from ..extract import classify_phone
from .brands import brands, official_brand_for
from .lexical import analyze

BANK_GOV = {"bank", "government"}


def _brand_in_name(name: str):
    low = (name or "").lower()
    for b in brands():
        if any(a.lower() in low for a in b["aliases"]):
            return b
    return None


def check_listing(row: dict) -> dict:
    name, phone, site = row.get("name", ""), row.get("phone", ""), row.get("website", "")
    brand = _brand_in_name(name)
    sig = []
    ph = classify_phone(phone) if phone else None
    if brand:
        if site:
            host = re.sub(r"^https?://", "", site.strip().lower()).split("/")[0]
            if not official_brand_for(host):
                sig.append({"code": "listing_site", "w": 40, "ar": f"الإدراج باسم «{brand['name_ar']}» لكن موقعه ({host}) ليس رسمياً.",
                            "en": f"The listing is named after {brand['name_en']} but its website ({host}) is not official."})
        if ph:
            num, kind = ph
            if brand.get("helplines") and num not in brand["helplines"]:
                sig.append({"code": "listing_phone", "w": 40, "ar": f"الرقم {num} ليس من أرقام «{brand['name_ar']}» الرسمية.",
                            "en": f"{num} is not one of {brand['name_en']}'s official numbers."})
            elif brand["category"] in BANK_GOV and kind in ("uae_mobile", "intl"):
                sig.append({"code": "listing_mobile_helpline", "w": 45,
                            "ar": f"خط مساعدة لـ«{brand['name_ar']}» برقم جوال أو دولي ({num})، والجهات الرسمية تستخدم أرقاماً مجانية أو أرضية.",
                            "en": f"A {brand['name_en']} helpline on a mobile/foreign number ({num}); official lines use toll-free or landline numbers."})
    if site and not brand:
        a = analyze(site)
        if a["brand"]:
            brand = a["brand"]
        sig += [s for s in a["signals"] if s["w"] >= 20]
    total = sum(s["w"] for s in sig)
    label = "fake" if total >= 40 else "check" if total >= 20 else "ok"
    return {**row, "brand": (brand or {}).get("name_en", ""), "label": label, "score": min(100, total),
            "reasons_ar": [s["ar"] for s in sig], "reasons_en": [s["en"] for s in sig]}
