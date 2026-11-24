"""Loads three earlier "closed" cases so the live demo lights up the network map.

The live scammer in the demo sends the same IBAN as two of these cases,
so the dashboard links the new case to an existing gang in front of the judges.

  python seed_demo.py --reset    # wipe the database, then load the demo cases
"""
import sys
import time

from altum import config
from altum.extract import extract_all
from altum.store import Store

DEMO_IBAN = "AE07 0331 2345 6789 0123 456"   # the IBAN on the pitch deck; its checksum is valid

HISTORY = [
    {   # 6 days ago: fake customs parcel
        "days": 6, "type": "delivery", "persona": "khalid",
        "chat": [
            ("scammer", "عزيزي العميل، شحنتك محتجزة في الجمارك. ادفع 35 درهم رسوم عبر الرابط: parcel-uae-pay.xyz/track"),
            ("bait", "ما عندي وقت للروابط، عطني الآيبان وأحوّل من التطبيق."),
            ("scammer", f"حوّل على الحساب {DEMO_IBAN} وارسل الإيصال"),
            ("bait", "المحاسب يسأل: الحساب باسم منو؟"),
            ("scammer", "اكتب: شركة الوهم للتجارة"),
        ],
    },
    {   # 4 days ago: fake job tasks
        "days": 4, "type": "job", "persona": "reem",
        "chat": [
            ("scammer", "مرحبا، عندنا وظيفة دوام جزئي من المنزل، راتب 300 درهم يومياً على مهام لايك وتقييم"),
            ("bait", "واو بجد؟! احكيلي التفاصيل لو سمحت 🙏"),
            ("scammer", f"لازم تدفعي 200 درهم تسجيل على {DEMO_IBAN}"),
            ("bait", "ممكن رقم واتساب عشان نحكي أسرع؟"),
            ("scammer", "كلميني على 0552468135"),
        ],
    },
    {   # 2 days ago: prize scam, shares the phone number with case 2
        "days": 2, "type": "prize", "persona": "reem",
        "chat": [
            ("scammer", "مبروك! ربحت سحب 50,000 درهم. للاستلام تواصل مع المسؤول على 0552468135"),
            ("bait", "Really? شو المطلوب مني عشان أكمل؟ 😍"),
            ("scammer", "ادفع رسوم الاستلام 750 درهم USDT على TQ5n8m3Gx7yKkQ6Wb2dE4rT9uV1sZ3aB7c"),
        ],
    },
]


def main() -> None:
    store = Store(config.DB_PATH)
    if "--reset" in sys.argv:
        store.wipe()
        print("تم مسح قاعدة البيانات.")
    now = time.time()
    for i, case in enumerate(HISTORY, 1):
        t0 = now - case["days"] * 86400
        cid = store.create_case(f"seed:{i}", "seed", "قضية سابقة", persona=case["persona"],
                                scam_type=case["type"], status="closed", ts=t0)
        for j, (role, text) in enumerate(case["chat"]):
            ts = t0 + j * 240
            store.add_message(cid, role, text, ts=ts)
            if role == "scammer":
                store.add_entities(cid, extract_all(text), ts=ts)
        store.update_case(cid, risk=80, updated=t0 + len(case["chat"]) * 240)
        print(f"قضية سابقة #{cid}: {case['type']}")
    print(f"\nالآيبان الذي يرسله «المحتال» في العرض: {DEMO_IBAN}")


if __name__ == "__main__":
    main()
