"""Server side of «حارس» (Haris), the browser extension.

  check(url)      -> is this link already known from an Al-Tu'm chat or another Haris user?
  report(payload) -> a suspicious page Haris found becomes a case on the police map.

Privacy: Haris sends only the page address without its query string, the brand the
page claims, the kinds of data it asks for and the reasons. Never what the user typed.
"""
from __future__ import annotations

import ipaddress
import json
import time

from .extract import Entity, defang, normalize_url
from .store import Store

CHAT_SOURCES = {"telegram", "cli", "forward", "seed"}
REQUEST_LABELS = {
    "password": "كلمة المرور", "email_password": "كلمة مرور البريد الإلكتروني", "otp": "رمز التحقق",
    "card": "بيانات البطاقة", "cvv": "رمز CVV", "id_number": "رقم الهوية",
}
CATEGORY_TO_SCAM = {"shipping": "delivery", "bank": "bank", "government": "gov", "telecom": "unknown"}
DEDUP_SECONDS = 1800


def _is_local(host: str) -> bool:
    h = host.split(":")[0].strip("[]")
    if h in ("localhost", "0.0.0.0"):
        return True
    try:
        return ipaddress.ip_address(h).is_private or ipaddress.ip_address(h).is_loopback
    except ValueError:
        return False


def _ago_ar(seconds: float) -> str:
    m = int(seconds // 60)
    if m < 1:
        return "قبل أقل من دقيقة"
    if m == 1:
        return "قبل دقيقة"
    if m == 2:
        return "قبل دقيقتين"
    if m < 60:
        return f"قبل {m} دقائق" if m <= 10 else f"قبل {m} دقيقة"
    h = m // 60
    if h < 24:
        return "قبل ساعة" if h == 1 else f"قبل {h} ساعات" if h <= 10 else f"قبل {h} ساعة"
    d = h // 24
    return "قبل يوم" if d == 1 else f"قبل {d} أيام" if d <= 10 else f"قبل {d} يوماً"


def _ago_en(seconds: float) -> str:
    m = int(seconds // 60)
    if m < 1:
        return "less than a minute ago"
    if m < 60:
        return f"{m} minute{'s' if m > 1 else ''} ago"
    h = m // 60
    if h < 24:
        return f"{h} hour{'s' if h > 1 else ''} ago"
    d = h // 24
    return f"{d} day{'s' if d > 1 else ''} ago"


def check(store: Store, url: str) -> dict:
    norm, host = normalize_url(url or "")
    if not host:
        return {"known": False}
    # Match the whole host only for real domains; a local demo host serves many unrelated pages.
    rows = store.url_matches(norm, None if _is_local(host) else host)
    rows = [r for r in rows if r["source"] != "scanner"]        # the scanner's own past verdicts are not evidence
    if not rows:
        return {"known": False, "url": norm}
    chat = [r for r in rows if r["source"] in CHAT_SOURCES]
    best = (chat or rows)[0]
    now = time.time()
    case_ids = sorted({r["case_id"] for r in rows})
    from_chat = bool(chat)
    ago = now - best["ts"]
    return {
        "known": True,
        "url": norm,
        "from_chat": from_chat,
        "case_id": best["case_id"],
        "case_ids": case_ids,
        "first_seen": best["ts"],
        "ago_ar": _ago_ar(ago),
        "ago_en": _ago_en(ago),
        "source_ar": "في محادثة احتيال رصدها الطُّعم" if from_chat else "عند مستخدم آخر لحارس",
        "source_en": "in a scam conversation caught by Al-Tu'm" if from_chat else "by another Haris user",
    }


def _clean_list(value, limit: int, max_len: int) -> list[str]:
    if not isinstance(value, list):
        return []
    return [str(v)[:max_len] for v in value[:limit] if isinstance(v, (str, int, float))]


def report(store: Store, payload: dict) -> dict:
    url = str(payload.get("url", ""))[:500]
    norm, host = normalize_url(url)
    if not host:
        return {"ok": False, "error": "missing url"}
    level = payload.get("level") if payload.get("level") in ("high", "medium") else "medium"
    brand = str(payload.get("brand") or "")[:60]
    category = payload.get("category") if payload.get("category") in CATEGORY_TO_SCAM else None
    requested = [r for r in _clean_list(payload.get("requested"), 8, 20) if r in REQUEST_LABELS]
    reasons = _clean_list(payload.get("reasons_ar"), 6, 220)
    signals = _clean_list(payload.get("signals"), 8, 30)

    key = f"haris:{norm}"
    existing = store.recent_case(key, DEDUP_SECONDS)
    if existing:
        store.add_message(existing["id"], "haris", "رُصدت الصفحة نفسها مجدداً عند مستخدم لحارس.")
        return {"ok": True, "case_id": existing["id"], "new": False,
                "linked": store.other_cases_with("url", norm, existing["id"])}

    what = f"تدّعي أنها «{brand}»" if brand else "مشبوهة"
    text = f"رصد حارس صفحة {what} على النطاق {host}"
    if requested:
        text += " وتطلب: " + "، ".join(REQUEST_LABELS[r] for r in requested)
    text += "."
    if reasons:
        text += " الأسباب: " + " · ".join(reasons)

    scam_type = CATEGORY_TO_SCAM.get(category or "", "unknown")
    case_id = store.create_case(key, "haris", contact=host, scam_type=scam_type, status="reported")
    store.add_message(case_id, "haris", text)
    store.add_entities(case_id, [Entity("url", norm, defang(url.split("?")[0]), True)])
    risk = 90 if "known_threat" in signals else 80 if level == "high" else 55
    store.update_case(case_id, risk=risk, state={"haris": {"level": level, "signals": signals,
                                                             "requested": requested, "brand": brand}})
    return {"ok": True, "case_id": case_id, "new": True, "linked": store.other_cases_with("url", norm, case_id)}


def pending_alerts(store: Store) -> list[dict]:
    """Haris cases the police phones have not been told about yet (marks them as told)."""
    out = []
    for row in store.list_cases(50):
        if row["source"] != "haris":
            continue
        state = store.state_of(row)
        if state.get("alerted"):
            continue
        state["alerted"] = True
        store.update_case(row["id"], state=json.dumps(state, ensure_ascii=False), updated=row["updated"])
        ents = store.case_entities(row["id"])
        url = next((e for e in ents if e["type"] == "url"), None)
        linked = store.other_cases_with("url", url["value"], row["id"]) if url else []
        msgs = store.messages(row["id"], limit=1)
        out.append({"case_id": row["id"], "risk": row["risk"] or 0, "url": url["display"] if url else "",
                    "linked": linked, "text": msgs[0]["text"] if msgs else "",
                    "level": state.get("haris", {}).get("level", "")})
    return out
