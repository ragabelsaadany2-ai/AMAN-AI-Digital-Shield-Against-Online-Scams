"""Combines URL, page, infrastructure and shared-intelligence signals into one explainable risk score."""
from __future__ import annotations

import math
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from urllib.parse import urlsplit

from . import content, infra, lexical
from .brands import official_brand_for, registered_domain

LABELS = {"phishing": ("احتيالي", "Phishing"), "suspicious": ("مشبوه", "Suspicious"), "safe": ("آمن", "Likely safe")}
PHISHING_AT, SUSPICIOUS_AT = 60, 40


def _score(signals: list) -> int:
    total = sum(s["w"] for s in signals)
    return int(round(100 * (1 - math.exp(-total / 45)))) if total > 0 else 0


def _label(score: int) -> str:
    return "phishing" if score >= PHISHING_AT else "suspicious" if score >= SUSPICIOUS_AT else "safe"


def scan_url(url: str, online: bool = True, store=None, timeout: float = 8.0) -> dict:
    started = datetime.now(timezone.utc)
    lex = lexical.analyze(url)
    sig = list(lex["signals"])
    result = {"input": url, "url": lex["url"], "final_url": lex["url"], "scanned_at": started.isoformat(timespec="seconds"),
              "online": online, "chain": [], "page": {}, "infra": {}, "errors": []}

    if online:
        try:
            user = content.fetch(lex["url"], content.UA_USER, timeout)
            result["final_url"], result["chain"], result["http_status"] = user["final_url"], user["chain"], user["status"]
            result["page_sha256"] = user["sha256"]
            result["_html"] = user["html"]
            bot = None
            if user["html"] and ("<input" in user["html"].lower() or lex["brand"]):
                try:
                    bot = content.fetch(lex["url"], content.UA_BOT, timeout)
                except Exception as e:
                    result["errors"].append(f"bot fetch: {type(e).__name__}")
            csig, feats = content.signals(lex["url"], user, bot, lex)
            sig += csig
            result["page"] = feats
        except Exception as e:
            result["errors"].append(f"fetch: {type(e).__name__}: {str(e)[:120]}")

    final_host = (urlsplit(result["final_url"]).hostname or lex["host"]).lower()
    if final_host and final_host != lex["host"]:
        # the landing page gets the same URL checks as the link that led there
        flex = lexical.analyze(result["final_url"])
        have = {s["code"] for s in sig}
        for s in flex["signals"]:
            if s["code"] not in have:
                s = dict(s, ar="بعد التحويل: " + s["ar"], en="After redirect: " + s["en"])
                sig.append(s)
        if flex["brand"] and not lex["brand"]:
            lex["brand"] = flex["brand"]
    final_reg = registered_domain(final_host)
    official = official_brand_for(final_host)
    if online:
        info = infra.collect(final_host, final_reg, result["final_url"].startswith("https"))
        result["infra"] = info
        sig += infra.signals(info, bool(official) or lexical.is_popular(final_host))

    if store is not None:
        from ..haris import check
        k = check(store, result["final_url"])
        if not k.get("known") and result["final_url"] != lex["url"]:
            k = check(store, lex["url"])
        if k.get("known"):
            sig.append({"code": "known_threat", "w": 70, "ar": f"الرابط رُصد {k['ago_ar']} {k['source_ar']} (القضية #{k['case_id']}).",
                        "en": f"The link was seen {k['ago_en']} {k['source_en']}.", "evidence": f"cases {k['case_ids']}"})
            result["intel"] = k

    # Trust: official brand domains and very popular sites are not flagged on look-alike style signals.
    gov_ae = final_host.endswith(".gov.ae")                      # the .gov.ae registry is restricted to UAE government bodies
    # Pages anyone can publish on a popular platform (sites.google.com, forms ...) do not inherit its trust.
    user_content = any(s["code"] == "free_hosting" for s in sig) and not official
    popular = lexical.is_popular(final_host) and not user_content
    if (official or gov_ae or popular) and not any(s["code"] == "known_threat" for s in sig):
        keep = {"cloaking", "form_offsite"} if not official else set()
        sig = [s for s in sig if s["code"] in keep]
        result["trusted"] = official["name_en"] if official else ".gov.ae" if gov_ae else "popular site"

    sig.sort(key=lambda s: -s["w"])
    score = _score(sig)
    label = _label(score)
    result.update({
        "host": final_host, "registered_domain": final_reg, "score": score, "label": label,
        "label_ar": LABELS[label][0], "label_en": LABELS[label][1],
        "impersonates": "" if result.get("trusted") else (lex["brand"] or {}).get("name_en") or result["page"].get("claimed_brand") or "",
        "signals": sig,
        "reasons_ar": [s["ar"] for s in sig], "reasons_en": [s["en"] for s in sig],
        "duration_ms": int((datetime.now(timezone.utc) - started).total_seconds() * 1000),
    })
    return result


def scan_many(urls: list[str], online: bool = True, store=None, workers: int = 8, timeout: float = 8.0) -> list[dict]:
    with ThreadPoolExecutor(max_workers=workers if online else 1) as ex:
        return list(ex.map(lambda u: scan_url(u, online, store, timeout), urls))
