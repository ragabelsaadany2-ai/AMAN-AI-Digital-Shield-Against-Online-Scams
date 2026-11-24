"""UAE brand reference: official domains, URL tokens and helplines (shared with the Haris extension)."""
from __future__ import annotations

import json
from functools import lru_cache
from pathlib import Path

BRANDS_FILE = Path(__file__).resolve().parents[2] / "haris-extension" / "brands.json"

# Multi-part public suffixes we need to find the registered domain without a download.
MULTI_SUFFIXES = {
    "gov.ae", "ac.ae", "co.ae", "net.ae", "org.ae", "sch.ae", "mil.ae", "com.sa", "gov.sa", "com.qa", "com.kw", "com.bh",
    "com.om", "com.eg", "co.uk", "org.uk", "gov.uk", "com.au", "co.in", "com.pk", "com.tr", "co.za", "com.br",
}

# Widely used sites, never flagged on reputation alone (content and threat intel still apply).
POPULAR = {
    "google.com", "youtube.com", "facebook.com", "instagram.com", "whatsapp.com", "x.com", "twitter.com", "linkedin.com",
    "microsoft.com", "live.com", "office.com", "apple.com", "icloud.com", "amazon.com", "amazon.ae", "noon.com",
    "wikipedia.org", "github.com", "yahoo.com", "bing.com", "netflix.com", "paypal.com", "tiktok.com", "snapchat.com",
    "telegram.org", "zoom.us", "gulfnews.com", "khaleejtimes.com", "thenationalnews.com", "wam.ae", "emirates.com",
    "etihad.com", "dubizzle.com", "careem.com", "talabat.com", "carrefouruae.com", "luluhypermarket.com",
}


@lru_cache(maxsize=1)
def brands() -> list[dict]:
    with open(BRANDS_FILE, encoding="utf-8") as f:
        return json.load(f)["brands"]


def registered_domain(host: str) -> str:
    host = host.lower().strip(".").split(":")[0]
    parts = host.split(".")
    if len(parts) >= 3 and ".".join(parts[-2:]) in MULTI_SUFFIXES:
        return ".".join(parts[-3:])
    return ".".join(parts[-2:]) if len(parts) >= 2 else host


# Sub-domains of a brand where anyone can publish a page: they never count as the brand's official site.
USER_CONTENT_HOSTS = {"sites.google.com", "storage.googleapis.com", "firebasestorage.googleapis.com"}


def official_brand_for(host: str) -> dict | None:
    h = host.lower().split(":")[0]
    if h.startswith("www."):
        h = h[4:]
    if any(h == u or h.endswith("." + u) for u in USER_CONTENT_HOSTS):
        return None
    for b in brands():
        if any(h == d or h.endswith("." + d) for d in b["domains"]):
            return b
    return None


def is_gov_domain(host: str) -> bool:
    h = host.lower().split(":")[0]
    return h.endswith(".gov.ae") or official_brand_for(h) is not None and official_brand_for(h)["category"] == "government"


def is_popular(host: str) -> bool:
    return registered_domain(host) in POPULAR
