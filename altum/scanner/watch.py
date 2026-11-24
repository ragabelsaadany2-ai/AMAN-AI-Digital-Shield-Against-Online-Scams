"""Early detection: find look-alike domains of UAE brands before victims report them.

Two sources:
  1. generate  - permutations of each official domain (typos, homoglyphs, brand+lure word, other TLDs),
                 then check which ones are registered (DNS) and how new they are (RDAP).
  2. feed      - filter a newly-registered-domains list (one domain per line, e.g. a daily NRD feed)
                 for names that imitate a UAE brand.
"""
from __future__ import annotations

import itertools
from concurrent.futures import ThreadPoolExecutor

from . import infra, lexical
from .brands import brands, official_brand_for

LURES = ["pay", "fine", "fines", "login", "verify", "update", "secure", "refund", "portal", "online", "service", "support",
         "ae", "uae", "gov", "app", "track", "delivery"]
TLDS = ["com", "net", "org", "info", "online", "site", "top", "xyz", "shop", "live", "click", "icu", "ae", "co"]
GLYPHS = {"o": "0", "l": "1", "i": "1", "e": "3", "a": "4", "s": "5", "b": "8", "m": "rn", "w": "vv", "d": "cl"}


def permutations(domain: str, limit: int = 400) -> list[str]:
    label, _, tld = domain.partition(".")
    out = set()
    for i in range(len(label)):                                       # omission, repetition, homoglyph
        out.add(label[:i] + label[i + 1:])
        out.add(label[:i] + label[i] + label[i:])
        if label[i] in GLYPHS:
            out.add(label[:i] + GLYPHS[label[i]] + label[i + 1:])
    for i in range(len(label) - 1):                                   # transposition, hyphenation
        out.add(label[:i] + label[i + 1] + label[i] + label[i + 2:])
        out.add(label[:i + 1] + "-" + label[i + 1:])
    names = {f"{n}.{tld}" for n in out if len(n) >= 3 and n != label}
    for lure, t in itertools.product(LURES, ["com", "online", "top", "site", "info"]):   # combosquatting
        names.add(f"{label}-{lure}.{t}")
        names.add(f"{lure}-{label}.{t}")
    for t in TLDS:                                                    # same name, other extension
        if t != tld:
            names.add(f"{label}.{t}")
    return sorted(n for n in names if not official_brand_for(n))[:limit]


def candidates(brand_ids: list[str] | None = None, per_brand: int = 200) -> list[tuple[str, str]]:
    out = []
    for b in brands():
        if b.get("demo") or (brand_ids and b["id"] not in brand_ids):
            continue
        for d in b["domains"]:
            if d.count(".") == 1:
                out += [(c, b["id"]) for c in permutations(d, per_brand)]
    return out


def check_registered(domains: list[tuple[str, str]], workers: int = 32) -> list[dict]:
    def one(item):
        dom, bid = item
        ips = infra.dns(dom)
        if not ips:
            return None
        rec = {"domain": dom, "brand": bid, "ips": ips}
        try:
            w = infra.rdap_domain(dom)
            rec.update({"created": w.get("created", ""), "age_days": w.get("age_days"), "registrar": w.get("registrar", "")})
        except Exception:
            pass
        rec["new"] = rec.get("age_days") is not None and rec["age_days"] < 90
        return rec
    with ThreadPoolExecutor(max_workers=workers) as ex:
        return [r for r in ex.map(one, domains) if r]


def filter_feed(lines: list[str]) -> list[dict]:
    """Keep the newly registered domains that look like a UAE brand."""
    hits = []
    for raw in lines:
        dom = raw.strip().lower()
        if not dom or dom.startswith("#") or official_brand_for(dom):
            continue
        brand, how = lexical.brand_hits(dom, "")
        if brand and how in ("token", "typo"):
            a = lexical.analyze(dom)
            hits.append({"domain": dom, "brand": brand["id"], "how": how,
                         "score_hint": sum(s["w"] for s in a["signals"]), "reasons_ar": [s["ar"] for s in a["signals"]]})
    return sorted(hits, key=lambda h: -h["score_hint"])
