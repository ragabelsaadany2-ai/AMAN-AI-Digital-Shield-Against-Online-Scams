"""Signals that need nothing but the URL itself (work offline)."""
from __future__ import annotations

import ipaddress
import re
import unicodedata
from urllib.parse import unquote, urlsplit

from .brands import brands, is_popular, official_brand_for, registered_domain

SHORTENERS = {
    "bit.ly", "bitly.com", "tinyurl.com", "t.co", "goo.gl", "is.gd", "v.gd", "cutt.ly", "rebrand.ly", "ow.ly", "s.id",
    "shorturl.at", "rb.gy", "t.ly", "tiny.cc", "buff.ly", "lnkd.in", "shorte.st", "adf.ly", "bl.ink", "short.io",
    "tinu.be", "qrco.de", "urlz.fr", "clck.ru", "u.to", "lnk.bio", "linktr.ee",
}
RISKY_TLDS = {
    "top", "xyz", "icu", "buzz", "shop", "online", "site", "live", "click", "link", "cc", "vip", "sbs", "cfd", "bond",
    "rest", "monster", "cyou", "quest", "lol", "tk", "ml", "ga", "cf", "gq", "pw", "ws", "support", "help", "work",
    "win", "bid", "loan", "date", "racing", "review", "country", "kim", "men", "party", "trade", "webcam", "zip", "mov",
    "store", "fun", "space", "website", "tech", "today", "info", "ltd", "asia", "club",
}
FREE_HOSTS = {
    "weebly.com", "wixsite.com", "firebaseapp.com", "web.app", "pages.dev", "netlify.app", "vercel.app", "github.io",
    "blogspot.com", "000webhostapp.com", "glitch.me", "repl.co", "ngrok.io", "ngrok-free.app", "herokuapp.com",
    "azurewebsites.net", "appspot.com", "workers.dev", "r2.dev", "sites.google.com", "square.site", "godaddysites.com",
    "webflow.io", "framer.website", "carrd.co", "jimdosite.com", "wordpress.com", "duckdns.org", "trycloudflare.com",
}
LURE_WORDS = {
    "login", "signin", "sign-in", "logon", "verify", "verification", "update", "secure", "security", "account", "confirm",
    "payment", "pay", "refund", "fine", "fines", "penalty", "wallet", "kyc", "otp", "unlock", "suspend", "suspended",
    "invoice", "redeliver", "redelivery", "delivery", "parcel", "customs", "reward", "gift", "prize", "claim", "bonus",
    "support", "helpdesk", "service", "portal", "online", "ebanking", "netbanking", "auth", "token", "reset",
}
GEO = {"uae", "dubai", "abudhabi", "emirates", "sharjah", "ajman", "ae"}
HOMOGLYPH = str.maketrans({"0": "o", "1": "l", "3": "e", "4": "a", "5": "s", "7": "t", "8": "b", "@": "a", "$": "s"})


def _sig(code, w, ar, en, ev=""):
    return {"code": code, "w": w, "ar": ar, "en": en, "evidence": ev}


def _lev(a: str, b: str) -> int:
    if a == b:
        return 0
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i]
        for j, cb in enumerate(b, 1):
            cur.append(min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (ca != cb)))
        prev = cur
    return prev[-1]


def _skeleton(label: str) -> str:
    s = label.lower().translate(HOMOGLYPH).replace("rn", "m").replace("vv", "w").replace("cl", "d")
    return re.sub(r"[^a-z]", "", s)


GOV_LURES = {"gov", "fines", "fine", "traffic", "visa", "customs", "refund", "emiratesid", "emirates-id", "police", "ministry", "court"}


# Cyrillic and Greek letters that look like Latin ones (the common IDN homograph set).
CONFUSABLES = str.maketrans({
    "а": "a", "е": "e", "о": "o", "р": "p", "с": "c", "у": "y", "х": "x", "і": "i", "ј": "j", "ѕ": "s",
    "ԁ": "d", "ɡ": "g", "һ": "h", "ӏ": "l", "к": "k", "м": "m", "т": "t", "в": "b", "н": "h", "ո": "n",
    "α": "a", "ο": "o", "ρ": "p", "ε": "e", "ι": "i", "κ": "k", "ν": "v", "τ": "t", "υ": "u", "χ": "x",
})
_LATIN_LIKE = re.compile(r"[A-Za-z\u00C0-\u024F\u0370-\u03FF\u0400-\u04FF]")


def idn_unicode(host: str) -> str:
    try:
        return host.encode("ascii").decode("idna")
    except (UnicodeError, ValueError):
        return host


def idn_ascii(host: str) -> str:
    """xn--tmm-qla.com -> tamm.com (decode punycode, map look-alike letters, drop accents)."""
    u = idn_unicode(host).translate(CONFUSABLES)
    return unicodedata.normalize("NFKD", u).encode("ascii", "ignore").decode()


def is_native_arabic_idn(host: str) -> bool:
    """A domain written only in Arabic script (e.g. دبي.امارات): normal in the UAE, not a Latin look-alike."""
    u = idn_unicode(host)
    return u != host and not _LATIN_LIKE.search(u) and bool(re.search(r"[\u0600-\u06FF]", u))


def parse(url: str):
    url = url.strip()
    if not re.match(r"^[a-zA-Z][a-zA-Z0-9+.\-]*://", url):
        url = "http://" + url
    u = urlsplit(url)
    host = (u.hostname or "").lower().rstrip(".")
    return url, u, host


def brand_hits(host: str, path: str) -> tuple[dict | None, str]:
    """Which UAE brand does this URL try to look like, and how (token / typo / path)?"""
    labels = host.split(".")
    reg = registered_domain(host)
    reg_label = reg.split(".")[0]
    tokens = set(re.split(r"[.\-_]", host))
    for b in brands():
        for t in b.get("tokens", []):
            t = t.lower()
            if t in tokens or ("-" in t and re.search(r"(^|[.\-])" + re.escape(t) + r"($|[.\-])", host)):
                return b, "token"
            if len(t) >= 6:
                for piece in tokens:
                    if t in piece and piece != t:
                        rest = piece.replace(t, "", 1)
                        if len(rest) <= 3 or rest in LURE_WORDS or rest in GEO:
                            return b, "token"
    for b in brands():
        for d in b["domains"]:
            target = d.split(".")[0]
            if len(target) < 4 or reg_label == target:
                continue
            dist = _lev(reg_label, target)
            if (len(target) >= 7 and dist <= 2) or (len(target) >= 5 and dist == 1) or \
               (_skeleton(reg_label) == _skeleton(target) and reg_label != target):
                return b, "typo"
    p = path.lower()
    for b in brands():
        for t in b.get("tokens", []):
            if len(t) >= 4 and re.search(r"(^|[/_\-.])" + re.escape(t) + r"($|[/_\-.])", p):
                return b, "path"
    return None, ""


def analyze(url: str) -> dict:
    url, u, host = parse(url)
    path = unquote(u.path or "") + ("?" + unquote(u.query) if u.query else "")
    reg = registered_domain(host)
    tld = host.rsplit(".", 1)[-1] if "." in host else ""
    sig = []
    official = official_brand_for(host)

    is_ip = False
    try:
        ipaddress.ip_address(host.strip("[]"))
        is_ip = True
    except ValueError:
        pass
    if is_ip:
        sig.append(_sig("ip_host", 30, "الرابط يستخدم عنوان IP بدلاً من اسم نطاق.", "The link uses a raw IP address instead of a domain name.", host))
    if "xn--" in host and not is_native_arabic_idn(host):
        sig.append(_sig("punycode", 30, "النطاق مكتوب بحروف مشفّرة (Punycode) قد تخفي تقليداً لاسم معروف.",
                        "The domain uses punycode, which can hide a look-alike name.", host))
    if "@" in (u.netloc or ""):
        sig.append(_sig("at_sign", 25, "الرابط يحتوي علامة @ تخفي الوجهة الحقيقية.", "The link contains @, which hides the real destination."))
    if reg in SHORTENERS or host in SHORTENERS:
        sig.append(_sig("shortener", 15, "رابط مختصر يخفي الوجهة الحقيقية.", "A URL shortener hides the real destination.", host))
    free = next((f for f in FREE_HOSTS if host == f or host.endswith("." + f)), None)
    if free and not official:
        sig.append(_sig("free_hosting", 15, f"الصفحة مستضافة على خدمة مجانية ({free}).", f"The page is on a free hosting service ({free}).", free))
    if tld in RISKY_TLDS and not official:
        sig.append(_sig("risky_tld", 12, f"امتداد النطاق ‎.{tld} شائع في مواقع الاحتيال.", f"The .{tld} extension is common in scam sites.", tld))
    if u.scheme == "http" and not is_ip:
        sig.append(_sig("no_https", 5, "الاتصال غير مشفّر (http).", "The connection is not encrypted (http)."))
    sub_labels = host[: -len(reg)].strip(".").split(".") if host.endswith(reg) and host != reg else []
    if len(sub_labels) >= 3:
        sig.append(_sig("deep_subdomain", 10, "النطاق يحتوي مستويات فرعية كثيرة.", "The host has many sub-domain levels.", host))
    if host.count("-") >= 3 or len(host) > 45:
        sig.append(_sig("long_host", 8, "اسم النطاق طويل أو كثير الشرطات.", "The host name is unusually long or hyphenated.", host))
    if re.search(r"\d{4,}", reg.split(".")[0]):
        sig.append(_sig("digits_host", 6, "اسم النطاق يحتوي أرقاماً كثيرة.", "The domain name contains many digits."))
    if "//" in (u.path or "")[1:] or re.search(r"https?%3a|https?:/", u.path or "", re.I):
        sig.append(_sig("embedded_url", 12, "الرابط يحتوي رابطاً آخر داخله.", "The link embeds another URL inside it."))
    lures = sorted({w for w in LURE_WORDS if re.search(r"(^|[^a-z])" + re.escape(w) + r"([^a-z]|$)", (host + " " + path).lower())})
    if lures and not official:
        sig.append(_sig("lure_words", min(6 * len(lures), 18), f"الرابط يحتوي كلمات استدراج: {', '.join(lures[:5])}.",
                        f"The link contains lure words: {', '.join(lures[:5])}.", ",".join(lures)))

    if free:
        # On a platform where anyone can publish (sites.google.com, web.app ...), the platform's own name is not
        # impersonation: judge the brand only from the page's own name and path.
        own = host[: -len(free)].strip(".")
        brand, how = brand_hits(own, u.path or "") if own else brand_hits("", u.path or "")
        if not own and brand:
            how = "path"
    else:
        brand, how = brand_hits(host, u.path or "")
    if not brand and "xn--" in host and not is_native_arabic_idn(host):
        brand, how = brand_hits(idn_ascii(host), "")
        if brand:
            how = "typo"
    if brand and not official:
        if how == "typo":
            sig.append(_sig("typosquat", 45, f"اسم النطاق يشبه نطاق «{brand['name_ar']}» مع اختلاف بسيط في الحروف.",
                            f"The domain is a misspelling of {brand['name_en']}'s domain.", f"{reg} ≈ {brand['domains'][0]}"))
        elif how == "token":
            sig.append(_sig("brand_in_domain", 45, f"اسم «{brand['name_ar']}» موجود في نطاق ليس من نطاقاتها الرسمية.",
                            f"{brand['name_en']}'s name appears in a domain it does not own.", f"{host} ∉ {', '.join(brand['domains'])}"))
        elif how == "path" and (lures or is_ip or free):
            sig.append(_sig("brand_in_path", 30, f"الرابط يستخدم اسم «{brand['name_ar']}» مع كلمات استدراج على نطاق آخر.",
                            f"The link uses {brand['name_en']}'s name with lure words on another domain."))
    if brand and brand["category"] == "government" and not official and how in ("token", "typo") and not host.endswith(".gov.ae"):
        sig.append(_sig("fake_gov", 15, "جهة حكومية إماراتية على نطاق لا ينتهي بـ ‎.gov.ae ولا هو من نطاقاتها الرسمية.",
                        "A UAE government brand on a domain that is neither .gov.ae nor one of its official domains."))

    if not official and re.search(r"/wp-(?:content|includes|admin)/", (u.path or "").lower()) and (brand or lures):
        sig.append(_sig("cms_hosted_kit", 12, "صفحة دخول داخل مجلدات ووردبريس، وهو أسلوب شائع لمواقع مخترقة تستضيف صفحات احتيال.",
                        "A login page inside WordPress folders, typical of hacked sites hosting phishing kits."))
    htoks = set(re.split(r"[.\-_]", host))
    hjoined = host.replace(".", "-")
    gov_hits = sorted(t for t in GOV_LURES if t in htoks or ("-" in t and t in hjoined))
    if not official and not host.endswith(".gov.ae") and gov_hits and (htoks & GEO or "gov" in htoks):
        sig.append(_sig("fake_gov_generic", 30, f"نطاق يوحي بجهة حكومية إماراتية ({', '.join(gov_hits)}) لكنه ليس ‎.gov.ae.",
                        f"The domain poses as a UAE government service ({', '.join(gov_hits)}) but is not .gov.ae.", host))
    elif not official and (htoks & GEO) and lures and tld in RISKY_TLDS:
        sig.append(_sig("uae_lure_combo", 15, "النطاق يجمع اسم الإمارات مع كلمات استدراج وامتداد شائع في الاحتيال.",
                        "The domain combines a UAE place name with lure words on a risky extension.", host))

    return {"url": url, "host": host, "registered_domain": reg, "tld": tld, "scheme": u.scheme,
            "official": official, "popular": is_popular(host), "brand": brand, "brand_how": how,
            "is_shortener": reg in SHORTENERS or host in SHORTENERS, "signals": sig}
