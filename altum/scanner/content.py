"""Online page checks: redirect chain, shorteners, cloaking, and what the page claims and asks for."""
from __future__ import annotations

import hashlib
import html as htmllib
import re
import ssl
import urllib.error
import urllib.request
from urllib.parse import urljoin, urlsplit

from ..extract import extract_all
from .brands import brands, official_brand_for, registered_domain

UA_USER = ("Mozilla/5.0 (Linux; Android 14; SM-S918B) AppleWebKit/537.36 (KHTML, like Gecko) "
           "Chrome/131.0 Mobile Safari/537.36")
UA_BOT = "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)"
MAX_HOPS = 8
MAX_BYTES = 1_500_000


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *a, **k):
        return None


def _open(url: str, ua: str, timeout: float):
    ctx = ssl.create_default_context()
    opener = urllib.request.build_opener(_NoRedirect, urllib.request.HTTPSHandler(context=ctx))
    req = urllib.request.Request(url, headers={"User-Agent": ua, "Accept-Language": "ar,en;q=0.8"})
    try:
        return opener.open(req, timeout=timeout)
    except urllib.error.HTTPError as e:      # 3xx/4xx/5xx still carry headers and maybe a body
        return e


_META_REFRESH = re.compile(r"""<meta[^>]+http-equiv=["']?refresh["']?[^>]+content=["']?\s*\d+\s*;\s*url=([^"'>\s]+)""", re.I)
_JS_REDIRECT = re.compile(r"""(?:window\.|document\.|top\.)?location(?:\.href)?\s*=\s*["']([^"']{4,300})["']|location\.replace\(\s*["']([^"']+)["']""", re.I)


def fetch(url: str, ua: str = UA_USER, timeout: float = 8.0) -> dict:
    """Follow HTTP, meta-refresh and simple JavaScript redirects; return the chain and the final page."""
    chain, cur, body, status, headers = [], url, b"", None, {}
    for _ in range(MAX_HOPS):
        r = _open(cur, ua, timeout)
        status = getattr(r, "status", None) or getattr(r, "code", None)
        headers = dict(r.headers.items()) if getattr(r, "headers", None) else {}
        chain.append({"url": cur, "status": status})
        loc = headers.get("Location") or headers.get("location")
        if status in (301, 302, 303, 307, 308) and loc:
            cur = urljoin(cur, loc)
            continue
        try:
            body = r.read(MAX_BYTES)
        except Exception:
            body = b""
        text = body.decode("utf-8", "replace")
        m = _META_REFRESH.search(text[:20000])
        j = _JS_REDIRECT.search(text[:20000]) if len(text) < 6000 else None   # only tiny "bounce" pages
        nxt = (m.group(1) if m else None) or (j and (j.group(1) or j.group(2)))
        if nxt and nxt.strip() and not nxt.startswith("#"):
            nxt = urljoin(cur, htmllib.unescape(nxt.strip()))
            if nxt != cur:
                chain[-1]["via"] = "meta/js"
                cur = nxt
                continue
        break
    text = body.decode("utf-8", "replace")
    return {"final_url": cur, "chain": chain, "status": status, "html": text,
            "sha256": hashlib.sha256(body).hexdigest() if body else "", "headers": headers}


# ------------------------------------------------------------------ page parsing
def _text(html: str) -> str:
    h = re.sub(r"(?is)<(script|style|noscript)[^>]*>.*?</\1>", " ", html)
    h = re.sub(r"(?s)<[^>]+>", " ", h)
    return re.sub(r"\s+", " ", htmllib.unescape(h)).strip()


def _attr(tag: str, name: str) -> str:
    m = re.search(name + r"""\s*=\s*["']([^"']*)["']""", tag, re.I)
    return (m.group(1) if m else "").lower()


def page_features(html: str, final_url: str) -> dict:
    host = (urlsplit(final_url).hostname or "").lower()
    title = re.search(r"(?is)<title[^>]*>(.*?)</title>", html)
    title = htmllib.unescape(title.group(1)).strip() if title else ""
    text = _text(html)
    low = (title + " " + text[:8000]).lower()
    inputs = re.findall(r"(?is)<input\b[^>]*>", html)
    kinds = set()
    for tag in inputs:
        t, n = _attr(tag, "type"), " ".join(_attr(tag, a) for a in ("name", "id", "placeholder", "autocomplete", "aria-label"))
        if t in ("hidden", "submit", "button", "checkbox", "radio", "image"):
            continue
        if t == "password" or "password" in n or "كلمة المرور" in n:
            kinds.add("password")
        elif re.search(r"\botp\b|one-time-code|verification|رمز التحقق|كود", n):
            kinds.add("otp")
        elif re.search(r"cc-number|card|cardnumber|بطاقة", n):
            kinds.add("card")
        elif re.search(r"cvv|cvc|cc-csc", n):
            kinds.add("cvv")
        elif re.search(r"emirates.?id|national.?id|رقم الهوية", n):
            kinds.add("id_number")
        elif t == "email" or "email" in n or "البريد" in n:
            kinds.add("email")
    actions = [urljoin(final_url, _attr(f, "action")) for f in re.findall(r"(?is)<form\b[^>]*>", html)]
    ext_actions = [a for a in actions if a and urlsplit(a).hostname and registered_domain(urlsplit(a).hostname) != registered_domain(host)]
    # brand claimed by the page (title counts triple)
    claimed, best = None, 0
    for b in brands():
        n = sum(low.count(a.lower()) for a in b["aliases"]) + 3 * sum(title.lower().count(a.lower()) for a in b["aliases"])
        if n >= 2 and n > best:
            claimed, best = b, n
    # resources loaded from the official brand site (phishing kits copy logos/CSS)
    res_hosts = {(urlsplit(urljoin(final_url, s)).hostname or "").lower()
                 for s in re.findall(r"""(?:src|href)\s*=\s*["']([^"']+)["']""", html, re.I)[:400]}
    borrowed = sorted({h for h in res_hosts if h and official_brand_for(h) and registered_domain(h) != registered_domain(host)})
    obf = bool(re.search(r"eval\s*\(\s*(?:atob|unescape|String\.fromCharCode)|document\.write\s*\(\s*(?:atob|unescape)", html, re.I))
    arabic = len(re.findall(r"[؀-ۿ]", text[:8000]))
    latin = len(re.findall(r"[A-Za-z]", text[:8000]))
    phones = [e for e in extract_all(text[:20000]) if e.type == "phone"]
    return {"title": title[:200], "kinds": sorted(kinds), "form_actions": actions[:10], "external_form_actions": ext_actions[:10],
            "claimed_brand": claimed, "borrowed_resources": borrowed[:10], "obfuscated_js": obf,
            "language": "ar+en" if arabic > 50 and latin > 50 else "ar" if arabic > 50 else "en" if latin > 50 else "",
            "phones": [p.value for p in phones][:10], "text_len": len(text), "iframes": len(re.findall(r"(?i)<iframe\b", html))}


def _sig(code, w, ar, en, ev=""):
    return {"code": code, "w": w, "ar": ar, "en": en, "evidence": ev}


ITEM_AR = {"password": "كلمة المرور", "otp": "رمز التحقق", "card": "بيانات البطاقة", "cvv": "رمز CVV", "id_number": "رقم الهوية"}
ITEM_EN = {"password": "a password", "otp": "a verification code", "card": "card details", "cvv": "a card security code", "id_number": "an ID number"}


def signals(url: str, user: dict, bot: dict | None, lex: dict) -> tuple[list, dict]:
    sig = []
    feats = page_features(user["html"], user["final_url"]) if user.get("html") else {}
    start_reg = registered_domain(urlsplit(url).hostname or "")
    final_host = (urlsplit(user["final_url"]).hostname or "").lower()
    final_reg = registered_domain(final_host)
    official_final = official_brand_for(final_host)
    hops = len(user["chain"]) - 1
    if hops >= 1 and final_reg != start_reg:
        w = 12 if lex.get("is_shortener") else 10
        sig.append(_sig("redirect_offsite", w + (8 if hops >= 3 else 0),
                        f"الرابط يحوّل إلى نطاق آخر ({final_reg}) بعد {hops} تحويلات.",
                        f"The link redirects to another domain ({final_reg}) after {hops} hop(s).",
                        " → ".join(h["url"] for h in user["chain"])[:600]))
    sensitive = [k for k in feats.get("kinds", []) if k in ITEM_AR]
    if "password" in sensitive and "email" in feats.get("kinds", []):
        sensitive = ["password"]
    claimed = feats.get("claimed_brand")
    in_title = bool(claimed) and any(a.lower() in feats.get("title", "").lower() for a in claimed["aliases"])
    if claimed and not official_final and not any(final_host == d or final_host.endswith("." + d) for d in claimed["domains"]) \
            and (sensitive or in_title):
        # A page that only mentions a brand (news, guides) weighs little; asking for secrets weighs a lot.
        sig.append(_sig("claims_brand", 45 if sensitive else 12,
                        f"الصفحة تدّعي أنها «{claimed['name_ar']}» لكنها على نطاق غير رسمي ({final_host})"
                        + (f" وتطلب {('، '.join(ITEM_AR[k] for k in sensitive))}." if sensitive else "."),
                        f"The page claims to be {claimed['name_en']} on an unofficial domain ({final_host})"
                        + (f" and asks for {', '.join(ITEM_EN[k] for k in sensitive)}." if sensitive else "."), claimed["id"]))
    elif sensitive and not official_final and (lex.get("brand") or lex.get("signals")):
        sig.append(_sig("sensitive_form", 15, f"الصفحة تطلب {('، '.join(ITEM_AR[k] for k in sensitive))} على نطاق غير موثوق.",
                        f"The page asks for {', '.join(ITEM_EN[k] for k in sensitive)} on an untrusted domain."))
    if feats.get("external_form_actions") and sensitive:
        sig.append(_sig("form_offsite", 20, "النموذج يرسل البيانات إلى نطاق آخر.", "The form sends data to a different domain.",
                        feats["external_form_actions"][0]))
    if feats.get("borrowed_resources") and not official_final:
        sig.append(_sig("borrowed_assets", 15, "الصفحة تحمّل شعارات أو ملفات من الموقع الرسمي لجهة أخرى.",
                        "The page loads logos or files from another organisation's official site.", ", ".join(feats["borrowed_resources"][:3])))
    if feats.get("obfuscated_js"):
        sig.append(_sig("obfuscated_js", 10, "الصفحة تستخدم شيفرة مخفية (JavaScript مشوّش).", "The page uses obfuscated JavaScript."))
    if claimed and claimed.get("helplines") and feats.get("phones"):
        bad = [p for p in feats["phones"] if p not in claimed["helplines"]]
        if bad:
            sig.append(_sig("fake_helpline", 20, f"رقم التواصل في الصفحة ({bad[0]}) ليس من أرقام «{claimed['name_ar']}» الرسمية.",
                            f"The contact number on the page ({bad[0]}) is not one of {claimed['name_en']}'s official numbers.", bad[0]))
    if bot is not None and user.get("html"):
        bf = page_features(bot["html"], bot["final_url"]) if bot.get("html") else {"kinds": []}
        bot_reg = registered_domain(urlsplit(bot["final_url"]).hostname or "")
        if (bot_reg != final_reg) or (sensitive and not set(sensitive) & set(bf.get("kinds", []))):
            sig.append(_sig("cloaking", 25, "الصفحة تعرض محتوى مختلفاً لمحركات البحث عمّا تعرضه للمستخدم (إخفاء).",
                            "The page shows search engines different content than users (cloaking).",
                            f"user→{final_reg} {sorted(sensitive)} | bot→{bot_reg} {bf.get('kinds')}"))
    if user.get("status") and user["status"] >= 400 and not user.get("html"):
        pass
    feats = dict(feats)
    if claimed:
        feats["claimed_brand"] = claimed["name_en"]
    return sig, feats
