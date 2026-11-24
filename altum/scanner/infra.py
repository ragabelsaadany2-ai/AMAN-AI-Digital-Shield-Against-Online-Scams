"""Infrastructure evidence: DNS, domain registration (RDAP), hosting network and TLS certificate."""
from __future__ import annotations

import json
import socket
import ssl
import time
import urllib.request
from datetime import datetime, timezone

RDAP_DOMAIN = "https://rdap.org/domain/{}"
RDAP_IP = "https://rdap.org/ip/{}"


def _get_json(url: str, timeout: float = 8.0):
    req = urllib.request.Request(url, headers={"Accept": "application/rdap+json, application/json", "User-Agent": "HarisScanner/0.2"})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return json.loads(r.read(400_000).decode("utf-8", "replace"))


def dns(host: str) -> list[str]:
    try:
        return sorted({ai[4][0] for ai in socket.getaddrinfo(host, None)})[:8]
    except OSError:
        return []


def _vcard_email(entity: dict) -> str:
    for item in (entity.get("vcardArray") or [None, []])[1]:
        if item and item[0] == "email":
            return item[3]
    return ""


def rdap_domain(domain: str) -> dict:
    d = _get_json(RDAP_DOMAIN.format(domain))
    out = {"source": "rdap", "domain": domain}
    for ev in d.get("events", []):
        if ev.get("eventAction") == "registration":
            out["created"] = ev.get("eventDate")
        elif ev.get("eventAction") == "expiration":
            out["expires"] = ev.get("eventDate")
    out["nameservers"] = sorted({(n.get("ldhName") or "").lower() for n in d.get("nameservers", [])})[:6]
    for ent in d.get("entities", []):
        roles = ent.get("roles", [])
        if "registrar" in roles:
            vc = (ent.get("vcardArray") or [None, []])[1]
            out["registrar"] = next((i[3] for i in vc if i and i[0] == "fn"), "")
            for sub in ent.get("entities", []):
                if "abuse" in sub.get("roles", []):
                    out["abuse_email"] = _vcard_email(sub)
        if "abuse" in roles and not out.get("abuse_email"):
            out["abuse_email"] = _vcard_email(ent)
    if out.get("created"):
        try:
            c = datetime.fromisoformat(out["created"].replace("Z", "+00:00"))
            out["age_days"] = (datetime.now(timezone.utc) - c).days
        except ValueError:
            pass
    return out


def rdap_ip(ip: str) -> dict:
    d = _get_json(RDAP_IP.format(ip))
    out = {"ip": ip, "network": d.get("name", ""), "country": d.get("country", "")}
    for ent in d.get("entities", []):
        vc = (ent.get("vcardArray") or [None, []])[1]
        fn = next((i[3] for i in vc if i and i[0] == "fn"), "")
        if fn and not out.get("org"):
            out["org"] = fn
        if "abuse" in ent.get("roles", []) and not out.get("abuse_email"):
            out["abuse_email"] = _vcard_email(ent)
        for sub in ent.get("entities", []):
            if "abuse" in sub.get("roles", []) and not out.get("abuse_email"):
                out["abuse_email"] = _vcard_email(sub)
    return out


def tls_cert(host: str, timeout: float = 6.0) -> dict:
    ctx = ssl.create_default_context()
    with socket.create_connection((host, 443), timeout=timeout) as s:
        with ctx.wrap_socket(s, server_hostname=host) as t:
            c = t.getpeercert()
    issuer = dict(x[0] for x in c.get("issuer", ()))
    nb = ssl.cert_time_to_seconds(c["notBefore"])
    return {"issuer": issuer.get("organizationName", ""), "not_before": c["notBefore"], "not_after": c["notAfter"],
            "age_days": int((time.time() - nb) // 86400),
            "san_count": len(c.get("subjectAltName", ()))}


def collect(host: str, reg: str, https: bool) -> dict:
    """Best-effort: every lookup is optional; failures are recorded, never raised."""
    info = {"collected_at": datetime.now(timezone.utc).isoformat(timespec="seconds")}
    info["ips"] = dns(host)
    try:
        info["whois"] = rdap_domain(reg)
    except Exception as e:
        info["whois_error"] = type(e).__name__
    if info["ips"]:
        try:
            info["hosting"] = rdap_ip(info["ips"][0])
        except Exception as e:
            info["hosting_error"] = type(e).__name__
    if https:
        try:
            info["tls"] = tls_cert(host)
        except Exception as e:
            info["tls_error"] = type(e).__name__
    return info


def _sig(code, w, ar, en, ev=""):
    return {"code": code, "w": w, "ar": ar, "en": en, "evidence": ev}


def signals(info: dict, official: bool) -> list:
    if official:
        return []
    sig = []
    age = (info.get("whois") or {}).get("age_days")
    if age is not None:
        if age < 30:
            sig.append(_sig("new_domain", 30, f"النطاق مسجّل منذ {age} يوماً فقط.", f"The domain was registered only {age} days ago.",
                            (info["whois"] or {}).get("created", "")))
        elif age < 180:
            sig.append(_sig("young_domain", 15, f"النطاق حديث التسجيل ({age} يوماً).", f"The domain is recently registered ({age} days).",
                            (info["whois"] or {}).get("created", "")))
    tls = info.get("tls") or {}
    if tls.get("age_days") is not None and tls["age_days"] < 14:
        sig.append(_sig("fresh_cert", 8, "شهادة الأمان صادرة منذ أيام قليلة.", "The TLS certificate was issued only days ago.", tls.get("not_before", "")))
    return sig
