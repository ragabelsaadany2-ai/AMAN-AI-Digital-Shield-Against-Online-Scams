"""Evidence package for the police and takedown requests.

For each flagged URL: report.json (everything, UTC timestamps), page.html + SHA-256, screenshot.png
(if Playwright + Chrome are installed), report.html (bilingual, printable), and one row in takedown.csv.
"""
from __future__ import annotations

import csv
import hashlib
import html
import json
import re
from datetime import datetime, timezone
from pathlib import Path

TAKEDOWN_FIELDS = ["reported_at_utc", "url", "final_url", "domain", "label", "score", "impersonates", "ips", "registrar",
                   "registrar_abuse", "domain_created", "hosting_org", "hosting_abuse", "page_sha256", "reasons_en", "evidence_dir"]


def _slug(s: str) -> str:
    return re.sub(r"[^a-zA-Z0-9.\-]+", "_", s)[:60]


def screenshot(url: str, path: Path) -> bool:
    try:
        from playwright.sync_api import sync_playwright
    except ImportError:
        return False
    try:
        with sync_playwright() as p:
            try:
                b = p.chromium.launch()
            except Exception:
                b = p.chromium.launch(channel="chrome")
            pg = b.new_page(viewport={"width": 1280, "height": 900})
            pg.goto(url, timeout=15000, wait_until="domcontentloaded")
            pg.wait_for_timeout(1200)
            pg.screenshot(path=str(path), full_page=False)
            b.close()
        return True
    except Exception:
        return False


def takedown_row(r: dict, folder: str = "") -> dict:
    inf = r.get("infra") or {}
    w, h = inf.get("whois") or {}, inf.get("hosting") or {}
    return {"reported_at_utc": r["scanned_at"], "url": r["url"], "final_url": r["final_url"], "domain": r["registered_domain"],
            "label": r["label"], "score": r["score"], "impersonates": r.get("impersonates", ""), "ips": " ".join(inf.get("ips", [])),
            "registrar": w.get("registrar", ""), "registrar_abuse": w.get("abuse_email", ""), "domain_created": w.get("created", ""),
            "hosting_org": h.get("org", "") or h.get("network", ""), "hosting_abuse": h.get("abuse_email", ""),
            "page_sha256": r.get("page_sha256", ""), "reasons_en": " | ".join(r["reasons_en"]), "evidence_dir": folder}


def write_package(r: dict, root: str | Path, shot: bool = True) -> Path:
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    d = Path(root) / f"{stamp}_{_slug(r['registered_domain'] or r['host'])}"
    d.mkdir(parents=True, exist_ok=True)
    page = r.get("_html") or ""
    if page:
        (d / "page.html").write_text(page, encoding="utf-8")
    data = {k: v for k, v in r.items() if k != "_html"}
    data["evidence_files"] = {}
    if page:
        data["evidence_files"]["page.html"] = hashlib.sha256(page.encode("utf-8")).hexdigest()
    if shot and r.get("online") and screenshot(r["final_url"], d / "screenshot.png"):
        data["evidence_files"]["screenshot.png"] = hashlib.sha256((d / "screenshot.png").read_bytes()).hexdigest()
    (d / "report.json").write_text(json.dumps(data, ensure_ascii=False, indent=1, default=str), encoding="utf-8")
    (d / "report.html").write_text(report_html(data, d), encoding="utf-8")
    return d


def report_html(r: dict, d: Path) -> str:
    e = html.escape
    inf = r.get("infra") or {}
    w, h, t = inf.get("whois") or {}, inf.get("hosting") or {}, inf.get("tls") or {}
    rows = [("الرابط · URL", r["url"]), ("الوجهة النهائية · Final URL", r["final_url"]),
            ("سلسلة التحويل · Redirects", " → ".join(x["url"] for x in r.get("chain", [])) or "—"),
            ("الجهة المقلَّدة · Impersonates", r.get("impersonates") or "—"),
            ("عناوين IP", " ".join(inf.get("ips", [])) or "—"),
            ("المسجِّل · Registrar", w.get("registrar", "—")), ("تاريخ التسجيل · Created", w.get("created", "—")),
            ("بريد بلاغات المسجِّل · Registrar abuse", w.get("abuse_email", "—")),
            ("الاستضافة · Hosting", (h.get("org") or h.get("network") or "—") + (f" ({h.get('country')})" if h.get("country") else "")),
            ("بريد بلاغات الاستضافة · Hosting abuse", h.get("abuse_email", "—")),
            ("الشهادة · TLS", f"{t.get('issuer', '—')} · {t.get('not_before', '')}" if t else "—"),
            ("بصمة الصفحة · Page SHA-256", r.get("page_sha256") or "—"), ("وقت الفحص · Scanned (UTC)", r["scanned_at"])]
    reasons = "".join(f"<li><b>{e(s['ar'])}</b><br><span class='en'>{e(s['en'])}</span>"
                      + (f"<br><code>{e(str(s.get('evidence', ''))[:300])}</code>" if s.get("evidence") else "") + "</li>" for s in r["signals"])
    shot = "<img src='screenshot.png' alt='screenshot'>" if (d / "screenshot.png").exists() else "<p class='en'>No screenshot (offline scan or Playwright not installed).</p>"
    color = {"phishing": "#B4232A", "suspicious": "#B7791F", "safe": "#1F7A6F"}[r["label"]]
    return f"""<!doctype html><html lang="ar" dir="rtl"><head><meta charset="utf-8"><title>Evidence · {e(r['registered_domain'])}</title>
<style>body{{font-family:Tahoma,Arial,sans-serif;max-width:980px;margin:30px auto;padding:0 24px;color:#1B2740}}
.badge{{display:inline-block;background:{color};color:#fff;padding:8px 18px;border-radius:10px;font-size:22px;font-weight:bold}}
table{{border-collapse:collapse;width:100%;margin:16px 0}} td{{border:1px solid #DCE2EC;padding:8px 10px;vertical-align:top;word-break:break-all}}
td:first-child{{background:#F4F6F9;width:30%;font-weight:bold}} li{{margin:8px 0}} .en{{color:#5A6478;direction:ltr;display:inline-block}}
code{{font-size:12px;color:#5A6478;direction:ltr;display:inline-block}} img{{max-width:100%;border:1px solid #DCE2EC}}
@media print{{button{{display:none}}}}</style></head><body>
<button onclick="window.print()">طباعة / حفظ PDF</button>
<h1>حزمة أدلة · Evidence package</h1>
<p><span class="badge">{e(r['label_ar'])} · {e(r['label_en'])} · {r['score']}/100</span></p>
<table>{''.join(f'<tr><td>{e(k)}</td><td>{e(str(v))}</td></tr>' for k, v in rows)}</table>
<h2>الأسباب · Reasons</h2><ol>{reasons}</ol>
<h2>لقطة الشاشة · Screenshot</h2>{shot}
<p class="en">Generated by Haris Scanner (Al-Tu'm × Haris). Hashes of the saved files are in report.json. Final decision rests with the investigator.</p>
</body></html>"""


def append_takedown(rows: list[dict], path: str | Path) -> None:
    path = Path(path)
    new = not path.exists()
    with open(path, "a", newline="", encoding="utf-8-sig") as f:
        wr = csv.DictWriter(f, fieldnames=TAKEDOWN_FIELDS)
        if new:
            wr.writeheader()
        wr.writerows(rows)
