"""Builds the investigator report for a case (plain text for Telegram, HTML for print)."""
from __future__ import annotations

import html
import time

from . import classify, personas
from .extract import NETWORK_TYPES, TYPE_LABELS
from .store import Store


def _fmt_ts(ts: float) -> str:
    return time.strftime("%Y-%m-%d %H:%M", time.localtime(ts))


def gather(store: Store, case_id: int) -> dict | None:
    case = store.get_case(case_id)
    if not case:
        return None
    msgs = store.messages(case_id)
    ents = store.case_entities(case_id)
    linked: dict[int, list[str]] = {}
    for e in ents:
        if e["type"] in NETWORK_TYPES:
            for other in store.other_cases_with(e["type"], e["value"], case_id):
                linked.setdefault(other, []).append(f"{TYPE_LABELS.get(e['type'], e['type'])}: {e['display']}")
    scam_ts = [m["ts"] for m in msgs if m["role"] == "scammer"]
    minutes = (max(scam_ts) - min(scam_ts)) / 60 if len(scam_ts) > 1 else 0

    actions = []
    for e in ents:
        if e["type"] == "iban":
            note = "" if e["valid"] else " (رقم التحقق غير صحيح، يُراجع يدوياً)"
            actions.append(f"مخاطبة البنك المعني لتجميد الحساب {e['display']}{note}")
        elif e["type"] == "phone":
            actions.append(f"طلب بيانات المشترك وحظر الرقم {e['display']}")
        elif e["type"] == "url":
            actions.append(f"طلب حجب النطاق {e['display']}")
        elif e["type"] == "wallet":
            actions.append(f"تتبع المحفظة الرقمية {e['display']} ومخاطبة منصات التداول")
        elif e["type"] in ("tg_handle", "tg_account"):
            actions.append(f"الإبلاغ عن الحساب {e['display']} لدى المنصة")
    if linked:
        actions.append(f"ضم القضايا المرتبطة ({', '.join('#' + str(i) for i in sorted(linked))}) في ملف واحد")

    return {
        "case": case, "messages": msgs, "entities": ents, "linked": linked, "actions": actions,
        "minutes": minutes, "scam_label": classify.label_for(case["scam_type"]),
        "risk_label": classify.risk_label(case["risk"] or 0),
        "persona": "حارس" if case["source"] == "haris" else
                   personas.get(case["persona"]).name if case["persona"] else "—",
    }


def as_text(store: Store, case_id: int, max_lines: int = 14) -> str:
    d = gather(store, case_id)
    if not d:
        return "لا توجد قضية بهذا الرقم."
    c = d["case"]
    out = [
        f"📄 بلاغ آلي — القضية #{c['id']}",
        f"التاريخ: {_fmt_ts(c['created'])}",
        f"النوع: {d['scam_label']} · الخطورة: {d['risk_label']} ({c['risk']}/100)",
        f"الشخصية المستخدمة: {d['persona']} · مدة استنزاف المحتال: {d['minutes']:.0f} دقيقة",
        "",
        "المعرّفات المستخرجة:",
    ]
    for e in d["entities"]:
        mark = "" if e["valid"] else " ⚠️"
        out.append(f"• {TYPE_LABELS.get(e['type'], e['type'])}: {e['display']}{mark}")
    if not d["entities"]:
        out.append("• لا شيء بعد")
    if d["linked"]:
        out += ["", "قضايا مرتبطة:"]
        for other, why in sorted(d["linked"].items()):
            out.append(f"• #{other} ← {'، '.join(why)}")
    if d["actions"]:
        out += ["", "الإجراءات المقترحة (بانتظار قرار المحقق):"]
        out += [f"{i}. {a}" for i, a in enumerate(d["actions"], 1)]
    out += ["", "مقتطف من المحادثة:"]
    who = {"scammer": "المحتال", "bait": "الطُّعم", "reported": "الرسالة المُبلَّغ عنها", "haris": "حارس"}
    for m in d["messages"][-max_lines:]:
        out.append(f"{who.get(m['role'], m['role'])}: {m['text']}")
    return "\n".join(out)


def as_html(store: Store, case_id: int) -> str:
    d = gather(store, case_id)
    if not d:
        return "<p>لا توجد قضية بهذا الرقم.</p>"
    c, e = d["case"], html.escape
    rows = "".join(
        f"<tr><td>{e(TYPE_LABELS.get(x['type'], x['type']))}</td><td dir='auto'>{e(x['display'])}</td>"
        f"<td>{'صالح' if x['valid'] else 'يُراجع'}</td></tr>" for x in d["entities"]) or \
        "<tr><td colspan='3'>لا شيء بعد</td></tr>"
    linked = "".join(f"<li>القضية #{o}: {e('، '.join(w))}</li>" for o, w in sorted(d["linked"].items()))
    actions = "".join(f"<li>{e(a)}</li>" for a in d["actions"])
    who = {"scammer": "المحتال", "bait": "الطُّعم", "reported": "الرسالة المُبلَّغ عنها", "haris": "حارس"}
    chat = "".join(f"<p class='m {m['role']}'><b>{who.get(m['role'], m['role'])}:</b> {e(m['text'])}</p>"
                   for m in d["messages"])
    return f"""<!doctype html><html lang="ar" dir="rtl"><head><meta charset="utf-8">
<title>بلاغ القضية #{c['id']}</title>
<style>
body{{font-family:Tahoma,Arial,sans-serif;max-width:900px;margin:32px auto;padding:0 24px;color:#1B2740;line-height:1.7}}
h1{{color:#0F1B33;border-bottom:4px solid #C08A1E;padding-bottom:8px}} h2{{color:#0F1B33;margin-top:28px}}
table{{border-collapse:collapse;width:100%}} td,th{{border:1px solid #DCE2EC;padding:8px 12px;text-align:right}}
th{{background:#0F1B33;color:#fff}} .meta span{{display:inline-block;margin-left:24px}}
.m{{margin:4px 0;padding:8px 12px;border-radius:8px;background:#EEF1F6}} .m.bait{{background:#FFF6E2}} .m.haris{{background:#E3F1EF}}
.note{{color:#6B7689;font-size:13px;margin-top:32px}} button{{padding:8px 16px}}
@media print{{button{{display:none}}}}
</style></head><body>
<button onclick="window.print()">طباعة / حفظ PDF</button>
<h1>بلاغ آلي — القضية #{c['id']}</h1>
<p class="meta"><span>التاريخ: {_fmt_ts(c['created'])}</span><span>النوع: {e(d['scam_label'])}</span>
<span>الخطورة: {e(d['risk_label'])} ({c['risk']}/100)</span><span>الشخصية: {e(d['persona'])}</span>
<span>مدة الاستنزاف: {d['minutes']:.0f} دقيقة</span></p>
<h2>المعرّفات المستخرجة</h2><table><tr><th>النوع</th><th>القيمة</th><th>التحقق</th></tr>{rows}</table>
{'<h2>قضايا مرتبطة</h2><ul>' + linked + '</ul>' if linked else ''}
{'<h2>الإجراءات المقترحة (بانتظار قرار المحقق)</h2><ol>' + actions + '</ol>' if actions else ''}
<h2>نص المحادثة الكامل</h2>{chat}
<p class="note">أُنشئ هذا البلاغ آلياً بواسطة نظام «الطُّعم». القرار النهائي بيد المحقق المختص.</p>
</body></html>"""
