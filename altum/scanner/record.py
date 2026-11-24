"""Save scanner findings in the shared store, so scam domains that share hosting link up on the police map."""
from __future__ import annotations

from ..extract import Entity, defang, normalize_url
from ..store import Store

CATEGORY_TO_SCAM = {"shipping": "delivery", "bank": "bank", "government": "gov", "telecom": "unknown"}


def record(store: Store, r: dict) -> int | None:
    if r["label"] == "safe":
        return None
    norm, host = normalize_url(r["final_url"])
    key = f"scanner:{r['registered_domain']}"
    existing = store.recent_case(key, 86400)
    case_id = existing["id"] if existing else store.create_case(key, "scanner", contact=host, status="reported")
    ents = [Entity("url", norm, defang(r["final_url"].split("?")[0]))]
    if r["final_url"] != r["url"]:
        n0, _ = normalize_url(r["url"])
        ents.append(Entity("url", n0, defang(r["url"].split("?")[0])))
    inf = r.get("infra") or {}
    ents += [Entity("ip", ip, ip) for ip in inf.get("ips", [])[:3]]
    ents += [Entity("ns", ns, ns) for ns in (inf.get("whois") or {}).get("nameservers", [])[:3]]
    store.add_entities(case_id, ents)
    text = f"فحص حارس سكانر: {r['label_ar']} ({r['score']}/100)"
    if r.get("impersonates"):
        text += f" · يقلّد {r['impersonates']}"
    text += ". " + " · ".join(r["reasons_ar"][:4])
    store.add_message(case_id, "haris", text)
    store.update_case(case_id, risk=r["score"], scam_type="unknown")
    return case_id
