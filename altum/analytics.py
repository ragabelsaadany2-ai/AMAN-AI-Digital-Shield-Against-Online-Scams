"""Builds the live dashboard state: stats, cases, identifiers and the network graph."""
from __future__ import annotations

import time

from . import classify, config, personas
from .extract import NETWORK_TYPES, TYPE_LABELS
from .store import Store


def _components(edges: list[tuple[int, int]], nodes: set[int]) -> list[set[int]]:
    parent = {n: n for n in nodes}

    def find(x):
        while parent[x] != x:
            parent[x] = parent[parent[x]]
            x = parent[x]
        return x

    for a, b in edges:
        ra, rb = find(a), find(b)
        if ra != rb:
            parent[ra] = rb
    groups: dict[int, set[int]] = {}
    for n in nodes:
        groups.setdefault(find(n), set()).add(n)
    return list(groups.values())


def _persona_name(c) -> str:
    if c["source"] == "haris":
        return "حارس"
    return personas.get(c["persona"]).name if c["persona"] else "—"


def build_state(store: Store) -> dict:
    now = time.time()
    cases = store.list_cases(200)
    ents = store.all_entities()
    stats_rows = store.all_messages_stats()

    msg_count: dict[int, int] = {}
    span: dict[int, tuple[float, float]] = {}
    for r in stats_rows:
        msg_count[r["case_id"]] = msg_count.get(r["case_id"], 0) + r["n"]
        if r["role"] == "scammer":
            span[r["case_id"]] = (r["first"], r["last"])

    # identifiers grouped across cases
    by_key: dict[tuple, dict] = {}
    ent_count: dict[int, int] = {}
    for e in ents:
        ent_count[e["case_id"]] = ent_count.get(e["case_id"], 0) + 1
        k = (e["type"], e["value"])
        g = by_key.setdefault(k, {"type": e["type"], "label": TYPE_LABELS.get(e["type"], e["type"]),
                                  "display": e["display"], "valid": bool(e["valid"]),
                                  "cases": [], "first_ts": e["ts"], "last_ts": e["ts"]})
        if e["case_id"] not in g["cases"]:
            g["cases"].append(e["case_id"])
        g["last_ts"] = max(g["last_ts"], e["ts"])

    # network: cases linked through shared identifiers
    case_ids = {c["id"] for c in cases}
    case_edges = []
    for g in by_key.values():
        if g["type"] in NETWORK_TYPES and len(g["cases"]) > 1:
            first = g["cases"][0]
            case_edges += [(first, other) for other in g["cases"][1:]]
    networks = [comp for comp in _components(case_edges, case_ids) if len(comp) > 1]
    network_of = {cid: i + 1 for i, comp in enumerate(networks) for cid in comp}

    nodes, edges = [], []
    for c in cases:
        if c["id"] in ent_count:
            nodes.append({"id": f"c{c['id']}", "label": f"#{c['id']}", "group": "case",
                          "title": classify.label_for(c["scam_type"]),
                          "active": c["status"] == "active"})
    for (t, v), g in by_key.items():
        if t not in NETWORK_TYPES:
            continue
        nid = f"e:{t}:{v}"
        nodes.append({"id": nid, "label": g["display"] if len(g["display"]) <= 30 else g["display"][:28] + "…",
                      "group": t, "title": f"{g['label']}: {g['display']}", "shared": len(g["cases"]) > 1,
                      "fresh": now - g["last_ts"] < 8})
        edges += [{"from": f"c{cid}", "to": nid} for cid in g["cases"]]

    case_list = []
    for c in cases:
        s = span.get(c["id"])
        case_list.append({
            "id": c["id"], "status": c["status"], "source": c["source"],
            "persona": _persona_name(c),
            "scam_label": classify.label_for(c["scam_type"]), "risk": c["risk"] or 0,
            "risk_label": classify.risk_label(c["risk"] or 0),
            "messages": msg_count.get(c["id"], 0), "entities": ent_count.get(c["id"], 0),
            "minutes": round((s[1] - s[0]) / 60, 1) if s else 0,
            "network": network_of.get(c["id"]), "updated": c["updated"], "created": c["created"],
        })

    identifiers = sorted(
        (dict(g, count=len(g["cases"]), fresh=now - g["last_ts"] < 8) for g in by_key.values()
         if g["type"] in NETWORK_TYPES),
        key=lambda g: (-g["count"], -g["last_ts"]))

    live = [c for c in cases if c["source"] != "seed"]
    return {
        "now": now,
        "mode": "llm" if config.llm_enabled() else "scripted",
        "stats": {
            "cases": len(live),
            "active": sum(1 for c in live if c["status"] == "active"),
            "identifiers": sum(1 for g in identifiers if any(cid in {c["id"] for c in live} for cid in g["cases"])),
            "networks": len(networks),
            "haris": sum(1 for c in live if c["source"] == "haris"),
            "minutes": round(sum((span[c["id"]][1] - span[c["id"]][0]) / 60 for c in live if c["id"] in span), 1),
        },
        "cases": case_list,
        "identifiers": identifiers,
        "graph": {"nodes": nodes, "edges": edges},
    }


def case_detail(store: Store, case_id: int) -> dict | None:
    c = store.get_case(case_id)
    if not c:
        return None
    ents = []
    for e in store.case_entities(case_id):
        others = store.other_cases_with(e["type"], e["value"], case_id) if e["type"] in NETWORK_TYPES else []
        ents.append({"type": e["type"], "label": TYPE_LABELS.get(e["type"], e["type"]), "display": e["display"],
                     "valid": bool(e["valid"]), "ts": e["ts"], "linked": others})
    return {
        "id": c["id"], "status": c["status"], "source": c["source"],
        "persona": _persona_name(c),
        "scam_label": classify.label_for(c["scam_type"]), "risk": c["risk"] or 0,
        "risk_label": classify.risk_label(c["risk"] or 0),
        "messages": [{"role": m["role"], "text": m["text"], "ts": m["ts"]} for m in store.messages(case_id)],
        "entities": ents,
    }
