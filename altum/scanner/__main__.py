"""Haris Scanner command line.

  python -m altum.scanner scan https://example.top/login            one or more URLs
  python -m altum.scanner scan --input urls.txt --out results.csv    a list (txt: one URL per line, or csv with a 'url' column)
        [--json results.json] [--offline] [--evidence evidence/] [--record]
  python -m altum.scanner watch [--brand tamm] [--feed nrd.txt] --out lookalikes.csv
  python -m altum.scanner listings listings.csv --out listings_checked.csv
  python -m altum.scanner evaluate eval/urls_labeled.csv [--online]
"""
from __future__ import annotations

import argparse
import csv
import json
import sys
from pathlib import Path


def _read_urls(path: str) -> list[str]:
    p = Path(path)
    if p.suffix.lower() == ".csv":
        with open(p, encoding="utf-8-sig") as f:
            rows = list(csv.DictReader(f))
        col = next((c for c in rows[0].keys() if c.lower() in ("url", "link", "urls")), list(rows[0].keys())[0]) if rows else "url"
        return [r[col].strip() for r in rows if r.get(col, "").strip()]
    return [l.strip() for l in p.read_text(encoding="utf-8-sig").splitlines() if l.strip() and not l.startswith("#")]


def cmd_scan(a):
    from . import scan_many
    from .evidence import append_takedown, takedown_row, write_package
    urls = list(a.urls) + (_read_urls(a.input) if a.input else [])
    if not urls:
        sys.exit("no URLs given")
    store = None
    if a.record or a.intel:
        from .. import config
        from ..store import Store
        store = Store(config.DB_PATH)
    results = scan_many(urls, online=not a.offline, store=store, workers=a.workers, timeout=a.timeout)
    rows, takedown = [], []
    for r in results:
        folder = ""
        if a.evidence and r["label"] != "safe":
            folder = str(write_package(r, a.evidence, shot=not a.no_screenshot))
        if a.record and store is not None:
            from .record import record
            record(store, r)
        if r["label"] != "safe":
            takedown.append(takedown_row(r, folder))
        rows.append({"url": r["input"], "label": r["label"], "is_phishing": int(r["label"] == "phishing"),
                     "score": r["score"], "impersonates": r.get("impersonates", ""), "final_url": r["final_url"],
                     "reasons_en": " | ".join(r["reasons_en"]), "reasons_ar": " | ".join(r["reasons_ar"])})
        if not a.quiet:
            print(f"{r['score']:3d}  {r['label']:10s}  {r['input'][:70]}")
            for s in r["signals"][:4]:
                print(f"       - {s['ar']}")
    if a.out:
        with open(a.out, "w", newline="", encoding="utf-8-sig") as f:
            w = csv.DictWriter(f, fieldnames=list(rows[0].keys()))
            w.writeheader(); w.writerows(rows)
        print(f"results -> {a.out}")
    if a.json:
        Path(a.json).write_text(json.dumps([{k: v for k, v in r.items() if k != "_html"} for r in results],
                                           ensure_ascii=False, indent=1, default=str), encoding="utf-8")
    if a.evidence and takedown:
        append_takedown(takedown, Path(a.evidence) / "takedown.csv")
        print(f"evidence -> {a.evidence} ({len(takedown)} flagged, takedown.csv)")


def cmd_watch(a):
    from . import watch
    if a.feed:
        hits = watch.filter_feed(Path(a.feed).read_text(encoding="utf-8").splitlines())
        fields = ["domain", "brand", "how", "score_hint", "reasons_ar"]
    else:
        cands = watch.candidates(a.brand or None, a.per_brand)
        print(f"{len(cands)} look-alike candidates generated", file=sys.stderr)
        if a.offline:
            hits = [{"domain": d, "brand": b} for d, b in cands]
            fields = ["domain", "brand"]
        else:
            hits = watch.check_registered(cands)
            fields = ["domain", "brand", "ips", "created", "age_days", "registrar", "new"]
    for h in hits[:30]:
        print("  ", h["domain"], h.get("brand"), h.get("created", ""), "NEW" if h.get("new") else "")
    if a.out:
        with open(a.out, "w", newline="", encoding="utf-8-sig") as f:
            w = csv.DictWriter(f, fieldnames=fields, extrasaction="ignore")
            w.writeheader()
            for h in hits:
                w.writerow({k: (" | ".join(v) if isinstance(v, list) else v) for k, v in h.items()})
        print(f"{len(hits)} -> {a.out}")


def cmd_listings(a):
    from .listings import check_listing
    p = Path(a.file)
    if p.suffix == ".json":
        rows = json.loads(p.read_text(encoding="utf-8"))
    else:
        with open(p, encoding="utf-8-sig") as f:
            rows = list(csv.DictReader(f))
    out = [check_listing(r) for r in rows]
    for r in out:
        print(f"{r['label']:6s} {r['score']:3d}  {r.get('source', ''):7s} {r.get('name', '')[:40]:40s} {r['reasons_en'][:1]}")
    if a.out:
        with open(a.out, "w", newline="", encoding="utf-8-sig") as f:
            w = csv.DictWriter(f, fieldnames=list(out[0].keys()))
            w.writeheader()
            w.writerows([{k: (" | ".join(v) if isinstance(v, list) else v) for k, v in r.items()} for r in out])


def cmd_evaluate(a):
    from . import scan_many
    with open(a.file, encoding="utf-8-sig") as f:
        data = list(csv.DictReader(f))
    res = scan_many([d["url"] for d in data], online=a.online, workers=8)
    tp = fp = tn = fn = 0
    errors = []
    for d, r in zip(data, res):
        truth = d["label"].strip().lower() in ("phishing", "fraud", "1", "malicious")
        pred = r["label"] != "safe" if a.count_suspicious else r["label"] == "phishing"
        tp += truth and pred; fp += (not truth) and pred; tn += (not truth) and not pred; fn += truth and not pred
        if truth != pred:
            errors.append((d["url"], d["label"], r["label"], r["score"], ", ".join(s["code"] for s in r["signals"])))
    prec = tp / (tp + fp) if tp + fp else 0
    rec = tp / (tp + fn) if tp + fn else 0
    f1 = 2 * prec * rec / (prec + rec) if prec + rec else 0
    print(f"samples {len(data)}  TP {tp}  FP {fp}  TN {tn}  FN {fn}")
    print(f"precision {prec:.3f}  recall {rec:.3f}  F1 {f1:.3f}  false-positive rate {fp / (fp + tn) if fp + tn else 0:.3f}")
    for e in errors:
        print("  MISS" if e[1].lower().startswith("phish") else "  FALSE ALARM", *e, flush=True)


def main(argv=None):
    ap = argparse.ArgumentParser(prog="python -m altum.scanner", description="Haris Scanner")
    sub = ap.add_subparsers(dest="cmd", required=True)
    s = sub.add_parser("scan"); s.add_argument("urls", nargs="*"); s.add_argument("--input"); s.add_argument("--out")
    s.add_argument("--json"); s.add_argument("--offline", action="store_true"); s.add_argument("--evidence")
    s.add_argument("--no-screenshot", action="store_true"); s.add_argument("--record", action="store_true")
    s.add_argument("--intel", action="store_true", help="check the shared Al-Tu'm store for known links")
    s.add_argument("--workers", type=int, default=8); s.add_argument("--timeout", type=float, default=8.0)
    s.add_argument("--quiet", action="store_true"); s.set_defaults(f=cmd_scan)
    w = sub.add_parser("watch"); w.add_argument("--brand", action="append"); w.add_argument("--feed"); w.add_argument("--out")
    w.add_argument("--offline", action="store_true"); w.add_argument("--per-brand", type=int, default=200); w.set_defaults(f=cmd_watch)
    l = sub.add_parser("listings"); l.add_argument("file"); l.add_argument("--out"); l.set_defaults(f=cmd_listings)
    e = sub.add_parser("evaluate"); e.add_argument("file"); e.add_argument("--online", action="store_true")
    e.add_argument("--count-suspicious", action="store_true"); e.set_defaults(f=cmd_evaluate)
    a = ap.parse_args(argv)
    a.f(a)


if __name__ == "__main__":
    main()
