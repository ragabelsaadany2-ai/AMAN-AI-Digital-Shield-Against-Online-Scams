"""Live police dashboard, served with the standard library only.

  /                 the dashboard page
  /api/state        stats, cases, identifiers, network graph (JSON)
  /api/case?id=N    one case: messages and identifiers (JSON)
  /report?id=N      printable report (HTML)

  Haris (browser extension):
  /api/haris/ping           is the server up?
  /api/haris/check?url=...  is this link already known? (GET)
  /api/haris/report         a suspicious page found by Haris (POST, JSON)
  /demo/                    demo pages with a fictional shipping brand

  Haris Scanner:
  /scan                     page to scan links and see reasons
  /api/scan?url=...&online=1    scan one link (GET), or POST {"urls": [...], "online": true}
  /evidence?url=...         printable evidence report for one link
"""
from __future__ import annotations

import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse

from . import analytics, config, haris, report
from .store import Store

PAGE = Path(__file__).with_name("dashboard.html")
DEMO_DIR = Path(__file__).with_name("demo")
DEMO_PAGES = {"": "index.html", "search": "search.html", "falcon-track": "falcon-track.html",
              "falcon-clean": "falcon-clean.html"}


def _handler(store: Store):
    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *args):  # keep the console quiet
            pass

        def _send(self, body: bytes, ctype: str, status: int = 200):
            self.send_response(status)
            self.send_header("Content-Type", ctype)
            self.send_header("Cache-Control", "no-store")
            self.send_header("Access-Control-Allow-Origin", "*")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def _json(self, data, status: int = 200):
            self._send(json.dumps(data, ensure_ascii=False).encode("utf-8"), "application/json; charset=utf-8", status)

        def do_OPTIONS(self):
            self.send_response(204)
            self.send_header("Access-Control-Allow-Origin", "*")
            self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
            self.send_header("Access-Control-Allow-Headers", "Content-Type")
            self.end_headers()

        def do_POST(self):
            url = urlparse(self.path)
            if url.path == "/api/scan":
                try:
                    length = min(int(self.headers.get("Content-Length", "0")), 200000)
                    payload = json.loads(self.rfile.read(length).decode("utf-8") or "{}")
                    urls = [str(u) for u in payload.get("urls", [])][:200]
                except (ValueError, UnicodeDecodeError, AttributeError):
                    self._json({"error": "bad json"}, 400)
                    return
                from .scanner import scan_many
                from .scanner.record import record
                res = scan_many(urls, online=bool(payload.get("online", True)), store=store)
                for r in res:
                    record(store, r)
                self._json([{k: v for k, v in r.items() if k != "_html"} for r in res])
                return
            if url.path != "/api/haris/report":
                self._send(b"not found", "text/plain", 404)
                return
            try:
                length = min(int(self.headers.get("Content-Length", "0")), 20000)
                payload = json.loads(self.rfile.read(length).decode("utf-8") or "{}")
                if not isinstance(payload, dict):
                    raise ValueError
            except (ValueError, UnicodeDecodeError):
                self._json({"ok": False, "error": "bad json"}, 400)
                return
            self._json(haris.report(store, payload))

        def do_GET(self):
            url = urlparse(self.path)
            q = parse_qs(url.query)
            try:
                case_id = int(q.get("id", ["0"])[0])
            except ValueError:
                case_id = 0
            if url.path in ("/", "/index.html"):
                self._send(PAGE.read_bytes(), "text/html; charset=utf-8")
            elif url.path == "/api/state":
                self._json(analytics.build_state(store))
            elif url.path == "/api/case":
                d = analytics.case_detail(store, case_id)
                self._json(d or {"error": "not found"}, 200 if d else 404)
            elif url.path == "/scan":
                self._send(PAGE.with_name("scan.html").read_bytes(), "text/html; charset=utf-8")
            elif url.path in ("/api/scan", "/evidence"):
                from .scanner import scan_url
                from .scanner.evidence import report_html
                from .scanner.record import record
                target = q.get("url", [""])[0]
                if not target:
                    self._json({"error": "missing url"}, 400)
                    return
                r = scan_url(target, online=q.get("online", ["1"])[0] != "0", store=store)
                record(store, r)
                if url.path == "/evidence":
                    self._send(report_html({k: v for k, v in r.items() if k != "_html"}, Path("/nonexistent")).encode("utf-8"),
                               "text/html; charset=utf-8")
                else:
                    self._json({k: v for k, v in r.items() if k != "_html"})
            elif url.path == "/api/haris/ping":
                self._json({"ok": True, "name": "altum"})
            elif url.path == "/api/haris/check":
                self._json(haris.check(store, q.get("url", [""])[0]))
            elif url.path.startswith("/demo"):
                name = DEMO_PAGES.get(url.path[len("/demo"):].strip("/"))
                if name:
                    self._send((DEMO_DIR / name).read_bytes(), "text/html; charset=utf-8")
                else:
                    self._send(b"not found", "text/plain", 404)
            elif url.path == "/static/vis-network.min.js":
                lib = PAGE.with_name("vis-network.min.js")
                if lib.exists():
                    self._send(lib.read_bytes(), "application/javascript")
                else:
                    self._send(b"", "application/javascript", 404)
            elif url.path == "/report":
                self._send(report.as_html(store, case_id).encode("utf-8"), "text/html; charset=utf-8")
            else:
                self._send(b"not found", "text/plain", 404)

    return Handler


def start_dashboard(store: Store, host: str | None = None, port: int | None = None) -> str:
    host = host or config.DASHBOARD_HOST
    port = port or config.DASHBOARD_PORT
    server = ThreadingHTTPServer((host, port), _handler(store))
    threading.Thread(target=server.serve_forever, daemon=True, name="dashboard").start()
    return f"http://{'127.0.0.1' if host == '0.0.0.0' else host}:{port}"


if __name__ == "__main__":
    import time
    print("لوحة التحكم:", start_dashboard(Store(config.DB_PATH)))
    try:
        while True:
            time.sleep(3600)
    except KeyboardInterrupt:
        pass
