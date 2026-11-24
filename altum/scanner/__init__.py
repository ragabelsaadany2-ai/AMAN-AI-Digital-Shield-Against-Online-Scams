"""حارس سكانر (Haris Scanner): scores a URL for fraud risk with clear reasons and evidence.

  from altum.scanner import scan_url
  result = scan_url("https://tamm-fines-pay.top/login")   # online checks run when the network allows
"""
from .engine import scan_url, scan_many  # noqa: F401
