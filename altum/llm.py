"""Minimal client for any OpenAI-compatible chat API, using only the standard library."""
from __future__ import annotations

import json
import logging
import re
import urllib.error
import urllib.request

from . import config

log = logging.getLogger("altum.llm")
_THINK = re.compile(r"<think>.*?</think>", re.S)


def chat(messages: list[dict], temperature: float = 0.8, max_tokens: int = 220) -> str | None:
    """Return the model's reply text, or None if no model is set up or the call fails."""
    if not config.llm_enabled():
        return None
    body = json.dumps({
        "model": config.LLM_MODEL,
        "messages": messages,
        "temperature": temperature,
        "max_tokens": max_tokens,
    }).encode("utf-8")
    headers = {"Content-Type": "application/json"}
    if config.LLM_API_KEY:
        headers["Authorization"] = f"Bearer {config.LLM_API_KEY}"
    req = urllib.request.Request(f"{config.LLM_BASE_URL}/chat/completions", data=body, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=config.LLM_TIMEOUT) as resp:
            data = json.loads(resp.read().decode("utf-8"))
        text = data["choices"][0]["message"]["content"] or ""
        return _THINK.sub("", text).strip() or None
    except (urllib.error.URLError, TimeoutError, KeyError, IndexError, ValueError) as exc:
        log.warning("LLM call failed, using scripted reply: %s", exc)
        return None
