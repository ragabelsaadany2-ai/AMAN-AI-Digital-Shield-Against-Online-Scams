"""Settings, read from environment variables or a .env file next to the project."""
import os
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def _load_env_file() -> None:
    env = ROOT / ".env"
    if not env.exists():
        return
    for line in env.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        os.environ.setdefault(key.strip(), value.strip().strip('"').strip("'"))


_load_env_file()

TELEGRAM_BOT_TOKEN = os.getenv("TELEGRAM_BOT_TOKEN", "")

# Any OpenAI-compatible chat API: OpenAI, OpenRouter, Groq, a local Ollama or vLLM serving Falcon/Jais ...
LLM_BASE_URL = os.getenv("LLM_BASE_URL", "").rstrip("/")
LLM_API_KEY = os.getenv("LLM_API_KEY", "")
LLM_MODEL = os.getenv("LLM_MODEL", "")
LLM_TIMEOUT = float(os.getenv("LLM_TIMEOUT", "25"))

POLICE_PIN = os.getenv("POLICE_PIN", "2026")
DB_PATH = os.getenv("DB_PATH", str(ROOT / "altum.db"))

DASHBOARD_HOST = os.getenv("DASHBOARD_HOST", "127.0.0.1")
DASHBOARD_PORT = int(os.getenv("DASHBOARD_PORT", "8080"))

# Human-like typing delay before each reply (seconds are computed from reply length).
TYPING_DELAY = os.getenv("TYPING_DELAY", "1") == "1"


def llm_enabled() -> bool:
    return bool(LLM_BASE_URL and LLM_MODEL)
