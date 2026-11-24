"""Rehearse without Telegram: you type as the scammer, the bait replies.

The dashboard runs too and updates live, exactly as in the Telegram demo.

  python cli_chat.py            # uses the language model if .env sets one
  python cli_chat.py --offline  # scripted replies only

Commands: /reset  /report  /persona <abu_salem|reem|khalid>  /quit
"""
import sys

from altum import config, report
from altum.dashboard import start_dashboard
from altum.engine import Engine
from altum.store import Store


def main() -> None:
    offline = "--offline" in sys.argv
    store = Store(config.DB_PATH)
    engine = Engine(store)
    print("لوحة التحكم:", start_dashboard(store))
    print("وضع الردود:", "نصوص جاهزة" if offline or not config.llm_enabled() else f"نموذج لغوي ({config.LLM_MODEL})")
    print("اكتب كأنك محتال. الأوامر: /reset /report /persona <اسم> /quit\n")
    key = "cli:1"
    while True:
        try:
            text = input("المحتال> ").strip()
        except (EOFError, KeyboardInterrupt):
            break
        if not text:
            continue
        if text == "/quit":
            break
        if text == "/reset":
            print("أُغلقت القضية", store.close_active(key))
            continue
        row = store.active_case(key)
        if text == "/report":
            print(report.as_text(store, row["id"]) if row else "لا توجد قضية مفتوحة.")
            continue
        if text.startswith("/persona"):
            parts = text.split()
            print("تم." if row and len(parts) == 2 and engine.set_persona(row["id"], parts[1]) else "غير صحيح.")
            continue
        turn = engine.handle_scammer(key, text, contact="تجربة محلية", source="cli", use_llm=not offline)
        for e in turn.new_entities:
            extra = f"  ← مرتبط بالقضايا {turn.links[e.key]}" if e.key in turn.links else ""
            print(f"   🔎 {e.label}: {e.display}{'' if e.valid else ' (⚠ رقم تحقق خاطئ)'}{extra}")
        print(f"{turn.persona}> {turn.reply}")
        print(f"   [قضية #{turn.case_id} · {turn.scam_label} · خطورة {turn.risk} · هدف: {turn.goal}"
              f"{' · نموذج' if turn.used_llm else ''}]\n")


if __name__ == "__main__":
    main()
