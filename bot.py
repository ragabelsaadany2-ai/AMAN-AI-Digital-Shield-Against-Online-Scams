"""Telegram bot for «الطُّعم».

Anyone who writes to the bot is treated as a scammer: the bait persona answers.
A forwarded message is treated as a citizen's report.
Phones registered with /police <PIN> receive live alerts and can pull reports.

Run:  python bot.py
"""
from __future__ import annotations

import asyncio
import html
import logging

from telegram import Update
from telegram.constants import ChatAction, ParseMode
from telegram.ext import Application, CommandHandler, ContextTypes, MessageHandler, filters

from altum import config, haris, report
from altum.classify import risk_label
from altum.dashboard import start_dashboard
from altum.engine import Engine, Turn
from altum.extract import TYPE_LABELS
from altum.store import Store

logging.basicConfig(format="%(asctime)s %(levelname)s %(name)s: %(message)s", level=logging.INFO)
logging.getLogger("httpx").setLevel(logging.WARNING)
log = logging.getLogger("altum.bot")

store = Store(config.DB_PATH)
engine = Engine(store)
_chat_locks: dict[int, asyncio.Lock] = {}

INTRO = (
    "مرحباً بك في النسخة التجريبية من «الطُّعم» 🎣\n\n"
    "• أرسل رسالة كأنك محتال، وسترد عليك إحدى شخصيات الطُّعم.\n"
    "• أو حوّل (Forward) رسالة احتيال وصلتك، وسنفتح بها قضية ونستخرج ما فيها.\n"
    "• /reset يبدأ محادثة جديدة.\n\n"
    "للجهات المختصة: /police <الرمز> لتلقي التنبيهات."
)
POLICE_HELP = (
    "✅ تم تسجيلك كمراقب. ستصلك التنبيهات فور استخراج أي معرّف.\n\n"
    "/cases آخر القضايا\n/report <رقم> البلاغ الكامل\n"
    "/persona <رقم> <abu_salem|reem|khalid> تغيير الشخصية\n/stop إيقاف التنبيهات"
)


def _e(s) -> str:
    return html.escape(str(s))


def _sender(update: Update) -> str:
    u = update.effective_user
    if not u:
        return ""
    return f"@{u.username}" if u.username else f"{u.full_name} ({u.id})"


def _forward_origin(msg) -> str | None:
    """Who the forwarded message originally came from, if Telegram tells us."""
    origin = getattr(msg, "forward_origin", None)
    if origin is None:
        return None
    user = getattr(origin, "sender_user", None)
    if user:
        return f"@{user.username}" if user.username else f"{user.full_name} ({user.id})"
    chat = getattr(origin, "chat", None) or getattr(origin, "sender_chat", None)
    if chat:
        return f"@{chat.username}" if getattr(chat, "username", None) else (chat.title or str(chat.id))
    name = getattr(origin, "sender_user_name", None)
    return name or "مرسل مخفي"


async def _alert(context: ContextTypes.DEFAULT_TYPE, turn: Turn, who: str = "") -> None:
    """Push a live alert to every registered police observer."""
    lines = []
    if turn.is_new_case:
        lines.append(f"🆕 <b>قضية جديدة #{turn.case_id}</b> · {_e(turn.scam_label)}"
                     + (f" · {_e(who)}" if who else ""))
    for ent in turn.new_entities:
        if ent.type == "amount":
            continue
        icon = "🏦" if ent.type == "iban" else "📞" if ent.type == "phone" else "🔗" if ent.type == "url" else "🔎"
        check = "" if ent.type != "iban" else (" ✓ صالح" if ent.valid else " ⚠️ رقم تحقق خاطئ")
        lines.append(f"{icon} <b>{_e(ent.label)}</b> في القضية #{turn.case_id}: <code>{_e(ent.display)}</code>{check}")
        if ent.key in turn.links:
            ids = "، ".join(f"#{i}" for i in turn.links[ent.key])
            lines.append(f"   🕸 مرتبط بالقضايا: {ids}")
    if not lines:
        return
    lines.append(f"الخطورة: {risk_label(turn.risk)} ({turn.risk}/100) · /report {turn.case_id}")
    for chat_id in store.observers():
        try:
            await context.bot.send_message(int(chat_id), "\n".join(lines), parse_mode=ParseMode.HTML)
        except Exception as exc:  # an observer may have blocked the bot
            log.warning("alert to %s failed: %s", chat_id, exc)


async def _type_for(context: ContextTypes.DEFAULT_TYPE, chat_id: int, seconds: float) -> None:
    remaining = seconds
    while remaining > 0:
        await context.bot.send_chat_action(chat_id, ChatAction.TYPING)
        step = min(4.0, remaining)
        await asyncio.sleep(step)
        remaining -= step


# ------------------------------------------------------------------ commands
async def cmd_start(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    await update.message.reply_text(INTRO)


async def cmd_reset(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    closed = store.close_active(f"tg:{update.effective_chat.id}")
    await update.message.reply_text(f"تم إغلاق القضية #{closed}. ابدأ محادثة جديدة." if closed
                                    else "لا توجد محادثة مفتوحة. ابدأ بالكتابة.")


async def cmd_police(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    if not context.args or context.args[0] != config.POLICE_PIN:
        await update.message.reply_text("الرمز غير صحيح.")
        return
    store.add_observer(str(update.effective_chat.id), _sender(update))
    await update.message.reply_text(POLICE_HELP)


async def cmd_stop(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    store.remove_observer(str(update.effective_chat.id))
    await update.message.reply_text("تم إيقاف التنبيهات.")


def _police_only(func):
    async def wrapper(update: Update, context: ContextTypes.DEFAULT_TYPE):
        if not store.is_observer(str(update.effective_chat.id)):
            await update.message.reply_text("هذا الأمر للجهات المختصة فقط. استخدم /police <الرمز>.")
            return
        await func(update, context)
    return wrapper


@_police_only
async def cmd_cases(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    rows = store.list_cases(10)
    if not rows:
        await update.message.reply_text("لا توجد قضايا بعد.")
        return
    from altum.classify import label_for
    lines = [f"#{r['id']} · {label_for(r['scam_type'])} · {risk_label(r['risk'] or 0)} · "
             f"{len(store.case_entities(r['id']))} معرّف · {r['status']}" for r in rows]
    await update.message.reply_text("آخر القضايا:\n" + "\n".join(lines))


@_police_only
async def cmd_report(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    if not context.args or not context.args[0].lstrip("#").isdigit():
        await update.message.reply_text("الاستخدام: /report <رقم القضية>")
        return
    text = report.as_text(store, int(context.args[0].lstrip("#")))
    for i in range(0, len(text), 4000):
        await update.message.reply_text(text[i:i + 4000])


@_police_only
async def cmd_persona(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    if len(context.args) != 2 or not context.args[0].lstrip("#").isdigit():
        await update.message.reply_text("الاستخدام: /persona <رقم القضية> <abu_salem|reem|khalid>")
        return
    ok = engine.set_persona(int(context.args[0].lstrip("#")), context.args[1])
    await update.message.reply_text("تم تغيير الشخصية." if ok else "رقم القضية أو اسم الشخصية غير صحيح.")


# ------------------------------------------------------------------ messages
async def on_text(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    msg = update.message
    if not msg or not msg.text:
        return
    chat_id = update.effective_chat.id
    text = msg.text

    # A forwarded message = a citizen reporting a scam.
    origin = _forward_origin(msg)
    if origin is not None:
        turn = await asyncio.to_thread(engine.handle_report, f"tg:{chat_id}", text, _sender(update),
                                       origin if origin != "مرسل مخفي" else "")
        found = [f"• {e.label}: {e.display}" for e in turn.new_entities if e.type != "amount"]
        reply = (f"شكراً لك 🌟 فتحنا القضية #{turn.case_id} ({turn.scam_label}).\n"
                 + ("استخرجنا:\n" + "\n".join(found) + "\n" if found else "")
                 + "في النسخة التشغيلية يتولى الطُّعم الرد على المحتال من رقم بديل، ولا تحتاج لفعل شيء. "
                   "لا تتواصل معه ولا ترسل له أي بيانات.")
        await msg.reply_text(reply)
        await _alert(context, turn, who="بلاغ مواطن")
        return

    if store.is_observer(str(chat_id)):
        await msg.reply_text("أنت مسجل كمراقب. استخدم /cases أو /report <رقم>، أو /stop لتعمل كمحتال تجريبي.")
        return

    # Otherwise: a scammer is talking to the bait.
    lock = _chat_locks.setdefault(chat_id, asyncio.Lock())
    async with lock:
        await context.bot.send_chat_action(chat_id, ChatAction.TYPING)
        turn = await asyncio.to_thread(engine.handle_scammer, f"tg:{chat_id}", text, _sender(update), "telegram")
        await _alert(context, turn, who=_sender(update))
        if config.TYPING_DELAY and turn.reply:
            await _type_for(context, chat_id, min(1.5 + len(turn.reply) / 30, 6.0))
        if turn.reply:
            await msg.reply_text(turn.reply)
        log.info("case #%s goal=%s persona=%s llm=%s new=%s", turn.case_id, turn.goal, turn.persona,
                 turn.used_llm, [e.display for e in turn.new_entities])


async def _haris_watch(app: Application) -> None:
    """Forward pages reported by the Haris browser extension to the police phones."""
    while True:
        await asyncio.sleep(2)
        try:
            for a in await asyncio.to_thread(haris.pending_alerts, store):
                lines = [f"🛡 <b>حارس رصد صفحة مشبوهة</b> · القضية #{a['case_id']}",
                         f"<code>{_e(a['url'])}</code>", _e(a["text"])]
                if a["linked"]:
                    lines.append("🕸 الرابط نفسه في القضايا: " + "، ".join(f"#{i}" for i in a["linked"]))
                lines.append(f"/report {a['case_id']}")
                for chat_id in store.observers():
                    try:
                        await app.bot.send_message(int(chat_id), "\n".join(lines), parse_mode=ParseMode.HTML)
                    except Exception as exc:
                        log.warning("haris alert to %s failed: %s", chat_id, exc)
        except Exception as exc:  # keep watching whatever happens
            log.warning("haris watch: %s", exc)


async def _post_init(app: Application) -> None:
    app.create_task(_haris_watch(app))


def main() -> None:
    if not config.TELEGRAM_BOT_TOKEN:
        raise SystemExit("ضع TELEGRAM_BOT_TOKEN في ملف .env أولاً (من @BotFather).")
    url = start_dashboard(store)
    log.info("Dashboard: %s", url)
    log.info("Reply mode: %s", "language model" if config.llm_enabled() else "scripted (offline)")

    app = Application.builder().token(config.TELEGRAM_BOT_TOKEN).post_init(_post_init).build()
    app.add_handler(CommandHandler("start", cmd_start))
    app.add_handler(CommandHandler("reset", cmd_reset))
    app.add_handler(CommandHandler("police", cmd_police))
    app.add_handler(CommandHandler("stop", cmd_stop))
    app.add_handler(CommandHandler("cases", cmd_cases))
    app.add_handler(CommandHandler("report", cmd_report))
    app.add_handler(CommandHandler("persona", cmd_persona))
    app.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, on_text))
    app.run_polling(allowed_updates=Update.ALL_TYPES)


if __name__ == "__main__":
    main()
