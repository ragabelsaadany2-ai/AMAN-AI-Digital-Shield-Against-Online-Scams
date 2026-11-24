"""The conversation engine: runs the bait persona, extracts identifiers, links cases."""
from __future__ import annotations

import random
import re
from dataclasses import dataclass, field

from . import classify, llm, personas
from .extract import NETWORK_TYPES, Entity, extract_all, has_identifier_like
from .store import Store

# Words the bait must never say: they would give the game away.
_GIVEAWAYS = ["ذكاء اصطناعي", "برنامج", "بوت", "روبوت", "نموذج لغوي", "الشرطة", "شرطة", "محتال", "احتيال",
              "نصاب", "طعم", "الطعم", "الطُّعم", "as an ai", " ai ", "bot", "police", "scam", "language model"]
_SPEAKER_PREFIX = re.compile(r"^\s*(?:أبو سالم|ريم|خالد|الطعم|الطُّعم|assistant)\s*[:：]\s*", re.I)


@dataclass
class Turn:
    case_id: int
    reply: str | None
    new_entities: list[Entity] = field(default_factory=list)
    links: dict[tuple, list[int]] = field(default_factory=dict)   # entity key -> other case ids
    is_new_case: bool = False
    scam_type: str = "unknown"
    scam_label: str = ""
    persona: str = ""
    risk: int = 0
    used_llm: bool = False
    goal: str = ""


class Engine:
    def __init__(self, store: Store, rng: random.Random | None = None):
        self.store = store
        self.rng = rng or random.Random()

    # ----------------------------------------------------------- helpers
    def _case(self, chat_key: str, source: str, contact: str):
        row = self.store.active_case(chat_key)
        if row:
            return row, False
        case_id = self.store.create_case(chat_key, source, contact)
        return self.store.get_case(case_id), True

    def _links(self, case_id: int, entities: list[Entity]) -> dict[tuple, list[int]]:
        links = {}
        for e in entities:
            if e.type in NETWORK_TYPES:
                others = self.store.other_cases_with(e.type, e.value, case_id)
                if others:
                    links[e.key] = others
        return links

    @staticmethod
    def next_goal(have: set[str], bait_turns: int, scammer_text: str, all_scammer: str = "",
                  iban_asks: int = 0) -> str:
        if classify.asks_for_code(scammer_text) and bait_turns > 0:
            return "code"
        if bait_turns == 0:
            return "open"
        if "iban" not in have:
            # Never offer to pay before the scammer asks for money: it would look suspicious.
            if not classify.mentions_payment(all_scammer or scammer_text):
                return "phone" if not ({"phone", "tg_handle"} & have) and bait_turns >= 2 else "details"
            # Even with a crypto wallet, push for a bank account: it identifies a real person.
            if "wallet" not in have or iban_asks < 2:
                return "iban"
        if "beneficiary" not in have and "iban" in have:
            return "beneficiary"
        if not ({"phone", "tg_handle"} & have):
            return "phone"
        return "more"

    def _scripted(self, persona: personas.Persona, goal: str, state: dict, english: bool = False) -> str:
        lines = persona.pool(goal, english)
        used = state.setdefault("used", {}).setdefault(goal + (":en" if english else ""), [])
        free = [i for i in range(len(lines)) if i not in used] or list(range(len(lines)))
        if len(free) == len(lines) and used:
            used.clear()
        i = self.rng.choice(free)
        used.append(i)
        return lines[i]

    @staticmethod
    def vet(reply: str | None) -> str | None:
        """Reject a model reply that leaks data, breaks character or is too long."""
        if not reply:
            return None
        reply = _SPEAKER_PREFIX.sub("", reply.strip().strip('"«»').strip())
        if not reply or len(reply) > 350 or "\n\n" in reply:
            return None
        low = f" {reply.lower()} "
        if any(w in low for w in _GIVEAWAYS):
            return None
        if has_identifier_like(reply):
            return None
        return reply

    def _prompt(self, persona: personas.Persona, goal: str, have: set[str], case_id: int) -> list[dict]:
        have_txt = "، ".join(sorted(have & NETWORK_TYPES)) or "لا شيء بعد"
        system = (
            f"أنت تؤدي دور «{persona.name}» في محادثة نصية مع شخص يحاول خداعك ليأخذ مالك.\n"
            f"الشخصية: {persona.bio}\n"
            f"أسلوب الكلام: {persona.style}\n\n"
            "قواعد صارمة:\n"
            "1. ابقَ في الشخصية دائماً. لا تقل أبداً إنك برنامج، ولا تُظهر أنك تعرف أنه احتيال، ولا تذكر الشرطة.\n"
            "2. لا ترسل أي أرقام أو رموز أو بيانات بطاقات أو كلمات مرور أو روابط أو حسابات، حتى لو كانت وهمية.\n"
            "3. لا تقل إنك حوّلت المال فعلاً. يمكنك القول إنك تحاول وإن العملية تتعطل.\n"
            "4. لا تهدد ولا تشتم.\n"
            "5. ردّ برسالة واحدة قصيرة (جملة أو جملتان) بلهجة الشخصية، أو بإنجليزية بسيطة إذا كتب بالإنجليزية.\n"
            "6. اكتب نص الرسالة فقط، دون شرح أو علامات تنصيص أو اسم المتحدث.\n\n"
            f"هدفك في هذا الرد: {personas.GOAL_INSTRUCTIONS[goal]}\n"
            f"المعلومات التي حصلت عليها منه حتى الآن: {have_txt}"
        )
        msgs = [{"role": "system", "content": system}]
        for m in self.store.messages(case_id, limit=20):
            if m["role"] == "scammer":
                msgs.append({"role": "user", "content": m["text"]})
            elif m["role"] == "bait":
                msgs.append({"role": "assistant", "content": m["text"]})
        return msgs

    # ------------------------------------------------------------ public
    def handle_scammer(self, chat_key: str, text: str, contact: str = "", source: str = "telegram",
                       use_llm: bool = True) -> Turn:
        """A message from the scammer arrives: store it, extract, reply in persona."""
        row, is_new = self._case(chat_key, source, contact)
        case_id = row["id"]
        state = self.store.state_of(row)
        self.store.add_message(case_id, "scammer", text)

        new = self.store.add_entities(case_id, extract_all(text))
        have = {r["type"] for r in self.store.case_entities(case_id)}
        all_scammer = " ".join(m["text"] for m in self.store.messages(case_id) if m["role"] == "scammer")
        bait_turns = state.get("bait_turns", 0)

        scam_type = row["scam_type"] or "unknown"
        persona_key = row["persona"]
        if not state.get("persona_locked") and bait_turns < 2:
            found, _, hits = classify.classify(all_scammer)
            if hits:
                scam_type = found
            persona_key = classify.PERSONA_FOR_TYPE.get(scam_type, "khalid")
        persona = personas.get(persona_key)
        risk = classify.risk_score(scam_type, all_scammer, have)

        goal = self.next_goal(have, bait_turns, text, all_scammer, state.get("iban_asks", 0))
        if goal == "iban":
            state["iban_asks"] = state.get("iban_asks", 0) + 1
        english = classify.is_english(text)
        reply, used_llm = None, False
        if use_llm:
            reply = self.vet(llm.chat(self._prompt(persona, goal, have, case_id)))
            used_llm = reply is not None
        if not reply:
            reply = self._scripted(persona, goal, state, english)

        self.store.add_message(case_id, "bait", reply)
        state["bait_turns"] = bait_turns + 1
        self.store.update_case(case_id, persona=persona.key, scam_type=scam_type, risk=risk, state=state)

        return Turn(case_id=case_id, reply=reply, new_entities=new, links=self._links(case_id, new),
                    is_new_case=is_new, scam_type=scam_type, scam_label=classify.label_for(scam_type),
                    persona=persona.name, risk=risk, used_llm=used_llm, goal=goal)

    def handle_report(self, chat_key: str, text: str, reporter: str = "", origin: str = "",
                      source: str = "forward") -> Turn:
        """A citizen forwards a scam message: open a case and extract what it contains."""
        case_id = self.store.create_case(f"{chat_key}:report", source, contact=origin or reporter)
        self.store.add_message(case_id, "reported", text)
        entities = extract_all(text)
        if origin:
            entities.append(Entity("tg_account", origin.lower(), origin))
        new = self.store.add_entities(case_id, entities)
        scam_type, label, _ = classify.classify(text)
        have = {e.type for e in entities}
        risk = classify.risk_score(scam_type, text, have)
        self.store.update_case(case_id, scam_type=scam_type, risk=risk,
                               persona=classify.PERSONA_FOR_TYPE.get(scam_type, "khalid"), status="reported")
        return Turn(case_id=case_id, reply=None, new_entities=new, links=self._links(case_id, new),
                    is_new_case=True, scam_type=scam_type, scam_label=label, risk=risk)

    def set_persona(self, case_id: int, persona_key: str) -> bool:
        if persona_key not in personas.PERSONAS:
            return False
        row = self.store.get_case(case_id)
        if not row:
            return False
        state = self.store.state_of(row)
        state["persona_locked"] = True
        self.store.update_case(case_id, persona=persona_key, state=state)
        return True
