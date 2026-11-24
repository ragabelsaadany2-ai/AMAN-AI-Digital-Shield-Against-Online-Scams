"""SQLite storage for cases, messages, extracted identifiers and police observers."""
from __future__ import annotations

import json
import sqlite3
import threading
import time
from contextlib import contextmanager

from .extract import Entity

SCHEMA = """
CREATE TABLE IF NOT EXISTS cases(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  chat_key TEXT, source TEXT, contact TEXT,
  persona TEXT, scam_type TEXT, risk INTEGER DEFAULT 0,
  status TEXT DEFAULT 'active', created REAL, updated REAL, state TEXT DEFAULT '{}');
CREATE TABLE IF NOT EXISTS messages(
  id INTEGER PRIMARY KEY AUTOINCREMENT, case_id INTEGER, role TEXT, text TEXT, ts REAL, meta TEXT DEFAULT '');
CREATE TABLE IF NOT EXISTS entities(
  id INTEGER PRIMARY KEY AUTOINCREMENT, case_id INTEGER, type TEXT, value TEXT, display TEXT,
  valid INTEGER, ts REAL, UNIQUE(case_id, type, value));
CREATE TABLE IF NOT EXISTS observers(chat_id TEXT PRIMARY KEY, name TEXT, ts REAL);
CREATE INDEX IF NOT EXISTS idx_ent_val ON entities(type, value);
CREATE INDEX IF NOT EXISTS idx_msg_case ON messages(case_id);
CREATE INDEX IF NOT EXISTS idx_case_key ON cases(chat_key, status);
"""


class Store:
    def __init__(self, path: str):
        self.path = path
        self._lock = threading.RLock()
        with self._db() as c:
            c.execute("PRAGMA journal_mode=WAL")
            c.executescript(SCHEMA)

    @contextmanager
    def _db(self):
        with self._lock:
            conn = sqlite3.connect(self.path, timeout=15)
            conn.row_factory = sqlite3.Row
            try:
                yield conn
                conn.commit()
            finally:
                conn.close()

    # ------------------------------------------------------------- cases
    def active_case(self, chat_key: str):
        with self._db() as c:
            return c.execute("SELECT * FROM cases WHERE chat_key=? AND status='active' "
                             "ORDER BY id DESC LIMIT 1", (chat_key,)).fetchone()

    def create_case(self, chat_key: str, source: str, contact: str = "", persona: str | None = None,
                    scam_type: str | None = None, status: str = "active", ts: float | None = None) -> int:
        ts = ts or time.time()
        with self._db() as c:
            cur = c.execute("INSERT INTO cases(chat_key, source, contact, persona, scam_type, status, created, updated)"
                            " VALUES(?,?,?,?,?,?,?,?)", (chat_key, source, contact, persona, scam_type, status, ts, ts))
            return cur.lastrowid

    def get_case(self, case_id: int):
        with self._db() as c:
            return c.execute("SELECT * FROM cases WHERE id=?", (case_id,)).fetchone()

    def update_case(self, case_id: int, **fields) -> None:
        if "state" in fields and not isinstance(fields["state"], str):
            fields["state"] = json.dumps(fields["state"], ensure_ascii=False)
        fields.setdefault("updated", time.time())
        cols = ", ".join(f"{k}=?" for k in fields)
        with self._db() as c:
            c.execute(f"UPDATE cases SET {cols} WHERE id=?", (*fields.values(), case_id))

    def close_active(self, chat_key: str) -> int | None:
        row = self.active_case(chat_key)
        if row:
            self.update_case(row["id"], status="closed")
            return row["id"]
        return None

    def list_cases(self, limit: int = 50):
        with self._db() as c:
            return c.execute("SELECT * FROM cases ORDER BY updated DESC LIMIT ?", (limit,)).fetchall()

    @staticmethod
    def state_of(row) -> dict:
        try:
            return json.loads(row["state"] or "{}")
        except (TypeError, ValueError):
            return {}

    # ---------------------------------------------------------- messages
    def add_message(self, case_id: int, role: str, text: str, ts: float | None = None) -> None:
        ts = ts or time.time()
        with self._db() as c:
            c.execute("INSERT INTO messages(case_id, role, text, ts) VALUES(?,?,?,?)", (case_id, role, text, ts))
            c.execute("UPDATE cases SET updated=? WHERE id=?", (ts, case_id))

    def messages(self, case_id: int, limit: int = 500):
        with self._db() as c:
            rows = c.execute("SELECT * FROM messages WHERE case_id=? ORDER BY id DESC LIMIT ?",
                             (case_id, limit)).fetchall()
        return list(reversed(rows))

    # ---------------------------------------------------------- entities
    def add_entities(self, case_id: int, entities: list[Entity], ts: float | None = None) -> list[Entity]:
        """Store entities; return only the ones that are new for this case."""
        ts = ts or time.time()
        new = []
        with self._db() as c:
            for e in entities:
                cur = c.execute("INSERT OR IGNORE INTO entities(case_id, type, value, display, valid, ts)"
                                " VALUES(?,?,?,?,?,?)", (case_id, e.type, e.value, e.display, int(e.valid), ts))
                if cur.rowcount:
                    new.append(e)
        return new

    def case_entities(self, case_id: int):
        with self._db() as c:
            return c.execute("SELECT * FROM entities WHERE case_id=? ORDER BY id", (case_id,)).fetchall()

    def other_cases_with(self, etype: str, value: str, exclude_case: int) -> list[int]:
        with self._db() as c:
            rows = c.execute("SELECT DISTINCT case_id FROM entities WHERE type=? AND value=? AND case_id<>?"
                             " ORDER BY case_id", (etype, value, exclude_case)).fetchall()
        return [r["case_id"] for r in rows]

    def url_matches(self, norm: str, host: str | None):
        """Cases holding this link (exact host/path), or any link on this host when host is given."""
        with self._db() as c:
            if host:
                q = ("SELECT e.*, c.source, c.status FROM entities e JOIN cases c ON c.id = e.case_id "
                     "WHERE e.type='url' AND (e.value=? OR e.value=? OR e.value LIKE ?) ORDER BY e.ts")
                return c.execute(q, (norm, host, host + "/%")).fetchall()
            q = ("SELECT e.*, c.source, c.status FROM entities e JOIN cases c ON c.id = e.case_id "
                 "WHERE e.type='url' AND e.value=? ORDER BY e.ts")
            return c.execute(q, (norm,)).fetchall()

    def recent_case(self, chat_key: str, within: float):
        with self._db() as c:
            return c.execute("SELECT * FROM cases WHERE chat_key=? AND created>? ORDER BY id DESC LIMIT 1",
                             (chat_key, time.time() - within)).fetchone()

    def all_entities(self):
        with self._db() as c:
            return c.execute("SELECT * FROM entities ORDER BY ts").fetchall()

    def all_messages_stats(self):
        with self._db() as c:
            return c.execute("SELECT case_id, role, COUNT(*) n, MIN(ts) first, MAX(ts) last "
                             "FROM messages GROUP BY case_id, role").fetchall()

    # --------------------------------------------------------- observers
    def add_observer(self, chat_id: str, name: str) -> None:
        with self._db() as c:
            c.execute("INSERT OR REPLACE INTO observers(chat_id, name, ts) VALUES(?,?,?)", (chat_id, name, time.time()))

    def remove_observer(self, chat_id: str) -> None:
        with self._db() as c:
            c.execute("DELETE FROM observers WHERE chat_id=?", (chat_id,))

    def observers(self) -> list[str]:
        with self._db() as c:
            return [r["chat_id"] for r in c.execute("SELECT chat_id FROM observers").fetchall()]

    def is_observer(self, chat_id: str) -> bool:
        return chat_id in self.observers()

    # ------------------------------------------------------------- admin
    def wipe(self) -> None:
        with self._db() as c:
            c.executescript("DELETE FROM messages; DELETE FROM entities; DELETE FROM cases; "
                            "DELETE FROM sqlite_sequence WHERE name IN ('cases','messages','entities');")
