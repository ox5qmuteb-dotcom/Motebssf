"""Tiny SQLite-backed JSON document store."""
import json
import os
import sqlite3
import threading
import time

TABLES = ("events", "alerts", "scans", "audit")


class Store:
    def __init__(self, path):
        if path != ":memory:":
            os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
        self._db = sqlite3.connect(path, check_same_thread=False)
        self._lock = threading.Lock()
        with self._lock:
            for t in TABLES:
                self._db.execute(
                    f"CREATE TABLE IF NOT EXISTS {t} (id INTEGER PRIMARY KEY AUTOINCREMENT,"
                    " ts REAL NOT NULL, data TEXT NOT NULL)")
            self._db.execute(
                "CREATE TABLE IF NOT EXISTS users (name TEXT PRIMARY KEY, role TEXT NOT NULL,"
                " key_hash TEXT NOT NULL UNIQUE, active INTEGER NOT NULL DEFAULT 1)")
            self._db.commit()

    def add(self, table, data):
        if table not in TABLES:
            raise ValueError("invalid table")
        with self._lock:
            cur = self._db.execute(f"INSERT INTO {table} (ts, data) VALUES (?, ?)",
                                   (time.time(), json.dumps(data)))
            self._db.commit()
            return cur.lastrowid

    def list(self, table, limit=100, since=None):
        if table not in TABLES:
            raise ValueError("invalid table")
        q, args = f"SELECT id, ts, data FROM {table}", []
        if since is not None:
            q += " WHERE ts >= ?"
            args.append(since)
        q += " ORDER BY id DESC LIMIT ?"
        args.append(max(1, min(int(limit), 1000)))
        with self._lock:
            rows = self._db.execute(q, args).fetchall()
        return [{"id": i, "ts": ts, **json.loads(d)} for i, ts, d in rows]

    def get(self, table, id_):
        if table not in TABLES:
            raise ValueError("invalid table")
        with self._lock:
            r = self._db.execute(f"SELECT id, ts, data FROM {table} WHERE id=?", (id_,)).fetchone()
        return {"id": r[0], "ts": r[1], **json.loads(r[2])} if r else None

    def execute(self, sql, args=()):
        with self._lock:
            cur = self._db.execute(sql, args)
            self._db.commit()
            return cur.fetchall()
