"""SQLite store for OAuth clients, one-time codes and tokens. Plane API tokens are encrypted (Fernet); codes and
access/refresh tokens are stored only as SHA-256 hashes, so a copy of the database file cannot be replayed."""
from __future__ import annotations

import hashlib
import json
import secrets
import sqlite3
import threading
import time
from dataclasses import dataclass

from cryptography.fernet import Fernet, InvalidToken


def digest(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()


@dataclass(frozen=True)
class Client:
    client_id: str
    redirect_uris: list[str]
    name: str


class Store:
    def __init__(self, path: str, encryption_key: str, clock=time.time):
        self._db = sqlite3.connect(path, check_same_thread=False, isolation_level=None)
        self._lock = threading.Lock()
        self._fernet = Fernet(encryption_key.encode())
        self._clock = clock
        with self._lock:
            self._db.executescript(
                """
                CREATE TABLE IF NOT EXISTS clients (client_id TEXT PRIMARY KEY, redirect_uris TEXT NOT NULL, name TEXT NOT NULL, created REAL NOT NULL);
                CREATE TABLE IF NOT EXISTS codes (code_hash TEXT PRIMARY KEY, client_id TEXT NOT NULL, redirect_uri TEXT NOT NULL,
                    challenge TEXT NOT NULL, enc_pat BLOB NOT NULL, expires REAL NOT NULL);
                CREATE TABLE IF NOT EXISTS tokens (access_hash TEXT PRIMARY KEY, refresh_hash TEXT UNIQUE NOT NULL, client_id TEXT NOT NULL,
                    enc_pat BLOB NOT NULL, access_expires REAL NOT NULL, refresh_expires REAL NOT NULL);
                """
            )

    # clients ---------------------------------------------------------
    def add_client(self, redirect_uris: list[str], name: str) -> Client:
        client_id = secrets.token_urlsafe(18)
        with self._lock:
            self._db.execute("INSERT INTO clients VALUES (?,?,?,?)", (client_id, json.dumps(redirect_uris), name[:100], self._clock()))
        return Client(client_id, redirect_uris, name[:100])

    def client(self, client_id: str) -> Client | None:
        with self._lock:
            row = self._db.execute("SELECT redirect_uris, name FROM clients WHERE client_id=?", (client_id,)).fetchone()
        return Client(client_id, json.loads(row[0]), row[1]) if row else None

    # authorization codes (single use, 5 minutes) -------------------------
    def make_code(self, client_id: str, redirect_uri: str, challenge: str, pat: str) -> str:
        code = secrets.token_urlsafe(32)
        with self._lock:
            self._db.execute("INSERT INTO codes VALUES (?,?,?,?,?,?)",
                             (digest(code), client_id, redirect_uri, challenge, self._fernet.encrypt(pat.encode()), self._clock() + 300))
        return code

    def take_code(self, code: str) -> tuple[str, str, str, str] | None:
        """Consumes the code. Returns (client_id, redirect_uri, challenge, pat) or None when unknown, used or expired."""
        with self._lock:
            row = self._db.execute("SELECT client_id, redirect_uri, challenge, enc_pat, expires FROM codes WHERE code_hash=?", (digest(code),)).fetchone()
            self._db.execute("DELETE FROM codes WHERE code_hash=?", (digest(code),))
        if not row or row[4] < self._clock():
            return None
        return row[0], row[1], row[2], self._fernet.decrypt(row[3]).decode()

    # tokens ------------------------------------------------------------
    def make_tokens(self, client_id: str, pat: str, access_ttl: int = 3600, refresh_ttl: int = 30 * 86400) -> tuple[str, str]:
        access, refresh = secrets.token_urlsafe(32), secrets.token_urlsafe(32)
        now = self._clock()
        with self._lock:
            self._db.execute("INSERT INTO tokens VALUES (?,?,?,?,?,?)",
                             (digest(access), digest(refresh), client_id, self._fernet.encrypt(pat.encode()), now + access_ttl, now + refresh_ttl))
        return access, refresh

    def pat_for_access(self, access: str) -> str | None:
        with self._lock:
            row = self._db.execute("SELECT enc_pat, access_expires FROM tokens WHERE access_hash=?", (digest(access),)).fetchone()
        if not row or row[1] < self._clock():
            return None
        try:
            return self._fernet.decrypt(row[0]).decode()
        except InvalidToken:
            return None

    def rotate_refresh(self, refresh: str, client_id: str) -> tuple[str, str] | None:
        """Refresh tokens are single use: the old pair is deleted and a new one is issued."""
        with self._lock:
            row = self._db.execute("SELECT client_id, enc_pat, refresh_expires FROM tokens WHERE refresh_hash=?", (digest(refresh),)).fetchone()
            self._db.execute("DELETE FROM tokens WHERE refresh_hash=?", (digest(refresh),))
        if not row or row[0] != client_id or row[2] < self._clock():
            return None
        return self.make_tokens(client_id, self._fernet.decrypt(row[1]).decode())

    def purge(self) -> None:
        now = self._clock()
        with self._lock:
            self._db.execute("DELETE FROM codes WHERE expires<?", (now,))
            self._db.execute("DELETE FROM tokens WHERE refresh_expires<?", (now,))
