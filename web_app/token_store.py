"""Where each user's Egnyte tokens live, and the one-time states that start a sign-in.

FileTokenStore keeps one encrypted file per user (Fernet: AES-128-CBC + HMAC-SHA256) in a directory.
On App Service that directory is /home/data/..., which is persistent storage. File names are a hash of
the user key, so nothing a user controls ever becomes a path. The encryption keys come from Key Vault.

LIMITS (fine for a test deployment, not for production): the per-user locks only work inside one
process, so run a single gunicorn worker (the README's startup command does). For several workers or
several instances, replace this class with one backed by Azure Table Storage or SQL, with a lease or
row lock around refresh. PendingStates is in memory for the same reason.
"""
import hashlib
import json
import logging
import os
import secrets
import threading
import time
from dataclasses import asdict, dataclass
from typing import Optional

from cryptography.fernet import Fernet, InvalidToken, MultiFernet

log = logging.getLogger("egnyte.tokenstore")


@dataclass(frozen=True)
class TokenRecord:
    access_token: str
    refresh_token: Optional[str]
    expires_at: Optional[float]
    egnyte_username: str
    linked_at: float

    @classmethod
    def from_dict(cls, data):
        record = cls(**{name: data[name] for name in cls.__dataclass_fields__})
        if not isinstance(record.access_token, str) or not record.access_token:
            raise ValueError("bad access token")
        return record


class FileTokenStore:
    def __init__(self, directory, keys):
        if not keys:
            raise ValueError("at least one encryption key is required")
        # The first key encrypts; every key can decrypt, which allows key rotation.
        self._fernet = MultiFernet([Fernet(key) for key in keys])  # ValueError for a malformed key
        self.directory = os.path.abspath(directory)
        os.makedirs(self.directory, mode=0o700, exist_ok=True)
        self._locks = {}
        self._locks_guard = threading.Lock()

    def _path(self, user_key):
        return os.path.join(self.directory, hashlib.sha256(user_key.encode("utf-8")).hexdigest() + ".tok")

    def lock_for(self, user_key):
        """One reentrant lock per user (within this process). Reads and writes of a user's file take it,
        and callers hold it around a whole refresh, so a refresh can't interleave with another one."""
        with self._locks_guard:
            return self._locks.setdefault(user_key, threading.RLock())

    def save(self, user_key, record):
        path = self._path(user_key)
        blob = self._fernet.encrypt(json.dumps(asdict(record)).encode("utf-8"))
        temp = f"{path}.{secrets.token_hex(4)}.tmp"
        with self.lock_for(user_key):
            fd = os.open(temp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0), 0o600)
            try:
                with os.fdopen(fd, "wb") as fp:
                    fp.write(blob)
                    fp.flush()
                    os.fsync(fp.fileno())
                os.replace(temp, path)
            except BaseException:
                try:
                    os.remove(temp)
                except OSError:
                    pass
                raise

    def load(self, user_key):
        """The user's TokenRecord, or None if they have none or it can't be read (they just connect again)."""
        try:
            with self.lock_for(user_key), open(self._path(user_key), "rb") as fp:
                blob = fp.read()
        except FileNotFoundError:
            return None
        try:
            return TokenRecord.from_dict(json.loads(self._fernet.decrypt(blob).decode("utf-8")))
        except (InvalidToken, ValueError, KeyError, TypeError):
            log.warning("A stored token could not be read (was TOKEN_ENCRYPTION_KEYS changed?); ignoring it.")
            return None

    def delete(self, user_key):
        with self.lock_for(user_key):
            try:
                os.remove(self._path(user_key))
            except FileNotFoundError:
                pass


class PendingStates:
    """One-time `state` values for sign-ins in progress, each tied to the user who started it.

    A state can be consumed once, only by the same user, and only within `ttl` seconds."""

    def __init__(self, ttl=600, max_entries=1000, clock=time.monotonic):
        self._ttl, self._max, self._clock = ttl, max_entries, clock
        self._items = {}
        self._lock = threading.Lock()

    def _purge(self):
        now = self._clock()
        for state in [s for s, (_, expires) in self._items.items() if expires <= now]:
            del self._items[state]

    def create(self, user_key):
        state = secrets.token_urlsafe(32)
        with self._lock:
            self._purge()
            while len(self._items) >= self._max:
                del self._items[next(iter(self._items))]  # drop the oldest
            self._items[state] = (user_key, self._clock() + self._ttl)
        return state

    def consume(self, state, user_key):
        """True only the first time, for the user who created this state, before it expires."""
        with self._lock:
            entry = self._items.pop(state, None)
        if entry is None:
            return False
        owner, expires = entry
        return expires > self._clock() and secrets.compare_digest(owner.encode("utf-8"), user_key.encode("utf-8"))
