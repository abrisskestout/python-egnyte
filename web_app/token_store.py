"""Where each user's Egnyte tokens live, and the one-time states that start a sign-in.

CosmosTokenStore is the store the deployed site uses: one document per user in an Azure Cosmos DB for NoSQL
container. The app signs in to Cosmos DB with its managed identity (Microsoft Entra ID); there is no account key
and no connection string anywhere, and the account has key-based access switched off. The document id is a
hash of the user key, so nothing a user controls ever becomes a document id. Each piece of the token data is its
own field, so the document reads at a glance in Data Explorer: the Egnyte user name and the times are plain,
and only the two secrets, access_token and refresh_token, are encrypted by this app (Fernet: AES-128-CBC +
HMAC-SHA256, one ciphertext per field) before they are sent, with keys from Key Vault, so a person who can read
the database still can't read a token.

FileTokenStore keeps one encrypted file per user in a directory. It is only for running on your own PC without a
Cosmos DB account (the site refuses to start on App Service without one).

LIMITS (fine for a test deployment, not for production): the per-user locks only work inside one process, so
run a single gunicorn worker on a single instance (the README's startup command does). Cosmos DB would let
several instances share the tokens, but two instances could still refresh the same user's token at the same
moment; fixing that needs a lock or an ETag check around refresh. PendingStates is in memory for the same reason.
"""
import calendar
import hashlib
import json
import logging
import os
import secrets
import threading
import time
from dataclasses import asdict, dataclass
from typing import Optional

from azure.core.exceptions import AzureError
from cryptography.fernet import Fernet, InvalidToken, MultiFernet

log = logging.getLogger("egnyte.tokenstore")

COSMOS_DOCUMENT_VERSION = 2             # 1 was a single encrypted "data" field; it was never deployed
COSMOS_OWNER_RESOURCE_MISSING = 1003    # sub-status of a 404 that means the database or container doesn't exist
LOG_DETAIL_LIMIT = 500
TIME_FORMAT = "%Y-%m-%dT%H:%M:%SZ"      # UTC, to the second: how times read in the Cosmos DB document


class TokenStoreError(Exception):
    """The token database could not be used. The message is safe to show: a status code, never any details."""


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
        if not isinstance(record.egnyte_username, str) or not isinstance(record.linked_at, (int, float)):
            raise ValueError("bad record")
        return record


def user_id(user_key):
    """The stable, storage-safe name for a user: a hash, so the identity itself never appears in the store."""
    return hashlib.sha256(user_key.encode("utf-8")).hexdigest()


class _SealedStore:
    """What both stores share: encrypting a TokenRecord, and one lock per user."""

    def __init__(self, keys):
        if not keys:
            raise ValueError("at least one encryption key is required")
        # The first key encrypts; every key can decrypt, which allows key rotation.
        self._fernet = MultiFernet([Fernet(key) for key in keys])  # ValueError for a malformed key
        self._locks = {}
        self._locks_guard = threading.Lock()

    def lock_for(self, user_key):
        """One reentrant lock per user (within this process). Callers hold it around a whole refresh, so a
        refresh can't interleave with another one."""
        with self._locks_guard:
            return self._locks.setdefault(user_key, threading.RLock())

    def _seal(self, record):
        return self._fernet.encrypt(json.dumps(asdict(record)).encode("utf-8"))

    def _unseal(self, blob):
        """The TokenRecord in an encrypted blob, or None if it can't be read (the user just connects again)."""
        try:
            return TokenRecord.from_dict(json.loads(self._fernet.decrypt(blob).decode("utf-8")))
        except (InvalidToken, ValueError, KeyError, TypeError):
            return self._unreadable()

    def _seal_text(self, text):
        """One secret as an encrypted string that is safe to keep in a JSON document."""
        return self._fernet.encrypt(text.encode("utf-8")).decode("ascii")

    def _unseal_text(self, token):
        """The secret in _seal_text's output. Raises InvalidToken, TypeError or ValueError if it can't be read."""
        if not isinstance(token, str):
            raise TypeError("an encrypted field is not text")
        return self._fernet.decrypt(token.encode("ascii", "replace")).decode("utf-8")

    @staticmethod
    def _unreadable():
        log.warning("A stored token could not be read (was TOKEN_ENCRYPTION_KEYS changed?); ignoring it.")
        return None


def _time_text(epoch):
    """Seconds since the epoch as readable UTC text ('2026-12-19T14:02:11Z'); None stays None."""
    return None if epoch is None else time.strftime(TIME_FORMAT, time.gmtime(epoch))


def _epoch(text):
    """The reverse of _time_text. None stays None; anything that isn't exactly that format is a ValueError."""
    if text is None:
        return None
    if not isinstance(text, str):
        raise TypeError("a time is not text")
    return float(calendar.timegm(time.strptime(text, TIME_FORMAT)))


def _status(error):
    return getattr(error, "status_code", None)


def _is_missing_item(error):
    """A 404 for a document that isn't there. A 404 because the database or container doesn't exist is a
    configuration fault, not 'this user has no token', and must not be mistaken for one."""
    return _status(error) == 404 and getattr(error, "sub_status", None) != COSMOS_OWNER_RESOURCE_MISSING


class CosmosContainerSource:
    """Opens the Cosmos DB container on first use, signed in with a Microsoft Entra identity.

    On App Service that identity is the web app's managed identity; on your PC it is whatever `az login` set up.
    It is opened lazily because the Cosmos DB client contacts the account when it is created: a fault in the
    configuration should show up as an error page (and a log line), not stop the site from starting."""

    def __init__(self, endpoint, database, container, on_azure=False, credential=None, client_factory=None):
        self.endpoint, self.database, self.container, self.on_azure = endpoint, database, container, on_azure
        self._credential, self._client_factory = credential, client_factory
        self._opened = None
        self._guard = threading.Lock()

    def _make_credential(self):
        from azure.identity import DefaultAzureCredential, ManagedIdentityCredential
        # On Azure use the managed identity and nothing else, so a broken identity is an error rather than a
        # silent fall-back to some other credential. On a PC, use the developer's `az login`.
        return ManagedIdentityCredential() if self.on_azure else DefaultAzureCredential()

    def __call__(self):
        with self._guard:
            if self._opened is None:
                try:
                    factory = self._client_factory
                    if factory is None:
                        from azure.cosmos import CosmosClient as factory
                    client = factory(self.endpoint, credential=self._credential or self._make_credential())
                    self._opened = client.get_database_client(self.database).get_container_client(self.container)
                except AzureError as e:
                    raise _store_error("open the token database", e) from None
            return self._opened


def _store_error(what, error):
    status = _status(error)
    log.warning("Could not %s: %s status=%s sub_status=%s: %s", what, type(error).__name__, status,
                getattr(error, "sub_status", None), str(error)[:LOG_DETAIL_LIMIT])
    detail = f"HTTP {status}" if status else type(error).__name__
    return TokenStoreError(f"The token database could not be reached ({detail}).")


class CosmosTokenStore(_SealedStore):
    """One Cosmos DB document per user, one field per piece of the token data:

        id               hash of the user key (also the partition key)
        v                document layout version
        egnyte_username  plain text
        linked_at        plain, UTC ('2026-11-19T14:02:11Z')
        expires_at       plain, UTC; null when Egnyte didn't say
        access_token     encrypted
        refresh_token    encrypted; null when there is none
        updated          plain, UTC: when this document was last written

    Times are kept to the second. Only the two tokens are secret, so only they are encrypted; the plain fields can
    be edited by anyone with write access to the database, which can at worst make the page show a wrong name or
    make a token be refreshed early or late (Egnyte still decides whether a token works).

    `container` is a Cosmos DB container (ContainerProxy), or a function that returns one when first called
    (see CosmosContainerSource). Only point reads, writes and deletes are used, by id, so the account needs no
    query or index. Any failure other than "no such document" raises TokenStoreError and is never turned into
    "not connected": a database outage must not look like the user having no Egnyte link."""

    def __init__(self, container, keys):
        super().__init__(keys)
        self._container_source = container if callable(container) else (lambda: container)

    def _call(self, what, fn, missing_ok=False):
        """Run fn(container). With missing_ok, "that document doesn't exist" gives None instead of an error."""
        try:
            return fn(self._container_source())
        except TokenStoreError:
            raise
        except AzureError as e:     # Cosmos DB errors, failed sign-in of the identity, network errors
            if missing_ok and _is_missing_item(e):
                return None
            raise _store_error(what, e) from None

    def save(self, user_key, record):
        document = {"id": user_id(user_key), "v": COSMOS_DOCUMENT_VERSION,
                    "egnyte_username": record.egnyte_username,
                    "linked_at": _time_text(record.linked_at),
                    "expires_at": _time_text(record.expires_at),
                    "access_token": self._seal_text(record.access_token),
                    "refresh_token": None if record.refresh_token is None else self._seal_text(record.refresh_token),
                    "updated": _time_text(time.time())}
        self._call("save a token", lambda container: container.upsert_item(document))

    def load(self, user_key):
        """The user's TokenRecord, or None if they have none or it can't be read (they just connect again)."""
        item_id = user_id(user_key)
        document = self._call("read a token", lambda container: container.read_item(item=item_id, partition_key=item_id),
                              missing_ok=True)
        if not isinstance(document, dict) or document.get("v") != COSMOS_DOCUMENT_VERSION:
            return None
        try:
            refresh = document.get("refresh_token")
            return TokenRecord.from_dict({
                "access_token": self._unseal_text(document["access_token"]),
                "refresh_token": None if refresh is None else self._unseal_text(refresh),
                "expires_at": _epoch(document.get("expires_at")),
                "egnyte_username": document["egnyte_username"],
                "linked_at": _epoch(document["linked_at"])})
        except (InvalidToken, ValueError, KeyError, TypeError):
            return self._unreadable()

    def delete(self, user_key):
        item_id = user_id(user_key)
        self._call("delete a token", lambda container: container.delete_item(item=item_id, partition_key=item_id),
                   missing_ok=True)


def build_token_store(settings):
    """Cosmos DB when COSMOS_ENDPOINT is set (always, on App Service), otherwise files in token_dir (local use)."""
    if settings.cosmos_endpoint:
        source = CosmosContainerSource(settings.cosmos_endpoint, settings.cosmos_database, settings.cosmos_container,
                                       on_azure=settings.on_azure)
        return CosmosTokenStore(source, settings.encryption_keys)
    return FileTokenStore(settings.token_dir, settings.encryption_keys)


class FileTokenStore(_SealedStore):
    def __init__(self, directory, keys):
        super().__init__(keys)
        self.directory = os.path.abspath(directory)
        os.makedirs(self.directory, mode=0o700, exist_ok=True)

    def _path(self, user_key):
        return os.path.join(self.directory, user_id(user_key) + ".tok")

    def save(self, user_key, record):
        path = self._path(user_key)
        blob = self._seal(record)
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
        return self._unseal(blob)

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
