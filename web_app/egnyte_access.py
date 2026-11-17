"""Calling Egnyte as one specific user.

Every Egnyte call goes through EgnyteAccess.run(user, fn): it builds a client holding THAT user's access
token (never a shared or admin token, never a global client), runs fn(client), and closes the client.
If Egnyte rejects the token it tries one refresh (when a refresh token is stored) and otherwise
disconnects the user, who then connects again.
"""
import logging
import os
import sys
import threading
import time
from contextlib import closing
from dataclasses import replace

# Use the egnyte/ folder that sits next to this file when deployed, or in the repository root when
# running from a checkout. This must happen before egnyte is imported.
_HERE = os.path.dirname(os.path.abspath(__file__))
for _root in (_HERE, os.path.dirname(_HERE)):
    if os.path.isdir(os.path.join(_root, "egnyte")):
        sys.path.insert(0, _root)
        break

from egnyte import exc  # noqa: E402
from egnyte.client import EgnyteClient  # noqa: E402

import egnyte_oauth  # noqa: E402
from token_store import TokenRecord  # noqa: E402

log = logging.getLogger("egnyte.access")

REFRESH_MARGIN = 24 * 3600     # refresh when less than a day of the token's life is left
REQUEST_TIMEOUT = 30


class NotConnected(Exception):
    """The user has no usable Egnyte link. The message is safe to show."""


class RateLimiter:
    """One limit shared by ALL users: Egnyte rate-limits per API key, not per user."""

    def __init__(self, per_second, clock=time.monotonic, sleep=time.sleep):
        self._interval = 1.0 / per_second
        self._clock, self._sleep = clock, sleep
        self._next_slot = 0.0
        self._lock = threading.Lock()

    def wait(self):
        with self._lock:
            now = self._clock()
            start = max(now, self._next_slot)
            self._next_slot = start + self._interval
            delay = start - now
        if delay > 0:
            self._sleep(delay)


def build_client(settings, access_token, limiter):
    client = EgnyteClient({"domain": settings.domain, "access_token": access_token, "timeout": REQUEST_TIMEOUT})
    send = client._session.request

    def limited_request(method, *args, **kwargs):
        limiter.wait()
        return send(method, *args, **kwargs)

    client._session.request = limited_request
    return client


class EgnyteAccess:
    def __init__(self, settings, store, oauth=egnyte_oauth, limiter=None, client_factory=build_client,
                 clock=time.time):
        self.settings, self.store, self.oauth = settings, store, oauth
        self.limiter = limiter or RateLimiter(settings.max_rps)
        self._client_factory, self._clock = client_factory, clock

    # -- linking

    def status(self, user):
        return self.store.load(user.key)

    def connect(self, user, tokens, egnyte_username):
        self.store.save(user.key, TokenRecord(
            access_token=tokens.access_token, refresh_token=tokens.refresh_token,
            expires_at=tokens.expires_at, egnyte_username=egnyte_username, linked_at=self._clock()))

    def disconnect(self, user):
        self.store.delete(user.key)

    # -- using the link

    def run(self, user, fn):
        """Call fn(client) with a client acting as `user`. Raises NotConnected if they have no usable link."""
        record = self._usable_record(user)
        for attempt in (1, 2):
            try:
                with closing(self._client_factory(self.settings, record.access_token, self.limiter)) as client:
                    return fn(client)
            except exc.NotAuthorized:
                record = self._refresh(user, record.access_token) if attempt == 1 else None
                if record is None:
                    self.store.delete(user.key)
                    raise NotConnected("Egnyte no longer accepts your saved sign-in. Connect to Egnyte again.") from None

    def _usable_record(self, user):
        record = self.store.load(user.key)
        if record is None:
            raise NotConnected("You have not connected an Egnyte account yet.")
        if record.expires_at is not None and self._clock() >= record.expires_at - REFRESH_MARGIN:
            renewed = self._refresh(user, record.access_token)
            if renewed is not None:
                return renewed
            if self._clock() >= record.expires_at:
                self.store.delete(user.key)
                raise NotConnected("Your Egnyte sign-in has expired. Connect to Egnyte again.")
        return record

    def _refresh(self, user, rejected_access_token):
        """A record with a fresh access token, or None if that isn't possible. One refresh at a time per user."""
        with self.store.lock_for(user.key):
            current = self.store.load(user.key)
            if current is None:
                return None
            if current.access_token != rejected_access_token:
                return current          # another request already refreshed it
            if not current.refresh_token:
                return None
            try:
                tokens = self.oauth.refresh_access_token(
                    self.settings.domain, self.settings.client_id, self.settings.client_secret, current.refresh_token)
            except egnyte_oauth.OAuthError as e:
                log.warning("Token refresh failed for a user: %s", e)
                return None
            updated = replace(current, access_token=tokens.access_token,
                              refresh_token=tokens.refresh_token or current.refresh_token,
                              expires_at=tokens.expires_at)
            self.store.save(user.key, updated)
            return updated
