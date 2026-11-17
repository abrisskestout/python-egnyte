"""Shared test scaffolding: no network, no Azure, no real Egnyte."""
import base64
import json
import os
import sys
import tempfile
from types import SimpleNamespace
from urllib.parse import parse_qs, urlsplit

WEB_APP = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if WEB_APP not in sys.path:
    sys.path.insert(0, WEB_APP)

from cryptography.fernet import Fernet  # noqa: E402

import egnyte_oauth  # noqa: E402
from egnyte_access import EgnyteAccess  # noqa: E402  (also puts the egnyte package on the path)
from egnyte import exc  # noqa: E402
from settings import Settings  # noqa: E402
from token_store import FileTokenStore  # noqa: E402

TENANT = "11111111-1111-1111-1111-111111111111"
ALICE = "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"
BOB = "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb"
KEY = Fernet.generate_key().decode()
SECRET = "super-secret-client-secret-value"


def principal(oid, name, tenant=TENANT, claim_types=None):
    """An X-MS-CLIENT-PRINCIPAL header value like the one App Service Authentication sends."""
    types = claim_types or {"tenant": "http://schemas.microsoft.com/identity/claims/tenantid",
                            "oid": "http://schemas.microsoft.com/identity/claims/objectidentifier"}
    claims = [{"typ": types["tenant"], "val": tenant}, {"typ": types["oid"], "val": oid},
              {"typ": "preferred_username", "val": name}]
    return base64.b64encode(json.dumps({"auth_typ": "aad", "claims": claims}).encode()).decode()


def make_settings(token_dir, **overrides):
    values = dict(domain="stout.egnyte.com", client_id="CLIENT123", redirect_uri="https://webapp.example/egnyte/callback",
                  scope="Egnyte.filesystem", client_secret=SECRET, secret_key="s" * 40, encryption_keys=(KEY,),
                  token_dir=token_dir, max_rps=20.0)
    values.update(overrides)
    return Settings(**values)


class FakeOAuth:
    """Stands in for egnyte_oauth in the app: real URL building and callback parsing, fake Egnyte calls."""

    def __init__(self):
        # authorization code -> (access token, refresh token, Egnyte username)
        self.codes = {"code-alice": ("alice-access", "alice-refresh", "alice.eg"),
                      "code-bob": ("bob-access", "bob-refresh", "bob.eg")}
        self.usernames = {"alice-access": "alice.eg", "bob-access": "bob.eg"}
        self.exchanged = []      # codes that were exchanged
        self.refreshed = []      # refresh tokens that were used
        self.refresh_fails = False
        self.next_access = "refreshed-access"

    def __getattr__(self, name):
        return getattr(egnyte_oauth, name)

    def exchange_code(self, domain, client_id, client_secret, redirect_uri, code):
        self.exchanged.append(code)
        if code not in self.codes:
            raise egnyte_oauth.OAuthError("Token request failed: HTTP 400 (invalid_grant)", 400)
        access, refresh, _ = self.codes[code]
        return egnyte_oauth.TokenSet(access, refresh, 5_000_000_000.0)

    def fetch_userinfo(self, domain, access_token):
        return {"username": self.usernames[access_token]}

    def refresh_access_token(self, domain, client_id, client_secret, refresh_token):
        self.refreshed.append(refresh_token)
        if self.refresh_fails:
            raise egnyte_oauth.OAuthError("Token refresh failed: HTTP 400 (invalid_grant)", 400)
        self.usernames[self.next_access] = "alice.eg"
        return egnyte_oauth.TokenSet(self.next_access, "rotated-refresh", 5_000_000_000.0)


def entry(path, size=None, name=None):
    item = SimpleNamespace(path=path)
    if name:
        item.name = name
    if size is not None:
        item.size = size
    return item


class FakeEgnyte:
    """A fake Egnyte in which each access token sees its own tree: that's how permissions differ per user."""

    def __init__(self):
        self.trees = {
            "alice-access": {"/Shared": ([entry("/Shared/Team A")], [entry("/Shared/a.txt", 3)]),
                             "/Private/alice.eg": ([], [entry("/Private/alice.eg/notes.txt", 5)])},
            "bob-access": {"/Shared": ([entry("/Shared/Team B")], []),
                           "/Private/bob.eg": ([], [])},
        }
        self.contents = {"/Shared/a.txt": b"abc", "/Private/alice.eg/notes.txt": b"hello"}
        self.rejected = set()    # access tokens Egnyte answers 401 for
        self.fail_with = None    # an exception every call raises, to test error pages
        self.clients = []

    def factory(self, settings, access_token, limiter):
        client = FakeClient(self, access_token)
        self.clients.append(client)
        return client

    def tokens_used(self):
        return [client.token for client in self.clients]


class FakeClient:
    def __init__(self, world, token):
        self.world, self.token, self.closed = world, token, False

    def _check(self):
        if self.token in self.world.rejected or self.token not in self.world.trees:
            raise exc.NotAuthorized("Invalid access token")
        if self.world.fail_with is not None:
            raise self.world.fail_with

    def _visible_files(self):
        return {f.path for _, files in self.world.trees[self.token].values() for f in files}

    def folder(self, path):
        client = self

        class Folder:
            def list(self):
                client._check()
                tree = client.world.trees[client.token]
                if path in tree:
                    folders, files = tree[path]
                    return SimpleNamespace(folders=folders, files=files)
                if path in client._visible_files():
                    return SimpleNamespace(folders=None)      # a file, not a folder
                raise exc.NotFound("no such folder")
        return Folder()

    def file(self, path):
        client = self
        client._check()
        # Like Egnyte, only reveal a file to a token that is allowed to see it.
        content = client.world.contents.get(path) if path in client._visible_files() else None

        class File:
            is_folder = False
            size = len(content) if content is not None else 0

            def download(self):
                client._check()
                if content is None:
                    raise exc.NotFound("no such file")
                return SimpleNamespace(write_to=lambda fp: fp.write(content))
        return File()

    def close(self):
        self.closed = True


def build_stack(test, **setting_overrides):
    """Settings, a real encrypted store in a temp dir, fake Egnyte and fake OAuth, wired into an app."""
    from app import create_app
    from token_store import PendingStates
    folder = tempfile.TemporaryDirectory()
    test.addCleanup(folder.cleanup)
    settings = make_settings(folder.name, **setting_overrides)
    store = FileTokenStore(settings.token_dir, settings.encryption_keys)
    oauth, world = FakeOAuth(), FakeEgnyte()
    clock = SimpleNamespace(now=1000.0)      # advance clock.now to test expiry of pending sign-ins
    pending = PendingStates(clock=lambda: clock.now)
    access = EgnyteAccess(settings, store, oauth, client_factory=world.factory)
    app = create_app(settings, store=store, access=access, oauth=oauth, pending=pending)
    return SimpleNamespace(app=app, settings=settings, store=store, oauth=oauth, world=world, access=access,
                           pending=pending, clock=clock, folder=folder.name)


def as_user(client, oid, name):
    """Make every request from this test client carry that user's identity header."""
    client.environ_base["HTTP_X_MS_CLIENT_PRINCIPAL"] = principal(oid, name)
    return client


def start_signin(test, client):
    """Hit /egnyte/connect like the Connect button does and return the state it put in the Egnyte URL."""
    response = client.get("/egnyte/connect")
    test.assertEqual(response.status_code, 302)
    return parse_qs(urlsplit(response.headers["Location"]).query)["state"][0]


def connect_user(test, client, code):
    """Start a sign-in and complete it with `code`. Returns the callback response."""
    return client.get(f"/egnyte/callback?code={code}&state={start_signin(test, client)}")
