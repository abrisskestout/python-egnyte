#!/usr/bin/env python
"""Sign in to Egnyte in your browser (SSO works) and store an access token safely.

Runs the OAuth 2.0 authorization code flow against one of YOUR approved Egnyte domains:

1. The domain is checked against an allowlist before anything is prompted, opened or sent.
2. Your browser opens the Egnyte sign-in page. A loopback http redirect URI such as
   http://localhost:8080/callback is received by a short-lived local listener; for any other
   redirect URI (Egnyte's docs say https) you paste the address from the browser's address bar.
   Every callback is checked (path, one-time state, exactly one of code/error) before it counts.
3. The code is exchanged for a token (Egnyte says it lasts 30 days) over TLS, without following
   redirects. The token goes to the OS credential store (Windows Credential Manager); the config
   file keeps only the domain, the client ID and a reference to it. `--store file` keeps the token
   in a locked-down config file instead, which `python -m egnyte` can read.

The client secret is never written to disk: set EGNYTE_CLIENT_SECRET or type it when asked.
Setup instructions: README.md next to this file.
"""
import argparse
import base64
import getpass
import hashlib
import http.server
import os
import re
import secrets
import socket
import sys
import threading
import time
import urllib.parse
import webbrowser

import requests

HERE = os.path.dirname(os.path.abspath(__file__))
REPO_ROOT = os.path.dirname(HERE)
sys.path.insert(0, HERE)
if os.path.isdir(os.path.join(REPO_ROOT, "egnyte")):
    sys.path.insert(0, REPO_ROOT)

import egnyte_credentials as credentials  # noqa: E402  (must come after the sys.path changes above)
from egnyte import configuration  # noqa: E402

# Egnyte domains this script may send credentials to. Add yours here, or set EGNYTE_APPROVED_DOMAINS
# (comma-separated). Short names such as "yourcompany" mean yourcompany.egnyte.com.
APPROVED_DOMAINS = ("stout",)

DOMAIN_SUFFIX = ".egnyte.com"
LOOPBACK_HOSTS = ("localhost", "127.0.0.1")
REQUEST_TIMEOUT = 30
CONNECTION_TIMEOUT = 5      # longest a single callback connection may take, in seconds
STATUS_PATH = "/status"

# Least privilege: the test app's file, folder, search, notes, version and bulk checks all use the
# File System API. Anything else is something you ask for explicitly with --links or --scope.
DEFAULT_SCOPE = "Egnyte.filesystem"
LINKS_SCOPE = "Egnyte.link"            # only for egnyte_test_app.py --links
KNOWN_SCOPES = frozenset({
    "Egnyte.filesystem", "Egnyte.ai", "Egnyte.permission", "Egnyte.link", "Egnyte.projectfolders",
    "Egnyte.bookmark", "Egnyte.user", "Egnyte.group", "Egnyte.audit", "Egnyte.salesforce",
    "Egnyte.launchwebsession", "Egnyte.controlleddocs", "Egnyte.etmf", "Egnyte.documentportal",
    "Egnyte.uploadrequests", "Egnyte.webhooks", "Egnyte.integrations", "Egnyte.sign"})

OAUTH_ERRORS = frozenset({
    "invalid_request", "invalid_client", "invalid_grant", "unauthorized_client", "unsupported_grant_type",
    "invalid_scope", "access_denied", "server_error", "temporarily_unavailable", "unsupported_response_type"})

PENDING_PAGE = b"""<!doctype html>
<meta charset="utf-8"><title>Egnyte sign-in</title>
<h1 id="m">Response received.</h1>
<p id="d">Return to the terminal to finish signing in.</p>
<script>
const m = document.getElementById("m"), d = document.getElementById("d");
async function poll() {
  try {
    const status = (await (await fetch("/status", {cache: "no-store"})).text()).trim();
    if (status === "success") { m.textContent = "Signed in."; d.textContent = "You can close this tab."; return; }
    if (status === "failed") { m.textContent = "Sign-in failed."; d.textContent = "See the terminal for details."; return; }
  } catch (e) { return; }
  setTimeout(poll, 500);
}
poll();
</script>
"""


class SetupError(Exception):
    """Bad input or configuration. The message is safe to print."""


class LoginError(Exception):
    """The sign-in failed. The message is safe to print."""


# --------------------------------------------------------------------------- input checks

def safe_text(value, limit=80):
    """Text from outside this program, made safe to print: no control characters, bounded length."""
    text = "".join(ch for ch in str(value) if ch.isprintable())
    return text if len(text) <= limit else text[:limit] + "..."


def normalize_domain(value):
    """'Acme' -> 'acme.egnyte.com'. Only a bare host name is accepted: no credentials, port, path,
    query, fragment, whitespace or non-ASCII characters."""
    text = str(value).strip().lower()
    if not re.fullmatch(r"[a-z0-9.-]+", text):
        raise SetupError(f"{safe_text(value)!r} is not a bare Egnyte domain name (no credentials, ports, "
                         "slashes, queries, fragments or unusual characters).")
    host = text if "." in text else text + DOMAIN_SUFFIX
    if not all(re.fullmatch(r"[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?", label) for label in host.split(".")):
        raise SetupError(f"{safe_text(value)!r} is not a valid domain name.")
    return host


def approved_domains(environ):
    entries = list(APPROVED_DOMAINS) + [e for e in environ.get("EGNYTE_APPROVED_DOMAINS", "").split(",") if e.strip()]
    return {normalize_domain(entry) for entry in entries}


def validate_domain(value, approved):
    host = normalize_domain(value)
    if not approved:
        raise SetupError("No approved Egnyte domains are configured. Set EGNYTE_APPROVED_DOMAINS "
                         "(comma-separated) or edit APPROVED_DOMAINS in this script.")
    if host not in approved:
        raise SetupError(f"{host} is not an approved Egnyte domain. Add it to EGNYTE_APPROVED_DOMAINS "
                         "or APPROVED_DOMAINS only if it really is yours.")
    return host


def validate_redirect_uri(value):
    try:
        parts = urllib.parse.urlsplit(value)
        parts.port  # noqa: B018  (raises ValueError for a bad port)
    except ValueError:
        raise SetupError("The redirect URI is not a valid URL.") from None
    if parts.fragment or parts.username or parts.password or not parts.hostname:
        raise SetupError("The redirect URI must have a host and no credentials or fragment.")
    if parts.scheme == "https" or (parts.scheme == "http" and parts.hostname in LOOPBACK_HOSTS):
        return value
    raise SetupError("The redirect URI must be https (plain http is only accepted for localhost).")


def resolve_scope(scope, links):
    scopes = scope.split() if scope else [DEFAULT_SCOPE]
    if links:
        scopes.append(LINKS_SCOPE)
    scopes = list(dict.fromkeys(scopes))
    unknown = [s for s in scopes if s not in KNOWN_SCOPES]
    if unknown:
        raise SetupError(f"Unknown scope(s): {safe_text(' '.join(unknown))}")
    return " ".join(scopes)


def inside_repo(path):
    try:
        return os.path.commonpath([os.path.abspath(path), REPO_ROOT]) == REPO_ROOT
    except ValueError:  # different drives
        return False


# --------------------------------------------------------------------------- OAuth pieces

def make_pkce():
    """A fresh (verifier, S256 challenge) pair, per RFC 7636."""
    verifier = secrets.token_urlsafe(64)
    return verifier, pkce_challenge(verifier)


def pkce_challenge(verifier):
    return base64.urlsafe_b64encode(hashlib.sha256(verifier.encode("ascii")).digest()).rstrip(b"=").decode("ascii")


def token_url(domain):
    return f"https://{domain}/puboauth/token"


def userinfo_url(domain):
    return f"https://{domain}/pubapi/v1/userinfo"


def build_auth_url(domain, client_id, redirect_uri, scope, state, challenge=None):
    params = {"client_id": client_id, "redirect_uri": redirect_uri, "scope": scope,
              "state": state, "response_type": "code"}
    if challenge:
        params.update(code_challenge=challenge, code_challenge_method="S256")
    return f"{token_url(domain)}?{urllib.parse.urlencode(params, quote_via=urllib.parse.quote)}"


def validate_callback(query, expected_state):
    """Check a callback's query string. Returns (params, None) if it is acceptable, else (None, reason).

    Needs the exact one-time state, no duplicated parameters, and exactly one of code or error."""
    found = urllib.parse.parse_qs(query, keep_blank_values=True)
    if any(len(found.get(key, ())) > 1 for key in ("state", "code", "error", "error_description")):
        return None, "duplicate parameter"
    state = found.get("state", [""])[0]
    if not state:
        return None, "missing state"
    if not secrets.compare_digest(state.encode("utf-8"), expected_state.encode("utf-8")):
        return None, "state mismatch"
    if ("code" in found) == ("error" in found):
        return None, "need exactly one of code or error"
    if "code" in found and not (0 < len(found["code"][0]) <= 2048):
        return None, "unusable code"
    return {key: found[key][0] for key in ("code", "error", "error_description") if key in found}, None


def callback_error_text(params):
    code = params["error"] if params["error"] in OAUTH_ERRORS else "unrecognized_error"
    description = safe_text(params.get("error_description", ""), 200)
    return f"Egnyte returned an error: {code}" + (f" ({description})" if description else "")


def parse_pasted_callback(pasted, redirect_uri, expected_state):
    pasted_parts, expected = urllib.parse.urlsplit(pasted), urllib.parse.urlsplit(redirect_uri)
    if (pasted_parts.scheme, pasted_parts.netloc.lower(), pasted_parts.path or "/") != \
            (expected.scheme, expected.netloc.lower(), expected.path or "/"):
        return None, "that is not the redirect URI you registered"
    return validate_callback(pasted_parts.query, expected_state)


def read_pasted_callback(redirect_uri, expected_state, attempts=3):
    print("\nAfter you sign in, the browser tries to open your redirect URI and will probably show an\n"
          "error page. That is expected: copy the full address from the browser's address bar.")
    for _ in range(attempts):
        pasted = getpass.getpass("Paste the redirected URL (input is hidden): ").strip()
        params, problem = parse_pasted_callback(pasted, redirect_uri, expected_state)
        if params:
            return params
        print(f"That didn't work: {problem}.")
    raise LoginError("No valid redirected URL was provided.")


# --------------------------------------------------------------------------- local callback listener

class CallbackServer(http.server.ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = os.name != "nt"  # on Windows SO_REUSEADDR would let another process share the port

    def server_bind(self):
        if hasattr(socket, "SO_EXCLUSIVEADDRUSE"):
            self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_EXCLUSIVEADDRUSE, 1)
        super().server_bind()

    def handle_error(self, request, client_address):
        # A connection we cut off (or that the client dropped) is routine, not worth a traceback.
        if not isinstance(sys.exc_info()[1], OSError):
            super().handle_error(request, client_address)


class CallbackHandler(http.server.BaseHTTPRequestHandler):
    """Accepts exactly one valid callback; everything else gets an error and the listener keeps going."""

    def setup(self):
        remaining = self.server.deadline - time.monotonic()
        self.limit = max(0.05, min(self.server.connection_timeout, remaining))
        self.timeout = self.limit  # per-read timeout
        super().setup()

    def handle(self):
        # A per-read timeout alone doesn't stop a client that drips one byte at a time, so the whole
        # connection also gets a hard time limit that never outlives the sign-in deadline.
        watchdog = threading.Timer(self.limit, self._abort)
        watchdog.daemon = True
        watchdog.start()
        try:
            super().handle()
        finally:
            watchdog.cancel()

    def _abort(self):
        try:
            self.connection.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass

    def do_GET(self):
        server = self.server
        parts = urllib.parse.urlsplit(self.path)
        if parts.path == STATUS_PATH and server.params is not None:
            if server.outcome != "pending":
                server.status_fetched.set()
            return self._reply(200, server.outcome.encode())
        if parts.path != server.callback_path:
            return self._reply(404, b"Not found")
        params, problem = validate_callback(parts.query, server.expected_state)
        if problem:
            return self._reply(400, b"Invalid callback. Check the terminal; the sign-in is still waiting.")
        with server.lock:
            if server.params is not None or time.monotonic() > server.deadline:
                return self._reply(409, b"This sign-in has already finished.")
            server.params = params
        server.received.set()
        self._reply(200, PENDING_PAGE, "text/html; charset=utf-8")

    def _reply(self, status, body, content_type="text/plain; charset=utf-8"):
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Content-Security-Policy",
                         "default-src 'none'; script-src 'unsafe-inline'; connect-src 'self'")
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):  # keeps the one-time code and state out of the console
        pass


class CallbackListener:
    def __init__(self, redirect_uri, expected_state, timeout, connection_timeout=CONNECTION_TIMEOUT):
        parts = urllib.parse.urlsplit(redirect_uri)
        self.server = server = CallbackServer(("127.0.0.1", 80 if parts.port is None else parts.port),
                                              CallbackHandler)
        server.expected_state = expected_state
        server.callback_path = parts.path or "/"
        server.deadline = time.monotonic() + timeout
        server.connection_timeout = connection_timeout
        server.lock = threading.Lock()
        server.params = None
        server.outcome = "pending"
        server.received = threading.Event()
        server.status_fetched = threading.Event()
        self.closed = False
        self.thread = threading.Thread(target=server.serve_forever, kwargs={"poll_interval": 0.1}, daemon=True)
        self.thread.start()

    @property
    def port(self):
        return self.server.server_address[1]

    def wait(self):
        """Block until a valid callback arrives or the deadline passes (TimeoutError)."""
        while time.monotonic() < self.server.deadline:
            if self.server.received.wait(0.25):
                return self.server.params
        raise TimeoutError("No sign-in response arrived before the deadline.")

    def finish(self, success, grace=3.0):
        """Record the outcome for the browser tab, and give it a moment to read it."""
        self.server.outcome = "success" if success else "failed"
        if self.server.params is not None:
            self.server.status_fetched.wait(grace)

    def close(self):
        if self.closed:
            return
        self.closed = True
        if self.thread.is_alive():
            self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=2)


def open_listener(redirect_uri, expected_state, timeout):
    """A listener for a loopback http redirect URI, or None (then the redirect URL is pasted)."""
    parts = urllib.parse.urlsplit(redirect_uri)
    if parts.scheme != "http" or parts.hostname not in LOOPBACK_HOSTS:
        return None
    try:
        return CallbackListener(redirect_uri, expected_state, timeout)
    except OSError:
        print(f"Could not listen on {parts.netloc}; you will paste the redirected URL instead.")
        return None


# --------------------------------------------------------------------------- talking to Egnyte

def oauth_error_code(response):
    try:
        body = response.json()
    except ValueError:
        return None
    code = body.get("error") if isinstance(body, dict) else None
    return code if code in OAUTH_ERRORS else None


def checked_json(response, what):
    status = response.status_code
    if 300 <= status < 400:
        raise LoginError(f"{what}: unexpected redirect (HTTP {status}); refusing to follow it.")
    if status != 200:
        code = oauth_error_code(response)
        raise LoginError(f"{what} failed: HTTP {status}" + (f" ({code})" if code else ""))
    try:
        payload = response.json()
    except ValueError:
        raise LoginError(f"{what}: the response was not valid JSON.") from None
    if not isinstance(payload, dict):
        raise LoginError(f"{what}: unexpected response.")
    return payload


def send(method, url, what, **kwargs):
    """One HTTPS call: certificates verified, redirects never followed, only safe error text kept."""
    try:
        response = method(url, timeout=REQUEST_TIMEOUT, allow_redirects=False, verify=True, **kwargs)
    except requests.RequestException as e:
        raise LoginError(f"{what}: could not reach Egnyte ({type(e).__name__}).") from None
    return checked_json(response, what)


def exchange_code(url, client_id, client_secret, redirect_uri, code, verifier=None):
    data = {"client_id": client_id, "client_secret": client_secret, "redirect_uri": redirect_uri,
            "code": code, "grant_type": "authorization_code"}
    if verifier:
        data["code_verifier"] = verifier
    payload = send(requests.post, url, "Token request", data=data)
    token = payload.get("access_token")
    if not isinstance(token, str) or not 0 < len(token) <= 4096:
        raise LoginError("Token request: the response had no usable access token.")
    expires_in = payload.get("expires_in")
    days = expires_in / 86400 if isinstance(expires_in, (int, float)) and expires_in > 0 else None
    return token, days


def fetch_username(url, token):
    payload = send(requests.get, url, "Token check", headers={"Authorization": f"Bearer {token}"})
    return safe_text(payload.get("username", "unknown"), 64)


# --------------------------------------------------------------------------- saving

def save_login(config, config_path, domain, client_id, token, store, backend=None):
    config = dict(config, domain=domain, api_key=client_id)
    if store == "keyring":
        config["access_token_ref"] = credentials.store_token(domain, token, backend)
        config.pop("access_token", None)
        credentials.write_private_json(config_path, config, restrict=False)
    else:
        config["access_token"] = token
        config.pop("access_token_ref", None)
        credentials.write_private_json(config_path, config, restrict=True)


# --------------------------------------------------------------------------- main

def parse_args(argv):
    parser = argparse.ArgumentParser(description="Sign in to Egnyte in a browser and store an access token.")
    parser.add_argument("--domain", help="Egnyte domain, e.g. yourcompany; it must be on the approved list "
                                         "(default: EGNYTE_DOMAIN or the config file)")
    parser.add_argument("--client-id", help="API key / client ID (default: EGNYTE_API_KEY or 'api_key' in the config)")
    parser.add_argument("--redirect-uri", help="must match the redirect URI registered for the key exactly "
                                               "(default: EGNYTE_REDIRECT_URI)")
    parser.add_argument("--scope", help=f"space-separated OAuth scopes (default: {DEFAULT_SCOPE}); "
                                        "anything broader is your explicit choice")
    parser.add_argument("--links", action="store_true",
                        help=f"also request {LINKS_SCOPE}, which egnyte_test_app.py --links needs")
    parser.add_argument("--store", choices=("keyring", "file"), default="keyring",
                        help="keyring: OS credential store (default); file: token in the config file, "
                             "limited to your user")
    parser.add_argument("--pkce", action="store_true",
                        help="send a PKCE challenge. Off by default: Egnyte's docs don't say it is supported, "
                             "and if it ignored the challenge you would get no protection from it")
    parser.add_argument("--timeout", type=int, default=300, help="seconds to wait for the sign-in (default 300)")
    parser.add_argument("--config", help="config file (default ~/.egnyte/config.json; relative paths are "
                                         "resolved under ~/.egnyte/)")
    return parser.parse_args(argv)


def resolve_settings(args, environ):
    """Validate everything before any prompt, browser window or network request."""
    config_path = configuration.add_directory(args.config or "config.json")
    if inside_repo(config_path):
        raise SetupError("Refusing to keep credentials inside the repository checkout; use a path outside it.")
    try:
        config = configuration.load(config_path)
    except ValueError:
        raise SetupError(f"Could not parse {config_path}.") from None

    domain = args.domain or environ.get("EGNYTE_DOMAIN") or config.get("domain")
    client_id = args.client_id or environ.get("EGNYTE_API_KEY") or config.get("api_key")
    redirect_uri = args.redirect_uri or environ.get("EGNYTE_REDIRECT_URI")
    if not (domain and client_id and redirect_uri):
        raise SetupError("Need a domain, a client ID (API key) and a redirect URI.\n"
                         "  python test_app/egnyte_oauth_login.py --domain yourcompany --client-id KEY "
                         "--redirect-uri https://localhost/callback")
    if not re.fullmatch(r"[A-Za-z0-9._~-]{1,128}", str(client_id)):
        raise SetupError("The client ID contains unexpected characters.")
    return {
        "config": config, "config_path": config_path, "client_id": str(client_id),
        "domain": validate_domain(domain, approved_domains(environ)),
        "redirect_uri": validate_redirect_uri(redirect_uri),
        "scope": resolve_scope(args.scope, args.links),
    }


def open_browser(url):
    try:
        opened = webbrowser.open(url)
    except Exception:  # webbrowser can raise many things; the printed URL is the fallback
        opened = False
    if not opened:
        print("Could not open a browser automatically; open the URL above yourself.")


def main(argv=None, environ=None):
    environ = os.environ if environ is None else environ
    args = parse_args(argv)
    try:
        settings = resolve_settings(args, environ)
    except SetupError as e:
        print(f"Setup problem: {e}")
        return 2
    domain, client_id, redirect_uri = settings["domain"], settings["client_id"], settings["redirect_uri"]
    broad = sorted(set(settings["scope"].split()) - {DEFAULT_SCOPE, LINKS_SCOPE})

    secret = environ.get("EGNYTE_CLIENT_SECRET") or getpass.getpass("Egnyte client secret (input is hidden): ")
    state = secrets.token_urlsafe(32)
    verifier, challenge = make_pkce() if args.pkce else (None, None)
    url = build_auth_url(domain, client_id, redirect_uri, settings["scope"], state, challenge)

    print(f"Domain: {domain}\nScopes: {settings['scope']}")
    if broad:
        print(f"Note: you asked for broader scopes than the test app needs: {', '.join(broad)}")
    if not args.pkce:
        print("PKCE: off (not documented by Egnyte); the client secret protects the code exchange.")

    listener = open_listener(redirect_uri, state, args.timeout)
    exchanged = False
    try:
        print(f"\nOpening your browser to sign in.\nIf it doesn't open, paste this URL into a browser:\n\n  {url}")
        open_browser(url)
        params = listener.wait() if listener else read_pasted_callback(redirect_uri, state)
        if "error" in params:
            raise LoginError(callback_error_text(params))
        token, days = exchange_code(token_url(domain), client_id, secret, redirect_uri, params["code"], verifier)
        save_login(settings["config"], settings["config_path"], domain, client_id, token, args.store)
        exchanged = True
        where = ("the OS credential store (the config file holds only a reference)" if args.store == "keyring"
                 else f"{settings['config_path']}, limited to your user")
        print(f"\nStored the access token in {where}."
              + (f" It is valid for about {days:.0f} days." if days else ""))
        print(f"Token works: signed in as {fetch_username(userinfo_url(domain), token)}")
        return 0
    except LoginError as e:
        print(f"\n{e}")
        return 1
    except credentials.CredentialStoreError as e:
        print(f"\nCould not store the token: {e}")
        return 1
    except TimeoutError as e:
        print(f"\n{e}")
        return 1
    except KeyboardInterrupt:
        print("\nCancelled.")
        return 1
    finally:
        if listener:
            listener.finish(exchanged)
            listener.close()


if __name__ == "__main__":
    sys.exit(main())
