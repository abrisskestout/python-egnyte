"""Egnyte OAuth 2.0 authorization-code helpers for the web app.

Adapted from test_app/egnyte_oauth_login.py with the same hardening (certificates verified, redirects
never followed, timeouts, only safe error text kept) but free of anything that touches the console,
the browser or the disk. Response bodies are never logged or returned; error messages contain only
an HTTP status and a standard OAuth error code.

Facts confirmed against a real tenant on 2026-11-17: the authorize URL below works, the token response
holds access_token, token_type, expires_in (about 30 days) and refresh_token. NOT yet confirmed:
whether Egnyte accepts the refresh grant used by refresh_access_token(), how long a refresh token
lives, and whether it rotates when used.
"""
import re
import secrets
import time
import urllib.parse
from dataclasses import dataclass, field
from typing import Optional

import requests

DOMAIN_SUFFIX = ".egnyte.com"
LOOPBACK_HOSTS = ("localhost", "127.0.0.1")
REQUEST_TIMEOUT = 30
MAX_TOKEN_LENGTH = 4096

DEFAULT_SCOPE = "Egnyte.filesystem"
KNOWN_SCOPES = frozenset({
    "Egnyte.filesystem", "Egnyte.ai", "Egnyte.permission", "Egnyte.link", "Egnyte.projectfolders",
    "Egnyte.bookmark", "Egnyte.user", "Egnyte.group", "Egnyte.audit", "Egnyte.salesforce",
    "Egnyte.launchwebsession", "Egnyte.controlleddocs", "Egnyte.etmf", "Egnyte.documentportal",
    "Egnyte.uploadrequests", "Egnyte.webhooks", "Egnyte.integrations", "Egnyte.sign"})

OAUTH_ERRORS = frozenset({
    "invalid_request", "invalid_client", "invalid_grant", "unauthorized_client", "unsupported_grant_type",
    "invalid_scope", "access_denied", "server_error", "temporarily_unavailable", "unsupported_response_type"})


class OAuthError(Exception):
    """A call to Egnyte's OAuth endpoints failed. The message is safe to show to a user."""

    def __init__(self, message, status=None):
        super().__init__(message)
        self.status = status


class InvalidToken(OAuthError):
    """Egnyte answered 401: the access token is expired, revoked or wrong."""


@dataclass(frozen=True)
class TokenSet:
    access_token: str = field(repr=False)
    refresh_token: Optional[str] = field(default=None, repr=False)
    expires_at: Optional[float] = None  # seconds since the epoch; None if Egnyte didn't say


# --------------------------------------------------------------------------- input checks

def safe_text(value, limit=80):
    """Text from outside this program, made safe to display: no control characters, bounded length."""
    text = "".join(ch for ch in str(value) if ch.isprintable())
    return text if len(text) <= limit else text[:limit] + "..."


def normalize_domain(value):
    """'Acme' -> 'acme.egnyte.com'. Only a bare host name is accepted. Raises ValueError otherwise."""
    text = str(value).strip().lower()
    if not re.fullmatch(r"[a-z0-9.-]+", text):
        raise ValueError(f"{safe_text(value)!r} is not a bare Egnyte domain name "
                         "(no credentials, ports, slashes, queries, fragments or unusual characters)")
    host = text if "." in text else text + DOMAIN_SUFFIX
    if not all(re.fullmatch(r"[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?", label) for label in host.split(".")):
        raise ValueError(f"{safe_text(value)!r} is not a valid domain name")
    return host


def validate_redirect_uri(value, allow_loopback_http=False):
    try:
        parts = urllib.parse.urlsplit(value)
        parts.port  # noqa: B018  (raises ValueError for a bad port)
    except ValueError:
        raise ValueError("the redirect URI is not a valid URL") from None
    if parts.fragment or parts.query or parts.username or parts.password or not parts.hostname:
        raise ValueError("the redirect URI must have a host and no credentials, query or fragment")
    if parts.scheme == "https" or (allow_loopback_http and parts.scheme == "http"
                                   and parts.hostname in LOOPBACK_HOSTS):
        return value
    raise ValueError("the redirect URI must be https")


def resolve_scope(scope):
    scopes = scope.split() if scope and scope.strip() else [DEFAULT_SCOPE]
    scopes = list(dict.fromkeys(scopes))
    unknown = [s for s in scopes if s not in KNOWN_SCOPES]
    if unknown:
        raise ValueError(f"unknown scope(s): {safe_text(' '.join(unknown))}")
    return " ".join(scopes)


# --------------------------------------------------------------------------- URLs and callbacks

def new_state():
    return secrets.token_urlsafe(32)


def token_url(domain):
    return f"https://{domain}/puboauth/token"


def userinfo_url(domain):
    return f"https://{domain}/pubapi/v1/userinfo"


def build_auth_url(domain, client_id, redirect_uri, scope, state):
    params = {"client_id": client_id, "redirect_uri": redirect_uri, "scope": scope,
              "state": state, "response_type": "code"}
    return f"{token_url(domain)}?{urllib.parse.urlencode(params, quote_via=urllib.parse.quote)}"


def parse_callback(query):
    """Check the shape of a callback's query string. Returns (params, None) or (None, reason).

    This does not decide whether the state is the right one: the caller must look it up on the
    server (PendingStates.consume) before it uses the code."""
    found = urllib.parse.parse_qs(query, keep_blank_values=True)
    if any(len(found.get(key, ())) > 1 for key in ("state", "code", "error", "error_description")):
        return None, "duplicate parameter"
    state = found.get("state", [""])[0]
    if not state or len(state) > 256:
        return None, "missing or oversized state"
    if ("code" in found) == ("error" in found):
        return None, "need exactly one of code or error"
    if "code" in found and not (0 < len(found["code"][0]) <= 2048):
        return None, "unusable code"
    params = {key: found[key][0] for key in ("state", "code", "error", "error_description") if key in found}
    return params, None


def callback_error_text(params):
    code = params["error"] if params["error"] in OAUTH_ERRORS else "unrecognized_error"
    description = safe_text(params.get("error_description", ""), 200)
    return f"Egnyte returned an error: {code}" + (f" ({description})" if description else "")


# --------------------------------------------------------------------------- talking to Egnyte

def _oauth_error_code(response):
    try:
        body = response.json()
    except ValueError:
        return None
    code = body.get("error") if isinstance(body, dict) else None
    return code if code in OAUTH_ERRORS else None


def _checked_json(response, what):
    status = response.status_code
    if 300 <= status < 400:
        raise OAuthError(f"{what}: unexpected redirect (HTTP {status}); refusing to follow it.", status)
    if status != 200:
        code = _oauth_error_code(response)
        raise OAuthError(f"{what} failed: HTTP {status}" + (f" ({code})" if code else ""), status)
    try:
        payload = response.json()
    except ValueError:
        raise OAuthError(f"{what}: the response was not valid JSON.") from None
    if not isinstance(payload, dict):
        raise OAuthError(f"{what}: unexpected response.")
    return payload


def _send(method, url, what, **kwargs):
    """One HTTPS call: certificates verified, redirects never followed, only safe error text kept."""
    try:
        response = method(url, timeout=REQUEST_TIMEOUT, allow_redirects=False, verify=True, **kwargs)
    except requests.RequestException as e:
        raise OAuthError(f"{what}: could not reach Egnyte ({type(e).__name__}).") from None
    return _checked_json(response, what)


def _token_from_payload(payload, what, previous_refresh_token=None, now=None):
    access = payload.get("access_token")
    if not isinstance(access, str) or not 0 < len(access) <= MAX_TOKEN_LENGTH:
        raise OAuthError(f"{what}: the response had no usable access token.")
    refresh = payload.get("refresh_token")
    if not (isinstance(refresh, str) and 0 < len(refresh) <= MAX_TOKEN_LENGTH):
        refresh = previous_refresh_token  # keep the old one if Egnyte didn't send a new one
    lifetime = payload.get("expires_in")
    valid_lifetime = isinstance(lifetime, (int, float)) and not isinstance(lifetime, bool) and lifetime > 0
    expires_at = (time.time() if now is None else now) + lifetime if valid_lifetime else None
    return TokenSet(access_token=access, refresh_token=refresh, expires_at=expires_at)


def exchange_code(domain, client_id, client_secret, redirect_uri, code, now=None):
    """Trade an authorization code for tokens."""
    data = {"client_id": client_id, "client_secret": client_secret, "redirect_uri": redirect_uri,
            "code": code, "grant_type": "authorization_code"}
    payload = _send(requests.post, token_url(domain), "Token request", data=data)
    return _token_from_payload(payload, "Token request", now=now)


def refresh_access_token(domain, client_id, client_secret, refresh_token, now=None):
    """Trade a refresh token for a new access token. NOT yet verified against Egnyte (see module docs)."""
    data = {"client_id": client_id, "client_secret": client_secret,
            "refresh_token": refresh_token, "grant_type": "refresh_token"}
    payload = _send(requests.post, token_url(domain), "Token refresh", data=data)
    return _token_from_payload(payload, "Token refresh", previous_refresh_token=refresh_token, now=now)


def fetch_userinfo(domain, access_token):
    """Who does this token belong to? Returns {'username': ..., 'email': ... (if sent)}, text made safe."""
    try:
        payload = _send(requests.get, userinfo_url(domain), "Token check",
                        headers={"Authorization": f"Bearer {access_token}"})
    except OAuthError as e:
        if e.status == 401:
            raise InvalidToken("Token check: Egnyte rejected the token (HTTP 401).", 401) from None
        raise
    info = {"username": safe_text(payload.get("username", "unknown"), 64)}
    if payload.get("email"):
        info["email"] = safe_text(payload["email"], 128)
    return info
