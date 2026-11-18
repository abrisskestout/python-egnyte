"""A small multi-user test site for per-user Egnyte access.

Each person signs in to the site with Microsoft Entra ID (App Service Authentication), connects THEIR OWN
Egnyte account once, and from then on every Egnyte call the site makes for them uses their own access
token, so Egnyte enforces their own permissions. Two people looking at the same folder can see
different things, which is the point of the test.
"""
import hmac
import io
import os
import secrets
import time
from functools import wraps

import requests
from flask import Flask, abort, flash, g, redirect, render_template, request, send_file, session, url_for

import egnyte_oauth
import identity
import permission_check
from egnyte_access import EgnyteAccess, NotConnected, RateLimiter  # sets up the egnyte import path
from egnyte import exc  # noqa: E402  (must come after egnyte_access)
from token_store import FileTokenStore, PendingStates

MAX_DOWNLOAD_BYTES = 25 * 1024 * 1024
LISTING_LIMIT = 500
MAX_PATH_LENGTH = 512

CONTENT_SECURITY_POLICY = ("default-src 'none'; style-src 'self'; form-action 'self'; "
                           "frame-ancestors 'none'; base-uri 'none'")


def clean_path(value):
    """An Egnyte path from the query string, checked. Egnyte itself decides whether the user may see it."""
    value = value or ""
    # Reject control characters in the raw value, before any stripping can hide a trailing newline.
    if not value.strip() or len(value) > MAX_PATH_LENGTH or "\\" in value or any(ord(ch) < 32 or ord(ch) == 127 for ch in value):
        abort(400)
    path = "/" + value.strip().strip("/")
    if path == "/" or any(segment in (".", "..") for segment in path.split("/")[1:]):
        abort(400)
    return path


def describe_expiry(record, now):
    if record.expires_at is None:
        return "unknown"
    seconds = record.expires_at - now
    if seconds <= 0:
        return "expired"
    return f"about {seconds / 86400:.0f} day(s) from now" if seconds >= 86400 else f"about {seconds / 3600:.0f} hour(s) from now"


def create_app(settings, *, store=None, access=None, oauth=egnyte_oauth, pending=None, clock=time.time):
    app = Flask(__name__)
    app.config.update(
        SECRET_KEY=settings.secret_key,
        SESSION_COOKIE_SECURE=not settings.allow_dev_user,
        SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SAMESITE="Lax",
        MAX_CONTENT_LENGTH=64 * 1024,
    )
    store = store or FileTokenStore(settings.token_dir, settings.encryption_keys)
    pending = pending or PendingStates()
    access = access or EgnyteAccess(settings, store, oauth, RateLimiter(settings.max_rps))
    if settings.on_azure:
        if os.environ.get("WEBSITE_AUTH_ENABLED", "").lower() != "true":
            app.logger.warning("App Service Authentication does not look enabled. Without it anyone can forge "
                               "the identity headers this app trusts. See README.md.")

    # ------------------------------------------------------------------ plumbing

    def csrf_token():
        token = session.get("csrf")
        if not token:
            token = session["csrf"] = secrets.token_urlsafe(32)
        return token

    def check_csrf():
        sent, expected = request.form.get("csrf", ""), session.get("csrf", "")
        if not expected or not hmac.compare_digest(sent.encode("utf-8"), expected.encode("utf-8")):
            abort(400)

    app.jinja_env.globals["csrf_token"] = csrf_token

    def require_user(view):
        @wraps(view)
        def wrapper(*args, **kwargs):
            user = identity.current_user(request.headers, request.cookies, settings)
            if user is None:
                abort(401)
            g.user = user
            return view(*args, **kwargs)
        return wrapper

    def error_page(status, title, message, connect=False):
        return render_template("error.html", title=title, message=message, connect=connect), status

    @app.after_request
    def secure_headers(response):
        response.headers["Cache-Control"] = "no-store"
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["Content-Security-Policy"] = CONTENT_SECURITY_POLICY
        return response

    @app.errorhandler(400)
    def bad_request(_):
        return error_page(400, "Bad request", "That request was not valid.")

    @app.errorhandler(401)
    def unauthenticated(_):
        return error_page(401, "Sign-in required", "This site did not receive a signed-in identity. Open it through "
                          "its normal address so that Microsoft sign-in can run.")

    @app.errorhandler(404)
    def not_found(_):
        return error_page(404, "Not found", "There is nothing at that address.")

    @app.errorhandler(NotConnected)
    def not_connected(e):
        return error_page(409, "Connect to Egnyte", str(e), connect=True)

    @app.errorhandler(exc.InsufficientPermissions)
    def forbidden(_):
        return error_page(403, "No access", "Your Egnyte account is not allowed to do that.")

    @app.errorhandler(exc.NotFound)
    def egnyte_not_found(_):
        return error_page(404, "Not found in Egnyte", "That folder or file does not exist, or your Egnyte account "
                          "cannot see it.")

    @app.errorhandler(exc.EgnyteError)
    @app.errorhandler(requests.RequestException)
    def egnyte_failed(e):
        app.logger.warning("Egnyte call failed: %s", type(e).__name__)
        return error_page(502, "Egnyte problem", f"Egnyte did not complete that request ({type(e).__name__}).")

    # ------------------------------------------------------------------ pages

    @app.get("/healthz")
    def healthz():
        return "ok", 200, {"Content-Type": "text/plain; charset=utf-8"}

    @app.get("/")
    @require_user
    def index():
        record = access.status(g.user)
        return render_template("index.html", user=g.user, record=record, domain=settings.domain, scope=settings.scope,
                               expiry=describe_expiry(record, clock()) if record else None)

    @app.get("/egnyte/connect")
    @require_user
    def egnyte_connect():
        state = pending.create(g.user.key)
        return redirect(oauth.build_auth_url(settings.domain, settings.client_id, settings.redirect_uri,
                                             settings.scope, state))

    @app.get("/egnyte/callback")
    @require_user
    def egnyte_callback():
        params, problem = oauth.parse_callback(request.query_string.decode("utf-8", "replace"))
        if problem:
            return error_page(400, "Sign-in failed", f"Egnyte's response was not valid ({problem}). Try again.")
        # The state must be consumed BEFORE the code is used: one try, by the user who started it.
        if not pending.consume(params["state"], g.user.key):
            return error_page(400, "Sign-in failed", "This sign-in was not started from your session, has already "
                              "been used, or has expired. Start again.", connect=True)
        if "error" in params:
            return error_page(400, "Egnyte sign-in failed", oauth.callback_error_text(params), connect=True)
        try:
            tokens = oauth.exchange_code(settings.domain, settings.client_id, settings.client_secret,
                                         settings.redirect_uri, params["code"])
            info = oauth.fetch_userinfo(settings.domain, tokens.access_token)
        except oauth.OAuthError as e:
            app.logger.warning("Egnyte connect failed: %s", e)
            return error_page(502, "Egnyte sign-in failed", str(e), connect=True)
        access.connect(g.user, tokens, info["username"])
        app.logger.info("An Egnyte account was connected (refresh token stored: %s)", bool(tokens.refresh_token))
        return redirect(url_for("index"))

    @app.post("/egnyte/disconnect")
    @require_user
    def egnyte_disconnect():
        check_csrf()
        access.disconnect(g.user)
        return redirect(url_for("index"))

    @app.get("/folders")
    @require_user
    def folders():
        record = access.status(g.user)
        if record is None:
            raise NotConnected("You have not connected an Egnyte account yet.")
        path = clean_path(request.args.get("path") or f"/Private/{record.egnyte_username}")

        def list_folder(client):
            result = client.folder(path).list()
            if not hasattr(result, "folders") or result.folders is None:
                abort(400)  # the path is a file, not a folder
            # vars() avoids the library's lazy per-item fetch (one API call each)
            name = lambda item: vars(item).get("name") or item.path.rsplit("/", 1)[-1]  # noqa: E731
            subfolders = sorted(((name(f), f.path) for f in result.folders), key=lambda item: item[0].lower())
            files = sorted(((name(f), f.path, vars(f).get("size")) for f in result.files), key=lambda item: item[0].lower())
            return subfolders, files

        subfolders, files = access.run(g.user, list_folder)
        parent = path.rsplit("/", 1)[0] or None
        return render_template("folders.html", path=path, parent=parent,
                               subfolders=subfolders[:LISTING_LIMIT], files=files[:LISTING_LIMIT],
                               truncated=len(subfolders) > LISTING_LIMIT or len(files) > LISTING_LIMIT,
                               private_path=f"/Private/{record.egnyte_username}", egnyte_user=record.egnyte_username)

    @app.get("/file")
    @require_user
    def download():
        path = clean_path(request.args.get("path"))

        def fetch(client):
            file = client.file(path)
            if file.is_folder:
                abort(400)
            if (file.size or 0) > MAX_DOWNLOAD_BYTES:
                return None
            buffer = io.BytesIO()
            file.download().write_to(buffer)
            return buffer.getvalue()

        data = access.run(g.user, fetch)
        if data is None:
            return error_page(413, "Too large", f"This test site only downloads files up to "
                              f"{MAX_DOWNLOAD_BYTES // (1024 * 1024)} MB.")
        # Always an attachment, never rendered by the browser: file contents are not ours to trust.
        return send_file(io.BytesIO(data), mimetype="application/octet-stream", as_attachment=True,
                         download_name=path.rsplit("/", 1)[-1])

    # ------------------------------------------------------------------ permission test

    def permission_action(verb, action, done):
        """Run one of the three actions as the signed-in user and report what happened on the page.

        Egnyte, not this site, decides whether the user may do it: a refusal is shown, not hidden."""
        check_csrf()
        record = access.status(g.user)
        egnyte_user = record.egnyte_username if record else "unknown"
        try:
            name = access.run(g.user, action)
        except permission_check.ActionRefused as e:
            flash(str(e), "info")
        except exc.InsufficientPermissions:
            flash(f"Egnyte refused: the Egnyte account {egnyte_user} is not allowed to {verb} in "
                  f"{permission_check.FOLDER}.", "denied")
        except exc.NotFound:
            flash(f"Egnyte could not find {permission_check.FOLDER}, or the account {egnyte_user} can't see it.",
                  "denied")
        else:
            flash(done(name, egnyte_user), "success")
        return redirect(url_for("permissions"))

    @app.get("/permissions")
    @require_user
    def permissions():
        record = access.status(g.user)
        if record is None:
            raise NotConnected("You have not connected an Egnyte account yet.")
        state = access.run(g.user, permission_check.inspect)
        return render_template("permissions.html", state=state, who=g.user.name, egnyte_user=record.egnyte_username)

    @app.post("/permissions/edit")
    @require_user
    def permissions_edit():
        who = g.user.name
        return permission_action(
            "edit files", lambda client: permission_check.edit(client, who),
            lambda name, egnyte_user: f'Added the line "edited by {who}" to {name}, as the Egnyte account {egnyte_user}.')

    @app.post("/permissions/create")
    @require_user
    def permissions_create():
        who = g.user.name
        return permission_action(
            "create files", lambda client: permission_check.create(client, who),
            lambda name, egnyte_user: f"Created {name}, as the Egnyte account {egnyte_user}.")

    @app.post("/permissions/delete")
    @require_user
    def permissions_delete():
        return permission_action(
            "delete files", permission_check.delete,
            lambda name, egnyte_user: f"Deleted {name}, as the Egnyte account {egnyte_user}.")

    if settings.allow_dev_user:
        @app.get("/dev/as/<name>")
        def dev_login(name):
            if identity.dev_user(name) is None:
                abort(400)
            response = redirect(url_for("index"))
            response.set_cookie(identity.DEV_COOKIE, name, httponly=True, samesite="Lax")
            return response

    return app
