"""Tests for egnyte_oauth_login.py. Nothing here talks to Egnyte: requests is faked, the listener is
exercised over real loopback sockets, and redirect handling uses throwaway local HTTP servers."""
import contextlib
import http.server
import io
import json
import os
import shutil
import socket
import stat
import tempfile
import threading
import time
import unittest
import urllib.parse
from unittest import mock

from helpers import (FakeBackend, FakeResponse, acl_principals, fetch, free_port, wait_for_close, whoami)

import egnyte_oauth_login as m
import requests

STATE = "STATE-123"
VALID = f"/callback?code=good&state={STATE}"
ENV = {"EGNYTE_APPROVED_DOMAINS": "acme", "EGNYTE_CLIENT_SECRET": "sekret"}


def token_response(**extra):
    body = {"access_token": "tok-SECRET-1234", "refresh_token": "refresh-SECRET", "token_type": "bearer",
            "expires_in": 2592000}
    body.update(extra)
    return FakeResponse(200, body)


def auth_params(url):
    return {k: v[0] for k, v in urllib.parse.parse_qs(urllib.parse.urlsplit(url).query).items()}


# --------------------------------------------------------------------------- 1. domain validation

class DomainValidationTests(unittest.TestCase):
    def test_short_names_are_normalised(self):
        self.assertEqual(m.normalize_domain("Acme"), "acme.egnyte.com")
        self.assertEqual(m.normalize_domain("  ACME.egnyte.com "), "acme.egnyte.com")

    def test_credentials_ports_paths_queries_and_fragments_are_rejected(self):
        bad = ["user:pw@acme.egnyte.com", "acme.egnyte.com@evil.com", "acme.egnyte.com:8443", "acme:8443",
               "acme.egnyte.com/", "acme.egnyte.com/path", "acme.egnyte.com?x=1", "acme.egnyte.com#frag",
               "https://acme.egnyte.com", "acme egnyte.com", "acme.egnyte.com.", ".acme.egnyte.com",
               "acme..egnyte.com", "-acme", "acme-", "acme%2eegnyte.com", "acme\\evil.com", "",
               "аcme.egnyte.com",  # Cyrillic 'a'
               "acme.egnyte.com\n/x", "a" * 64 + ".egnyte.com"]
        for value in bad:
            with self.subTest(value=value), self.assertRaises(m.SetupError):
                m.normalize_domain(value)

    def test_only_an_exact_allowlist_match_passes(self):
        approved = {"acme.egnyte.com"}
        self.assertEqual(m.validate_domain("acme", approved), "acme.egnyte.com")
        self.assertEqual(m.validate_domain("ACME.egnyte.com", approved), "acme.egnyte.com")
        for other in ("other", "evil.com", "acme.egnyte.com.evil.com", "xacme.egnyte.com", "egnyte.com"):
            with self.subTest(other=other), self.assertRaises(m.SetupError):
                m.validate_domain(other, approved)

    def test_an_empty_allowlist_refuses_everything(self):
        with self.assertRaises(m.SetupError) as caught:
            m.validate_domain("acme", set())
        self.assertIn("EGNYTE_APPROVED_DOMAINS", str(caught.exception))

    def test_allowlist_sources(self):
        with mock.patch.object(m, "APPROVED_DOMAINS", ("one.egnyte.com",)):
            self.assertEqual(m.approved_domains({"EGNYTE_APPROVED_DOMAINS": " two , three.egnyte.com,"}),
                             {"one.egnyte.com", "two.egnyte.com", "three.egnyte.com"})
            self.assertEqual(m.approved_domains({}), {"one.egnyte.com"})

    def test_a_malformed_allowlist_entry_is_an_error(self):
        with self.assertRaises(m.SetupError):
            m.approved_domains({"EGNYTE_APPROVED_DOMAINS": "good,evil.com/path"})


class MainCase(unittest.TestCase):
    """Runs main() with requests, the browser, getpass and the credential store faked."""

    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="oauth-test-")
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)
        self.config = os.path.join(self.tmp, "cfg", "config.json")
        self.backend = FakeBackend()
        self.post = mock.Mock(return_value=token_response())
        self.get = mock.Mock(return_value=FakeResponse(200, {"username": "dry.run"}))
        self.browser_urls = []
        self.pasted = []
        self.prompts = 0
        self.final_status = None
        self.visitors = []

    def default_browser(self, url):
        self.browser_urls.append(url)
        return True

    def default_paste(self, prompt=""):
        self.prompts += 1
        if self.pasted:
            return self.pasted.pop(0)
        state = auth_params(self.browser_urls[-1])["state"]
        return "https://localhost/callback?code=CODE-1&state=" + urllib.parse.quote(state)

    def run_main(self, *extra, environ=None, browser=None, redirect="https://localhost/callback", config=True):
        argv = ["--domain", "acme", "--client-id", "KEY123", "--redirect-uri", redirect]
        if config:
            argv += ["--config", self.config]
        argv += list(extra)
        out = io.StringIO()
        with contextlib.ExitStack() as stack:
            stack.enter_context(contextlib.redirect_stdout(out))
            stack.enter_context(mock.patch.object(m.requests, "post", self.post))
            stack.enter_context(mock.patch.object(m.requests, "get", self.get))
            stack.enter_context(mock.patch.object(m.credentials, "default_backend", return_value=self.backend))
            stack.enter_context(mock.patch.object(m.webbrowser, "open", side_effect=browser or self.default_browser))
            stack.enter_context(mock.patch.object(m.getpass, "getpass", side_effect=self.default_paste))
            code = m.main(argv, environ=dict(ENV, **(environ or {})))
        for visitor in self.visitors:  # let the fake browser finish reading the status page
            visitor.join(5)
        return code, out.getvalue()

    def loopback_browser(self, port, callback=None):
        """A fake browser that, like a real one, loads the callback and then follows the status page."""
        def browser(url):
            self.browser_urls.append(url)
            state = urllib.parse.quote(auth_params(url)["state"])

            def visit():
                try:
                    fetch(port, callback.format(state=state) if callback else f"/callback?code=CODE-1&state={state}")
                    for _ in range(50):
                        self.final_status = fetch(port, "/status")[1]
                        if self.final_status != "pending":
                            return
                        time.sleep(0.1)
                except OSError:
                    pass
            visitor = threading.Thread(target=visit, daemon=True)
            self.visitors.append(visitor)
            visitor.start()
            return True
        return browser

    def saved_config(self):
        with open(self.config, encoding="utf-8") as fp:
            return json.load(fp)

    def assert_only_current_user(self, path):
        if os.name == "nt":
            self.assertEqual([p.casefold() for p in acl_principals(path)], [whoami().casefold()], path)
        else:
            self.assertEqual(stat.S_IMODE(os.stat(path).st_mode) & 0o077, 0, f"{path} is accessible to others")

    @contextlib.contextmanager
    def spy_on_listeners(self):
        created = []

        class Spy(m.CallbackListener):
            def __init__(self, *args, **kwargs):
                super().__init__(*args, **kwargs)
                created.append(self)

        with mock.patch.object(m, "CallbackListener", Spy):
            yield created


class UnapprovedDomainTests(MainCase):
    def assert_refused_before_anything_happens(self, code, **kwargs):
        self.assertEqual(code, 2)
        self.post.assert_not_called()
        self.get.assert_not_called()
        self.assertEqual(self.browser_urls, [])
        self.assertEqual(self.prompts, 0)

    def run_with_tripwires(self, argv, environ):
        """main() with every prompt, browser launch and request set to fail the test if reached."""
        out = io.StringIO()
        with contextlib.redirect_stdout(out), \
                mock.patch.object(m.requests, "post", self.post), mock.patch.object(m.requests, "get", self.get), \
                mock.patch.object(m.webbrowser, "open", side_effect=self.default_browser), \
                mock.patch.object(m.getpass, "getpass", side_effect=self.default_paste), \
                mock.patch.object(m, "CallbackListener", side_effect=AssertionError("listener started")):
            return m.main(argv, environ=environ), out.getvalue()

    def test_unapproved_domain_argument(self):
        code, out = self.run_with_tripwires(
            ["--domain", "evil.example.com", "--client-id", "KEY123", "--redirect-uri", "https://localhost/callback",
             "--config", self.config], {"EGNYTE_APPROVED_DOMAINS": "acme", "EGNYTE_CLIENT_SECRET": "sekret"})
        self.assert_refused_before_anything_happens(code)
        self.assertIn("not an approved Egnyte domain", out)

    def test_unapproved_domain_from_environment(self):
        code, _ = self.run_with_tripwires(
            ["--client-id", "KEY123", "--redirect-uri", "https://localhost/callback", "--config", self.config],
            {"EGNYTE_DOMAIN": "evil.example.com", "EGNYTE_APPROVED_DOMAINS": "acme"})
        self.assert_refused_before_anything_happens(code)

    def test_unapproved_domain_from_config_file(self):
        os.makedirs(os.path.dirname(self.config))
        with open(self.config, "w", encoding="utf-8") as fp:
            json.dump({"domain": "acme.egnyte.com.evil.example", "api_key": "KEY123"}, fp)
        code, _ = self.run_with_tripwires(
            ["--redirect-uri", "https://localhost/callback", "--config", self.config], {"EGNYTE_APPROVED_DOMAINS": "acme"})
        self.assert_refused_before_anything_happens(code)

    def test_domain_with_embedded_credentials_or_port(self):
        for domain in ("acme.egnyte.com@evil.example", "acme.egnyte.com:8443", "acme/../x"):
            with self.subTest(domain=domain):
                self.setUp()
                code, _ = self.run_with_tripwires(
                    ["--domain", domain, "--client-id", "KEY123", "--redirect-uri", "https://localhost/callback",
                     "--config", self.config], {"EGNYTE_APPROVED_DOMAINS": "acme"})
                self.assert_refused_before_anything_happens(code)

    def test_no_allowlist_at_all(self):
        # Pin the built-in list to empty so this holds whatever tenant is set as the shipped default.
        with mock.patch.object(m, "APPROVED_DOMAINS", ()):
            code, out = self.run_with_tripwires(
                ["--domain", "acme", "--client-id", "KEY123", "--redirect-uri", "https://localhost/callback",
                 "--config", self.config], {})
        self.assert_refused_before_anything_happens(code)
        self.assertIn("No approved Egnyte domains", out)

    def test_domain_from_the_config_file_is_accepted_when_approved(self):
        os.makedirs(os.path.dirname(self.config))
        with open(self.config, "w", encoding="utf-8") as fp:
            json.dump({"domain": "acme.egnyte.com", "api_key": "KEY123"}, fp)
        out = io.StringIO()
        with contextlib.redirect_stdout(out), mock.patch.object(m.requests, "post", self.post), \
                mock.patch.object(m.requests, "get", self.get), \
                mock.patch.object(m.credentials, "default_backend", return_value=self.backend), \
                mock.patch.object(m.webbrowser, "open", side_effect=self.default_browser), \
                mock.patch.object(m.getpass, "getpass", side_effect=self.default_paste):
            code = m.main(["--redirect-uri", "https://localhost/callback", "--config", self.config], environ=ENV)
        self.assertEqual(code, 0)

    def test_other_inputs_are_checked_before_the_secret_prompt_too(self):
        cases = {
            "scope": ["--scope", "Egnyte.bogus"],
            "redirect": ["--redirect-uri", "http://evil.example/callback"],
            "client id": ["--client-id", "bad id&x=1"],
            "repo path": ["--config", os.path.join(m.REPO_ROOT, "test_app", "tests", "must-not-exist", "c.json")],
        }
        for name, flags in cases.items():
            with self.subTest(name):
                self.setUp()
                base = ["--domain", "acme", "--client-id", "KEY123", "--redirect-uri", "https://localhost/callback",
                        "--config", self.config]
                code, _ = self.run_with_tripwires(base + flags, {"EGNYTE_APPROVED_DOMAINS": "acme"})
                self.assert_refused_before_anything_happens(code)
        self.assertFalse(os.path.exists(os.path.join(m.REPO_ROOT, "test_app", "tests", "must-not-exist")))


class RedirectUriTests(unittest.TestCase):
    def test_accepted(self):
        for uri in ("https://localhost/callback", "https://app.example.com/oauth", "http://localhost:8080/cb",
                    "http://127.0.0.1:9000/"):
            with self.subTest(uri=uri):
                self.assertEqual(m.validate_redirect_uri(uri), uri)

    def test_rejected(self):
        for uri in ("http://evil.example/cb", "ftp://localhost/cb", "https://u:p@localhost/cb",
                    "https://localhost/cb#frag", "http://localhost:99999/cb", "localhost/cb", "https:///cb", ""):
            with self.subTest(uri=uri), self.assertRaises(m.SetupError):
                m.validate_redirect_uri(uri)


# --------------------------------------------------------------------------- 2. callback validation

class CallbackValidationTests(unittest.TestCase):
    def check(self, query):
        return m.validate_callback(query, STATE)

    def test_valid_code_and_error_callbacks(self):
        self.assertEqual(self.check(f"code=abc&state={STATE}"), ({"code": "abc"}, None))
        self.assertEqual(self.check(f"error=access_denied&error_description=No+way&state={STATE}"),
                         ({"error": "access_denied", "error_description": "No way"}, None))

    def test_extra_parameters_are_ignored(self):
        params, _ = self.check(f"code=abc&state={STATE}&domain=evil&x=1")
        self.assertEqual(params, {"code": "abc"})

    def test_rejections(self):
        cases = {
            "missing state": "code=abc",
            "empty state": "code=abc&state=",
            "wrong state": "code=abc&state=nope",
            "wrong state on an error callback": "error=access_denied&state=nope",
            "no state on an error callback": "error=access_denied",
            "duplicate state": f"code=abc&state={STATE}&state={STATE}",
            "duplicate code": f"code=a&code=b&state={STATE}",
            "duplicate error": f"error=a&error=b&state={STATE}",
            "both code and error": f"code=abc&error=access_denied&state={STATE}",
            "neither code nor error": f"state={STATE}",
            "empty code": f"code=&state={STATE}",
            "oversized code": f"code={'a' * 3000}&state={STATE}",
            "non-ASCII state": "code=abc&state=%C3%A9%C3%A9",
        }
        for name, query in cases.items():
            with self.subTest(name):
                params, problem = self.check(query)
                self.assertIsNone(params)
                self.assertTrue(problem)

    def test_unknown_error_codes_are_not_echoed(self):
        text = m.callback_error_text({"error": "\x1b[31mevil\nerror"})
        self.assertIn("unrecognized_error", text)
        self.assertNotIn("evil", text)

    def test_error_descriptions_are_cleaned_and_bounded(self):
        text = m.callback_error_text({"error": "access_denied",
                                      "error_description": "\x1b[31mred\r\nforged line‮" + "x" * 500})
        self.assertNotIn("\x1b", text)
        self.assertNotIn("\n", text)
        self.assertNotIn("‮", text)
        self.assertLess(len(text), 300)


# --------------------------------------------------------------------------- 2 + 6. the local listener

class ListenerTests(unittest.TestCase):
    def make_listener(self, timeout=10, connection_timeout=2.0):
        listener = m.CallbackListener("http://localhost:0/callback", STATE, timeout, connection_timeout)
        self.addCleanup(listener.close)
        return listener

    def stalled_connection(self, listener, partial=b"GET /callback?code="):
        sock = socket.create_connection(("127.0.0.1", listener.port))
        self.addCleanup(sock.close)
        sock.sendall(partial)
        return sock

    def test_invalid_callbacks_are_rejected_and_listening_continues(self):
        listener = self.make_listener()
        bad = [
            ("/callback?code=x&state=nope", 400), ("/callback?code=x", 400), ("/callback?code=x&state=", 400),
            (f"/callback?code=x&state={STATE}&state={STATE}", 400),
            (f"/callback?code=x&code=y&state={STATE}", 400),
            (f"/callback?code=x&error=access_denied&state={STATE}", 400),
            ("/callback?error=access_denied&state=wrong", 400), ("/callback?error=access_denied", 400),
            (f"/callback?state={STATE}", 400), ("/callback", 400),
            (f"/other?code=x&state={STATE}", 404), ("/favicon.ico", 404), ("/status", 404),
        ]
        for target, expected in bad:
            status, _, _ = fetch(listener.port, target)
            self.assertEqual(status, expected, target)
            self.assertIsNone(listener.server.params, f"{target} was accepted")
            self.assertFalse(listener.server.received.is_set(), target)
        status, _, _ = fetch(listener.port, VALID)
        self.assertEqual(status, 200)
        self.assertEqual(listener.wait(), {"code": "good"})

    def test_error_callback_with_the_right_state_is_accepted(self):
        listener = self.make_listener()
        fetch(listener.port, f"/callback?error=access_denied&error_description=No%20thanks&state={STATE}")
        self.assertEqual(listener.wait(), {"error": "access_denied", "error_description": "No thanks"})

    def test_only_the_first_valid_callback_counts(self):
        listener = self.make_listener()
        self.assertEqual(fetch(listener.port, VALID)[0], 200)
        self.assertEqual(fetch(listener.port, f"/callback?code=second&state={STATE}")[0], 409)
        self.assertEqual(listener.wait(), {"code": "good"})

    def test_page_says_response_received_and_never_claims_success_early(self):
        listener = self.make_listener()
        status, body, headers = fetch(listener.port, VALID)
        self.assertEqual(status, 200)
        self.assertIn('<h1 id="m">Response received.</h1>', body)
        self.assertEqual(fetch(listener.port, "/status")[:2], (200, "pending"))
        self.assertEqual(headers["Referrer-Policy"], "no-referrer")
        self.assertEqual(headers["Cache-Control"], "no-store")
        listener.finish(True, grace=0)
        self.assertEqual(fetch(listener.port, "/status")[:2], (200, "success"))

    def test_failed_exchange_is_reported_as_failed(self):
        listener = self.make_listener()
        fetch(listener.port, VALID)
        listener.finish(False, grace=0)
        self.assertEqual(fetch(listener.port, "/status")[:2], (200, "failed"))

    def test_incomplete_request_is_dropped_and_does_not_block_a_valid_callback(self):
        listener = self.make_listener(connection_timeout=0.5)
        stalled = self.stalled_connection(listener)
        self.assertEqual(fetch(listener.port, VALID)[0], 200)  # served while the stalled one is still open
        self.assertLess(wait_for_close(stalled, 4), 3)

    def test_slow_drip_is_cut_off_by_the_total_connection_limit(self):
        listener = self.make_listener(connection_timeout=0.8)
        sock = self.stalled_connection(listener, b"GET /callback")
        start, closed = time.monotonic(), False
        while time.monotonic() - start < 5 and not closed:
            try:
                sock.sendall(b"x")
                sock.settimeout(0.05)
                closed = sock.recv(10) == b""
            except TimeoutError:
                pass
            except OSError:
                closed = True
            time.sleep(0.15)
        self.assertTrue(closed, "the server kept a drip-fed connection open")
        self.assertLess(time.monotonic() - start, 3)

    def test_wait_gives_up_at_the_deadline_even_with_a_connection_open(self):
        listener = self.make_listener(timeout=1.5, connection_timeout=30)
        self.stalled_connection(listener)
        start = time.monotonic()
        with self.assertRaises(TimeoutError):
            listener.wait()
        self.assertGreaterEqual(time.monotonic() - start, 1.3)
        self.assertLess(time.monotonic() - start, 3.5)

    def test_connection_limit_never_outlives_the_sign_in_deadline(self):
        listener = self.make_listener(timeout=1.0, connection_timeout=30)
        stalled = self.stalled_connection(listener)
        self.assertLess(wait_for_close(stalled, 5), 3)

    def test_close_is_idempotent_and_frees_the_port(self):
        listener = self.make_listener()
        port = listener.port
        listener.close()
        listener.close()
        with socket.socket() as probe:
            probe.bind(("127.0.0.1", port))

    def test_another_process_cannot_share_the_port(self):
        listener = self.make_listener()
        with socket.socket() as other:
            other.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            with self.assertRaises(OSError):
                other.bind(("127.0.0.1", listener.port))

    def test_only_loopback_http_gets_a_listener(self):
        for uri in ("https://localhost/callback", "http://example.com/callback"):
            self.assertIsNone(m.open_listener(uri, STATE, 5), uri)


# --------------------------------------------------------------------------- full flows

class LoginFlowTests(MainCase):
    def test_loopback_login_stores_the_token_in_the_credential_store_only(self):
        port = free_port()
        with self.spy_on_listeners() as listeners:
            code, out = self.run_main(browser=self.loopback_browser(port), redirect=f"http://localhost:{port}/callback")
        self.assertEqual(code, 0, out)
        self.assertEqual(self.final_status, "success")
        saved = self.saved_config()
        self.assertEqual(set(saved), {"access_token_ref", "api_key", "domain"})
        self.assertEqual(saved["domain"], "acme.egnyte.com")
        with open(self.config, encoding="utf-8") as fp:
            raw = fp.read()
        for secret in ("tok-SECRET", "sekret", "refresh-SECRET", "CODE-1"):
            self.assertNotIn(secret, raw)
            self.assertNotIn(secret, out)
        self.assertEqual(self.backend.items, {("python-egnyte", "acme.egnyte.com"): "tok-SECRET-1234"})
        self.assertTrue(listeners[0].closed)

    def test_file_store_keeps_the_token_in_a_locked_down_file(self):
        code, out = self.run_main("--store", "file")
        self.assertEqual(code, 0, out)
        saved = self.saved_config()
        self.assertEqual(saved["access_token"], "tok-SECRET-1234")
        self.assertNotIn("access_token_ref", saved)
        self.assertNotIn("sekret", json.dumps(saved))
        self.assertNotIn("refresh-SECRET", json.dumps(saved))
        self.assertEqual(self.backend.items, {})
        self.assert_only_current_user(self.config)
        self.assert_only_current_user(os.path.dirname(self.config))
        self.assertEqual([n for n in os.listdir(os.path.dirname(self.config)) if n.endswith(".tmp")], [])

    def test_keyring_mode_removes_a_stale_plaintext_token_and_keeps_other_settings(self):
        os.makedirs(os.path.dirname(self.config))
        with open(self.config, "w", encoding="utf-8") as fp:
            json.dump({"access_token": "old-plaintext", "timeout": 30}, fp)
        code, _ = self.run_main()
        self.assertEqual(code, 0)
        saved = self.saved_config()
        self.assertNotIn("access_token", saved)
        self.assertEqual(saved["timeout"], 30)

    def test_requests_are_verified_and_never_follow_redirects(self):
        code, _ = self.run_main()
        self.assertEqual(code, 0)
        for call, url in ((self.post.call_args, "https://acme.egnyte.com/puboauth/token"),
                          (self.get.call_args, "https://acme.egnyte.com/pubapi/v1/userinfo")):
            self.assertEqual(call.args[0], url)
            self.assertIs(call.kwargs["allow_redirects"], False)
            self.assertIs(call.kwargs["verify"], True)
            self.assertGreater(call.kwargs["timeout"], 0)
        self.assertEqual(self.post.call_args.kwargs["data"], {
            "client_id": "KEY123", "client_secret": "sekret", "redirect_uri": "https://localhost/callback",
            "code": "CODE-1", "grant_type": "authorization_code"})
        self.assertEqual(self.get.call_args.kwargs["headers"], {"Authorization": "Bearer tok-SECRET-1234"})

    def test_paste_mode_login(self):
        code, out = self.run_main()
        self.assertEqual(code, 0, out)
        self.assertEqual(self.prompts, 1)
        self.assertIn("signed in as dry.run", out)

    def test_paste_mode_survives_a_bad_paste(self):
        self.pasted = ["https://localhost/callback?code=EVIL&state=wrong"]
        code, _ = self.run_main()
        self.assertEqual(code, 0)
        self.assertEqual(self.prompts, 2)
        self.assertEqual(self.post.call_args.kwargs["data"]["code"], "CODE-1")

    def test_paste_mode_gives_up_after_three_bad_pastes(self):
        self.pasted = ["https://localhost/callback?code=EVIL&state=wrong"] * 3
        code, out = self.run_main()
        self.assertEqual(code, 1)
        self.post.assert_not_called()
        self.assertFalse(os.path.exists(self.config))

    def test_paste_mode_refuses_a_url_that_is_not_the_registered_redirect(self):
        for template in ("https://evil.example/callback?code=EVIL&state={state}",
                         "https://localhost/other?code=EVIL&state={state}",
                         "http://localhost/callback?code=EVIL&state={state}"):
            with self.subTest(template=template):
                self.setUp()

                def paste(prompt="", template=template):  # the right state, but the wrong place
                    self.prompts += 1
                    return template.format(state=urllib.parse.quote(auth_params(self.browser_urls[-1])["state"]))

                with mock.patch.object(self, "default_paste", paste):
                    code, _ = self.run_main()
                self.assertEqual(code, 1)
                self.assertEqual(self.prompts, 3)
                self.post.assert_not_called()

    def test_error_callback_ends_the_login_with_cleaned_output(self):
        state_box = []

        def browser(url):
            state_box.append(urllib.parse.quote(auth_params(url)["state"]))
            return True

        def paste(prompt=""):
            return ("https://localhost/callback?error=access_denied&error_description=%1B%5B31mRED%0Aforged%20line"
                    f"&state={state_box[0]}")

        with mock.patch.object(self, "default_paste", paste):
            code, out = self.run_main(browser=browser)
        self.assertEqual(code, 1)
        self.assertIn("access_denied", out)
        self.assertNotIn("\x1b", out)
        self.assertNotIn("RED\nforged", out)
        self.post.assert_not_called()

    # ---- redirects and error output

    def test_any_3xx_from_the_token_endpoint_is_an_error(self):
        self.post.return_value = FakeResponse(302, text="Location: https://evil.example/steal")
        code, out = self.run_main()
        self.assertEqual(code, 1)
        self.assertIn("HTTP 302", out)
        self.assertIn("redirect", out)
        self.assertNotIn("evil.example", out)
        self.assertEqual(self.backend.items, {})

    def test_3xx_from_userinfo_is_an_error(self):
        self.get.return_value = FakeResponse(307, text="Location: https://evil.example/steal")
        code, out = self.run_main()
        self.assertEqual(code, 1)
        self.assertIn("HTTP 307", out)
        self.assertNotIn("evil.example", out)

    def test_error_bodies_are_never_printed(self):
        self.post.return_value = FakeResponse(
            400, {"error": "invalid_grant", "error_description": "secret detail"}, text="RAW BODY WITH CODE-1")
        code, out = self.run_main()
        self.assertEqual(code, 1)
        self.assertIn("HTTP 400 (invalid_grant)", out)
        for leaked in ("secret detail", "RAW BODY", "CODE-1"):
            self.assertNotIn(leaked, out)
        self.assertFalse(os.path.exists(self.config))

    def test_unknown_error_codes_and_html_bodies_print_only_the_status(self):
        for response in (FakeResponse(400, {"error": "\x1b[31mweird"}, text="weird"),
                         FakeResponse(500, text="<html>Internal error with details</html>")):
            with self.subTest(status=response.status_code):
                self.setUp()
                self.post.return_value = response
                code, out = self.run_main()
                self.assertEqual(code, 1)
                self.assertIn(f"HTTP {response.status_code}", out)
                self.assertNotIn("weird", out)
                self.assertNotIn("Internal error", out)
                self.assertNotIn("\x1b", out)

    def test_userinfo_failure_prints_the_status_not_the_body(self):
        self.get.return_value = FakeResponse(403, text="FORBIDDEN BODY with details")
        code, out = self.run_main()
        self.assertEqual(code, 1)
        self.assertIn("HTTP 403", out)
        self.assertNotIn("FORBIDDEN BODY", out)

    def test_username_is_cleaned_and_bounded(self):
        self.get.return_value = FakeResponse(200, {"username": "ev\x1b[31mil\nuser" + "y" * 200})
        code, out = self.run_main()
        self.assertEqual(code, 0)
        self.assertNotIn("\x1b", out)
        self.assertNotIn("il\nuser", out)
        self.assertLess(max(len(line) for line in out.splitlines()), 200)

    def test_network_errors_print_only_the_exception_type(self):
        self.post.side_effect = requests.ConnectionError("https://acme.egnyte.com/puboauth/token?code=CODE-1 failed")
        code, out = self.run_main()
        self.assertEqual(code, 1)
        self.assertIn("ConnectionError", out)
        self.assertNotIn("CODE-1", out)

    def test_credential_store_failure_is_reported_without_the_token(self):
        class Broken(FakeBackend):
            def set_password(self, service, name, password):
                raise RuntimeError(f"cannot store {password}")

        self.backend = Broken()
        code, out = self.run_main()
        self.assertEqual(code, 1)
        self.assertNotIn("tok-SECRET", out)
        self.assertFalse(os.path.exists(self.config))

    # ---- listener lifecycle in the full flow

    def test_listener_is_closed_after_a_timeout(self):
        port = free_port()
        redirect = f"http://localhost:{port}/callback"
        with self.spy_on_listeners() as listeners:
            code, out = self.run_main("--timeout", "1", redirect=redirect)
        self.assertEqual(code, 1)
        self.assertIn("deadline", out)
        self.assertTrue(listeners[0].closed)
        with socket.socket() as probe:
            probe.bind(("127.0.0.1", port))

    def test_listener_is_closed_after_cancellation(self):
        port = free_port()
        with self.spy_on_listeners() as listeners, mock.patch.object(m.CallbackListener, "wait",
                                                                      side_effect=KeyboardInterrupt):
            code, out = self.run_main(redirect=f"http://localhost:{port}/callback")
        self.assertEqual(code, 1)
        self.assertIn("Cancelled", out)
        self.assertTrue(listeners[0].closed)

    def test_listener_is_closed_when_the_browser_cannot_be_launched(self):
        for behaviour in (RuntimeError("no browser"), False):
            with self.subTest(behaviour=behaviour):
                self.setUp()
                port = free_port()
                browser = mock.Mock(side_effect=behaviour) if isinstance(behaviour, Exception) \
                    else mock.Mock(return_value=behaviour)
                with self.spy_on_listeners() as listeners:
                    code, out = self.run_main("--timeout", "1", browser=browser,
                                              redirect=f"http://localhost:{port}/callback")
                self.assertEqual(code, 1)
                self.assertIn("Could not open a browser", out)
                self.assertTrue(listeners[0].closed)

    def test_invalid_callbacks_never_reach_the_token_exchange(self):
        port = free_port()
        bad = self.loopback_browser(port, callback="/callback?code=EVIL&state=wrong")
        with self.spy_on_listeners() as listeners:
            code, _ = self.run_main("--timeout", "2", browser=bad, redirect=f"http://localhost:{port}/callback")
        self.assertEqual(code, 1)
        self.post.assert_not_called()
        self.assertFalse(os.path.exists(self.config))
        self.assertTrue(listeners[0].closed)

    def test_failed_exchange_shows_failed_in_the_browser(self):
        port = free_port()
        self.post.return_value = FakeResponse(400, {"error": "invalid_grant"})
        code, _ = self.run_main(browser=self.loopback_browser(port), redirect=f"http://localhost:{port}/callback")
        self.assertEqual(code, 1)
        self.assertEqual(self.final_status, "failed")


# --------------------------------------------------------------------------- 4. no redirects

class Trap(http.server.BaseHTTPRequestHandler):
    hits = []

    def do_GET(self):
        Trap.hits.append(("GET", self.path))
        self._ok()

    def do_POST(self):
        Trap.hits.append(("POST", self.path, self.rfile.read(int(self.headers.get("Content-Length", 0)))))
        self._ok()

    def _ok(self):
        body = b'{"access_token": "stolen", "username": "stolen"}'
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):
        pass


class Redirector(http.server.BaseHTTPRequestHandler):
    target = ""

    def _redirect(self):
        self.send_response(302)
        self.send_header("Location", Redirector.target)
        self.send_header("Content-Length", "0")
        self.end_headers()

    do_GET = do_POST = _redirect

    def log_message(self, *args):
        pass


class RedirectRefusalTests(unittest.TestCase):
    def setUp(self):
        Trap.hits = []
        self.trap = self.serve(Trap)
        Redirector.target = f"http://127.0.0.1:{self.trap}/steal"
        self.redirector = self.serve(Redirector)
        patcher = mock.patch.dict(os.environ, {"NO_PROXY": "127.0.0.1,localhost", "no_proxy": "127.0.0.1,localhost"})
        patcher.start()
        self.addCleanup(patcher.stop)

    def serve(self, handler):
        server = http.server.HTTPServer(("127.0.0.1", 0), handler)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        self.addCleanup(server.server_close)
        self.addCleanup(server.shutdown)
        return server.server_address[1]

    def test_the_trap_is_reachable_when_redirects_are_followed(self):
        requests.get(f"http://127.0.0.1:{self.redirector}/x", timeout=5)  # sanity check of the test setup
        self.assertEqual(len(Trap.hits), 1)

    def test_token_exchange_does_not_follow_a_redirect(self):
        with self.assertRaises(m.LoginError) as caught:
            m.exchange_code(f"http://127.0.0.1:{self.redirector}/puboauth/token", "KEY123", "sekret",
                            "https://localhost/callback", "CODE-1")
        self.assertIn("HTTP 302", str(caught.exception))
        self.assertNotIn("steal", str(caught.exception))
        self.assertEqual(Trap.hits, [], "the client secret and code were sent to the redirect target")

    def test_userinfo_check_does_not_follow_a_redirect(self):
        with self.assertRaises(m.LoginError):
            m.fetch_username(f"http://127.0.0.1:{self.redirector}/pubapi/v1/userinfo", "tok-SECRET-1234")
        self.assertEqual(Trap.hits, [], "the bearer token was sent to the redirect target")

    def test_every_call_goes_through_one_helper_that_verifies_and_refuses_redirects(self):
        method = mock.Mock(return_value=FakeResponse(200, {}))
        m.send(method, "https://acme.egnyte.com/x", "Test")
        kwargs = method.call_args.kwargs
        self.assertIs(kwargs["verify"], True)
        self.assertIs(kwargs["allow_redirects"], False)
        self.assertGreater(kwargs["timeout"], 0)


# --------------------------------------------------------------------------- 5. PKCE

class PkceTests(MainCase):
    def test_challenge_matches_the_rfc_7636_example(self):
        self.assertEqual(m.pkce_challenge("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"),
                         "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM")

    def test_verifiers_are_fresh_and_well_formed(self):
        pairs = [m.make_pkce() for _ in range(5)]
        self.assertEqual(len({v for v, _ in pairs}), 5)
        for verifier, challenge in pairs:
            self.assertTrue(43 <= len(verifier) <= 128)
            self.assertRegex(verifier, r"^[A-Za-z0-9_-]+$")
            self.assertEqual(challenge, m.pkce_challenge(verifier))

    def test_with_pkce_the_challenge_is_sent_and_the_verifier_is_used_for_the_exchange(self):
        code, out = self.run_main("--pkce")
        self.assertEqual(code, 0, out)
        params = auth_params(self.browser_urls[0])
        self.assertEqual(params["code_challenge_method"], "S256")
        verifier = self.post.call_args.kwargs["data"]["code_verifier"]
        self.assertEqual(m.pkce_challenge(verifier), params["code_challenge"])
        self.assertNotIn(verifier, self.browser_urls[0])
        self.assertNotIn(verifier, out)
        self.assertIn("state", params)  # state validation stays on

    def test_a_new_verifier_for_every_login(self):
        self.run_main("--pkce")
        first = self.post.call_args.kwargs["data"]["code_verifier"]
        self.setUp()
        self.run_main("--pkce")
        self.assertNotEqual(first, self.post.call_args.kwargs["data"]["code_verifier"])

    def test_without_the_flag_no_pkce_parameters_are_sent_and_the_output_says_so(self):
        code, out = self.run_main()
        self.assertEqual(code, 0)
        self.assertNotIn("code_challenge", self.browser_urls[0])
        self.assertNotIn("code_verifier", self.post.call_args.kwargs["data"])
        self.assertIn("PKCE: off", out)


# --------------------------------------------------------------------------- 8. scopes

class ScopeTests(MainCase):
    def test_default_scope_is_file_system_only(self):
        self.assertEqual(m.DEFAULT_SCOPE, "Egnyte.filesystem")
        code, out = self.run_main()
        self.assertEqual(code, 0)
        self.assertEqual(auth_params(self.browser_urls[0])["scope"], "Egnyte.filesystem")
        self.assertNotIn("broader scopes", out)

    def test_links_scope_is_added_only_on_request(self):
        self.run_main("--links")
        self.assertEqual(auth_params(self.browser_urls[0])["scope"], "Egnyte.filesystem Egnyte.link")

    def test_broader_scopes_are_an_explicit_choice_and_are_flagged(self):
        code, out = self.run_main("--scope", "Egnyte.filesystem Egnyte.audit")
        self.assertEqual(code, 0)
        self.assertEqual(auth_params(self.browser_urls[0])["scope"], "Egnyte.filesystem Egnyte.audit")
        self.assertIn("broader scopes", out)
        self.assertIn("Egnyte.audit", out)

    def test_duplicates_collapse_and_unknown_scopes_are_refused(self):
        self.assertEqual(m.resolve_scope("Egnyte.filesystem Egnyte.filesystem", True), "Egnyte.filesystem Egnyte.link")
        for bad in ("Egnyte.bogus", "Egnyte.filesystem openid", "egnyte.filesystem"):
            with self.subTest(bad=bad), self.assertRaises(m.SetupError):
                m.resolve_scope(bad, False)

    def test_no_default_scope_grants_user_or_group_management(self):
        for scope in m.DEFAULT_SCOPE.split() + [m.LINKS_SCOPE]:
            self.assertNotIn(scope, {"Egnyte.user", "Egnyte.group", "Egnyte.audit", "Egnyte.permission"})


# --------------------------------------------------------------------------- 7. output

class SanitisingTests(unittest.TestCase):
    def test_control_and_format_characters_are_removed(self):
        self.assertEqual(m.safe_text("a\x1b[31mb\r\nc\td‮e\x00f"), "a[31mbcdef")

    def test_length_is_bounded(self):
        text = m.safe_text("x" * 500, 20)
        self.assertEqual(text, "x" * 20 + "...")

    def test_non_strings_are_accepted(self):
        self.assertEqual(m.safe_text(None), "None")


if __name__ == "__main__":
    unittest.main()
