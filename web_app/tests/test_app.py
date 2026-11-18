import re
import threading
import time
import unittest
import urllib.parse

import requests

from helpers import ALICE, BOB, SECRET, as_user, build_stack, connect_user, csrf_from, entry, principal, start_signin
from egnyte import exc
from token_store import TokenRecord
import identity


class Base(unittest.TestCase):
    def setUp(self):
        self.stack = build_stack(self)
        self.anon = self.stack.app.test_client()
        self.alice = as_user(self.stack.app.test_client(), ALICE, "alice@example.com")
        self.bob = as_user(self.stack.app.test_client(), BOB, "bob@example.com")

    def key(self, oid):
        return f"{identity.parse_principal(principal(oid, 'x')).key}"

    def link(self, client, code):
        response = connect_user(self, client, code)
        self.assertEqual(response.status_code, 302, response.get_data(as_text=True))

    def on_disk(self):
        import os
        data = b""
        for name in os.listdir(self.stack.folder):
            with open(os.path.join(self.stack.folder, name), "rb") as fp:
                data += fp.read()
        return data


class AuthenticationTests(Base):
    def test_every_page_needs_an_identity_except_the_health_check(self):
        for method, path in (("get", "/"), ("get", "/folders"), ("get", "/file?path=/Shared/a.txt"),
                             ("get", "/egnyte/connect"), ("get", "/egnyte/callback?code=c&state=s"),
                             ("post", "/egnyte/disconnect")):
            with self.subTest(path=path):
                self.assertEqual(getattr(self.anon, method)(path).status_code, 401)
        self.assertEqual(self.anon.get("/healthz").status_code, 200)

    def test_a_malformed_identity_header_is_not_an_identity(self):
        client = self.stack.app.test_client()
        client.environ_base["HTTP_X_MS_CLIENT_PRINCIPAL"] = principal("../../etc/passwd", "x")
        self.assertEqual(client.get("/").status_code, 401)

    def test_dev_cookie_does_nothing_when_dev_mode_is_off(self):
        self.anon.set_cookie("dev_user", "alice")
        self.assertEqual(self.anon.get("/").status_code, 401)
        self.assertEqual(self.anon.get("/dev/as/alice").status_code, 404)

    def test_security_headers_on_every_kind_of_response(self):
        for response in (self.alice.get("/"), self.anon.get("/"), self.anon.get("/healthz")):
            self.assertEqual(response.headers["Cache-Control"], "no-store")
            self.assertEqual(response.headers["X-Content-Type-Options"], "nosniff")
            # same-origin: nothing is sent to other sites, but our own form POSTs still carry a Referer, which
            # App Service Authentication's CSRF check demands (with "no-referrer" it answered every POST with 403).
            self.assertEqual(response.headers["Referrer-Policy"], "same-origin")
            self.assertIn("default-src 'none'", response.headers["Content-Security-Policy"])
            self.assertIn("frame-ancestors 'none'", response.headers["Content-Security-Policy"])

    def test_the_referrer_policy_lets_our_own_forms_send_a_referer(self):
        # Guards the production bug: with "no-referrer" the browser sends NO Referer on a form POST, so App Service
        # Authentication logs "Cross-site request forgery detected ... from referer ''" and returns 403 for every
        # button. Only policies that send the full URL on same-origin requests are accepted here.
        for response in (self.alice.get("/"), self.alice.get("/permissions")):
            self.assertIn(response.headers["Referrer-Policy"],
                          {"same-origin", "strict-origin-when-cross-origin", "origin-when-cross-origin"})

    def test_session_cookie_is_locked_down(self):
        self.link(self.alice, "code-alice")
        cookie = self.alice.get("/").headers.get("Set-Cookie", "")
        self.assertIn("HttpOnly", cookie)
        self.assertIn("Secure", cookie)
        self.assertIn("SameSite=Lax", cookie)


class ConnectFlowTests(Base):
    def test_connect_sends_the_user_to_egnyte_without_the_secret(self):
        response = self.alice.get("/egnyte/connect")
        self.assertEqual(response.status_code, 302)
        url = urllib.parse.urlsplit(response.headers["Location"])
        self.assertEqual((url.scheme, url.netloc, url.path), ("https", "stout.egnyte.com", "/puboauth/token"))
        query = urllib.parse.parse_qs(url.query)
        self.assertEqual(query["client_id"], ["CLIENT123"])
        self.assertEqual(query["redirect_uri"], ["https://webapp.example/egnyte/callback"])
        self.assertEqual(query["scope"], ["Egnyte.filesystem"])
        self.assertEqual(query["response_type"], ["code"])
        self.assertGreaterEqual(len(query["state"][0]), 40)
        self.assertNotIn(SECRET, response.headers["Location"])

    def test_each_connect_gets_a_new_state(self):
        self.assertNotEqual(start_signin(self, self.alice), start_signin(self, self.alice))

    def test_completing_the_flow_stores_that_users_tokens_encrypted(self):
        self.link(self.alice, "code-alice")
        record = self.stack.store.load(self.key(ALICE))
        self.assertEqual((record.access_token, record.refresh_token, record.egnyte_username),
                         ("alice-access", "alice-refresh", "alice.eg"))
        self.assertEqual(self.stack.oauth.exchanged, ["code-alice"])
        disk = self.on_disk()
        for needle in (b"alice-access", b"alice-refresh", b"alice.eg", SECRET.encode()):
            self.assertNotIn(needle, disk)
        page = self.alice.get("/").get_data(as_text=True)
        self.assertIn("alice.eg", page)
        self.assertIn("Refresh token: stored", page)

    def test_the_secret_and_tokens_never_appear_in_any_page(self):
        self.link(self.alice, "code-alice")
        for path in ("/", "/folders", "/folders?path=/Shared", "/egnyte/callback?error=x&state=y", "/nowhere"):
            body = self.alice.get(path).get_data(as_text=True)
            for needle in (SECRET, "alice-access", "alice-refresh"):
                self.assertNotIn(needle, body, path)

    def test_a_wrong_state_is_refused_and_the_code_is_never_exchanged(self):
        start_signin(self, self.alice)
        response = self.alice.get("/egnyte/callback?code=code-alice&state=not-the-state")
        self.assertEqual(response.status_code, 400)
        self.assertEqual(self.stack.oauth.exchanged, [])
        self.assertIsNone(self.stack.store.load(self.key(ALICE)))

    def test_a_callback_cannot_be_replayed(self):
        state = start_signin(self, self.alice)
        self.assertEqual(self.alice.get(f"/egnyte/callback?code=code-alice&state={state}").status_code, 302)
        self.assertEqual(self.alice.get(f"/egnyte/callback?code=code-alice&state={state}").status_code, 400)
        self.assertEqual(self.stack.oauth.exchanged, ["code-alice"])

    def test_one_user_cannot_finish_a_sign_in_that_another_user_started(self):
        # Bob is tricked into opening a callback link carrying Alice's code and state (login CSRF).
        state = start_signin(self, self.alice)
        response = self.bob.get(f"/egnyte/callback?code=code-alice&state={state}")
        self.assertEqual(response.status_code, 400)
        self.assertEqual(self.stack.oauth.exchanged, [])
        self.assertIsNone(self.stack.store.load(self.key(BOB)))

    def test_a_sign_in_expires(self):
        state = start_signin(self, self.alice)
        self.stack.clock.now += 601
        self.assertEqual(self.alice.get(f"/egnyte/callback?code=code-alice&state={state}").status_code, 400)
        self.assertEqual(self.stack.oauth.exchanged, [])

    def test_an_error_from_egnyte_is_shown_safely_and_stores_nothing(self):
        state = start_signin(self, self.alice)
        response = self.alice.get(f"/egnyte/callback?error=access_denied&error_description=%3Cscript%3E&state={state}")
        body = response.get_data(as_text=True)
        self.assertEqual(response.status_code, 400)
        self.assertIn("access_denied", body)
        self.assertNotIn("<script>", body)
        self.assertIsNone(self.stack.store.load(self.key(ALICE)))

    def test_a_rejected_code_gives_a_safe_error_and_stores_nothing(self):
        response = connect_user(self, self.alice, "bad-code")
        body = response.get_data(as_text=True)
        self.assertEqual(response.status_code, 502)
        self.assertIn("HTTP 400 (invalid_grant)", body)
        self.assertNotIn(SECRET, body)
        self.assertIsNone(self.stack.store.load(self.key(ALICE)))

    def test_malformed_callbacks_are_refused(self):
        start_signin(self, self.alice)
        for query in ("", "code=c", "state=s", "code=c&error=e&state=s", "code=a&code=b&state=s"):
            with self.subTest(query=query):
                self.assertEqual(self.alice.get(f"/egnyte/callback?{query}").status_code, 400)
        self.assertEqual(self.stack.oauth.exchanged, [])


class DisconnectTests(Base):
    def test_disconnect_needs_the_csrf_token(self):
        self.link(self.alice, "code-alice")
        self.assertEqual(self.alice.post("/egnyte/disconnect").status_code, 400)
        self.assertEqual(self.alice.post("/egnyte/disconnect", data={"csrf": "guess"}).status_code, 400)
        self.assertIsNotNone(self.stack.store.load(self.key(ALICE)))

    def test_disconnect_with_the_token_removes_the_stored_tokens(self):
        self.link(self.alice, "code-alice")
        token = csrf_from(self.alice.get("/"))
        self.assertEqual(self.alice.post("/egnyte/disconnect", data={"csrf": token}).status_code, 302)
        self.assertIsNone(self.stack.store.load(self.key(ALICE)))
        self.assertEqual(self.on_disk(), b"")

    def test_another_users_csrf_token_does_not_work(self):
        self.link(self.alice, "code-alice")
        self.link(self.bob, "code-bob")
        bobs_token = csrf_from(self.bob.get("/"))
        self.assertEqual(self.alice.post("/egnyte/disconnect", data={"csrf": bobs_token}).status_code, 400)
        self.assertIsNotNone(self.stack.store.load(self.key(ALICE)))

    def test_disconnect_cannot_be_triggered_with_a_get(self):
        self.link(self.alice, "code-alice")
        self.assertEqual(self.alice.get("/egnyte/disconnect").status_code, 405)


class MultiUserTests(Base):
    """The point of the whole app: each person gets their own Egnyte permissions."""

    def setUp(self):
        super().setUp()
        self.link(self.alice, "code-alice")
        self.link(self.bob, "code-bob")

    def test_two_users_see_different_things_in_the_same_folder(self):
        alice_page = self.alice.get("/folders?path=/Shared").get_data(as_text=True)
        bob_page = self.bob.get("/folders?path=/Shared").get_data(as_text=True)
        self.assertIn("Team A", alice_page)
        self.assertNotIn("Team B", alice_page)
        self.assertIn("Team B", bob_page)
        self.assertNotIn("Team A", bob_page)

    def test_each_request_uses_only_its_own_users_token_and_closes_the_client(self):
        self.alice.get("/folders?path=/Shared")
        self.bob.get("/folders?path=/Shared")
        self.alice.get("/folders?path=/Shared")
        self.assertEqual(self.stack.world.tokens_used(), ["alice-access", "bob-access", "alice-access"])
        self.assertTrue(all(client.closed for client in self.stack.world.clients))

    def test_the_default_folder_is_the_users_own_private_folder(self):
        alice_page = self.alice.get("/folders").get_data(as_text=True)
        self.assertIn("/Private/alice.eg", alice_page)
        self.assertIn("notes.txt", alice_page)
        self.assertIn("/Private/bob.eg", self.bob.get("/folders").get_data(as_text=True))

    def test_one_user_cannot_browse_into_anothers_private_folder(self):
        response = self.bob.get("/folders?path=/Private/alice.eg")
        self.assertEqual(response.status_code, 404)
        self.assertNotIn("notes.txt", response.get_data(as_text=True))

    def test_downloads_follow_the_same_rule(self):
        self.assertEqual(self.alice.get("/file?path=/Private/alice.eg/notes.txt").data, b"hello")
        self.assertEqual(self.bob.get("/file?path=/Private/alice.eg/notes.txt").status_code, 404)
        self.assertEqual(self.bob.get("/file?path=/Shared/a.txt").status_code, 404)
        self.assertEqual(self.alice.get("/file?path=/Shared/a.txt").data, b"abc")

    def test_disconnecting_one_user_leaves_the_other_connected(self):
        self.alice.post("/egnyte/disconnect", data={"csrf": csrf_from(self.alice.get("/"))})
        self.assertEqual(self.alice.get("/folders").status_code, 409)
        self.assertEqual(self.bob.get("/folders?path=/Shared").status_code, 200)

    def test_each_user_has_their_own_stored_record(self):
        self.assertEqual(self.stack.store.load(self.key(ALICE)).egnyte_username, "alice.eg")
        self.assertEqual(self.stack.store.load(self.key(BOB)).egnyte_username, "bob.eg")


class NotConnectedTests(Base):
    def test_browsing_without_connecting_offers_to_connect(self):
        for path in ("/folders", "/folders?path=/Shared", "/file?path=/Shared/a.txt"):
            with self.subTest(path=path):
                response = self.alice.get(path)
                self.assertEqual(response.status_code, 409)
                self.assertIn("/egnyte/connect", response.get_data(as_text=True))
        self.assertEqual(self.stack.world.clients, [])

    def test_the_home_page_offers_to_connect(self):
        self.assertIn("Connect to Egnyte", self.alice.get("/").get_data(as_text=True))


class TokenLifecycleTests(Base):
    def setUp(self):
        super().setUp()
        self.link(self.alice, "code-alice")
        self.world = self.stack.world
        self.world.trees["refreshed-access"] = self.world.trees["alice-access"]

    def test_a_rejected_token_is_refreshed_and_the_request_is_retried(self):
        self.world.rejected.add("alice-access")
        self.assertEqual(self.alice.get("/folders?path=/Shared").status_code, 200)
        self.assertEqual(self.stack.oauth.refreshed, ["alice-refresh"])
        record = self.stack.store.load(self.key(ALICE))
        self.assertEqual((record.access_token, record.refresh_token), ("refreshed-access", "rotated-refresh"))
        self.assertEqual(self.world.tokens_used(), ["alice-access", "refreshed-access"])
        self.alice.get("/folders?path=/Shared")
        self.assertEqual(self.world.tokens_used()[-1], "refreshed-access")
        self.assertEqual(len(self.stack.oauth.refreshed), 1)

    def test_when_the_refresh_fails_the_user_is_disconnected(self):
        self.world.rejected.add("alice-access")
        self.stack.oauth.refresh_fails = True
        response = self.alice.get("/folders?path=/Shared")
        self.assertEqual(response.status_code, 409)
        self.assertIn("/egnyte/connect", response.get_data(as_text=True))
        self.assertIsNone(self.stack.store.load(self.key(ALICE)))

    def test_without_a_refresh_token_a_rejected_token_disconnects(self):
        record = self.stack.store.load(self.key(ALICE))
        self.stack.store.save(self.key(ALICE), TokenRecord(record.access_token, None, record.expires_at,
                                                           record.egnyte_username, record.linked_at))
        self.world.rejected.add("alice-access")
        self.assertEqual(self.alice.get("/folders?path=/Shared").status_code, 409)
        self.assertEqual(self.stack.oauth.refreshed, [])
        self.assertIsNone(self.stack.store.load(self.key(ALICE)))

    def test_a_token_close_to_expiry_is_refreshed_before_use(self):
        record = self.stack.store.load(self.key(ALICE))
        self.stack.store.save(self.key(ALICE), TokenRecord(record.access_token, record.refresh_token, time.time() + 60,
                                                           record.egnyte_username, record.linked_at))
        self.assertEqual(self.alice.get("/folders?path=/Shared").status_code, 200)
        self.assertEqual(self.world.tokens_used(), ["refreshed-access"])

    def test_an_expired_token_that_cannot_be_refreshed_disconnects_without_calling_egnyte(self):
        record = self.stack.store.load(self.key(ALICE))
        self.stack.store.save(self.key(ALICE), TokenRecord(record.access_token, record.refresh_token, time.time() - 5,
                                                           record.egnyte_username, record.linked_at))
        self.stack.oauth.refresh_fails = True
        self.assertEqual(self.alice.get("/folders?path=/Shared").status_code, 409)
        self.assertEqual(self.world.clients, [])
        self.assertIsNone(self.stack.store.load(self.key(ALICE)))

    def test_a_token_close_to_expiry_still_works_if_the_refresh_fails(self):
        record = self.stack.store.load(self.key(ALICE))
        self.stack.store.save(self.key(ALICE), TokenRecord(record.access_token, record.refresh_token, time.time() + 60,
                                                           record.egnyte_username, record.linked_at))
        self.stack.oauth.refresh_fails = True
        self.assertEqual(self.alice.get("/folders?path=/Shared").status_code, 200)
        self.assertEqual(self.world.tokens_used(), ["alice-access"])

    def test_simultaneous_requests_with_a_rejected_token_refresh_only_once(self):
        self.world.rejected.add("alice-access")
        user = identity.parse_principal(principal(ALICE, "a"))
        results, errors = [], []

        def call():
            try:
                results.append(self.stack.access.run(user, lambda client: client.folder("/Shared").list()))
            except BaseException as e:
                errors.append(e)
        threads = [threading.Thread(target=call) for _ in range(6)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        self.assertEqual(errors, [])
        self.assertEqual(len(results), 6)
        self.assertEqual(self.stack.oauth.refreshed, ["alice-refresh"])


class EgnyteFailureTests(Base):
    def setUp(self):
        super().setUp()
        self.link(self.alice, "code-alice")

    def test_unexpected_egnyte_errors_become_a_generic_page(self):
        self.stack.world.fail_with = exc.EgnyteError("https://internal-url?token=LEAKED", {"headers": "x"})
        response = self.alice.get("/folders?path=/Shared")
        body = response.get_data(as_text=True)
        self.assertEqual(response.status_code, 502)
        self.assertIn("EgnyteError", body)
        self.assertNotIn("LEAKED", body)
        self.assertNotIn("internal-url", body)

    def test_network_errors_become_a_generic_page(self):
        self.stack.world.fail_with = requests.ConnectionError("https://host/secret?token=LEAKED")
        response = self.alice.get("/folders?path=/Shared")
        self.assertEqual(response.status_code, 502)
        self.assertNotIn("LEAKED", response.get_data(as_text=True))

    def test_permission_errors_have_their_own_page(self):
        self.stack.world.fail_with = exc.InsufficientPermissions("nope")
        self.assertEqual(self.alice.get("/folders?path=/Shared").status_code, 403)


class FolderPageTests(Base):
    def setUp(self):
        super().setUp()
        self.link(self.alice, "code-alice")

    def test_names_from_egnyte_are_escaped(self):
        nasty = "<img src=x onerror=alert(1)>"
        self.stack.world.trees["alice-access"]["/Shared"] = (
            [entry(f"/Shared/{nasty}", name=nasty)], [entry(f"/Shared/{nasty}.txt", 10, name=nasty + ".txt")])
        body = self.alice.get("/folders?path=/Shared").get_data(as_text=True)
        self.assertNotIn("<img src=x", body)
        self.assertIn("&lt;img src=x", body)

    def test_links_encode_awkward_names_and_work_when_followed(self):
        folder, file = "/Shared/R&D team+x", "/Shared/q1 report+final.txt"
        self.stack.world.trees["alice-access"]["/Shared"] = ([entry(folder)], [entry(file, 7)])
        self.stack.world.trees["alice-access"][folder] = ([], [entry(folder + "/in.txt", 2)])
        self.stack.world.contents[file] = b"payload"
        body = self.alice.get("/folders?path=/Shared").get_data(as_text=True)
        self.assertIn("(7 bytes)", body)
        hrefs = [href.replace("&amp;", "&") for href in re.findall(r'href="(/(?:folders|file)\?path=[^"]*)"', body)]
        folder_link = next(h for h in hrefs if "R%26D" in h)
        file_link = next(h for h in hrefs if h.startswith("/file"))
        self.assertNotIn("&D", folder_link)             # the & in the name must be encoded
        self.assertIn("%2B", folder_link + file_link)   # and so must the +
        self.assertIn("in.txt", self.alice.get(folder_link).get_data(as_text=True))
        self.assertEqual(self.alice.get(file_link).data, b"payload")

    def test_a_parent_link_is_shown_below_the_top_level(self):
        self.stack.world.trees["alice-access"]["/Shared/Team A"] = ([], [])
        self.assertIn("&larr; /Shared", self.alice.get("/folders?path=/Shared/Team%20A").get_data(as_text=True))
        self.assertNotIn("&larr;", self.alice.get("/folders?path=/Shared").get_data(as_text=True))

    def test_an_empty_folder_says_so(self):
        self.stack.world.trees["alice-access"]["/Shared/Team A"] = ([], [])
        self.assertIn("empty", self.alice.get("/folders?path=/Shared/Team%20A").get_data(as_text=True))

    def test_a_file_path_is_not_a_folder(self):
        self.assertEqual(self.alice.get("/folders?path=/Shared/a.txt").status_code, 400)

    def test_listings_are_capped(self):
        self.stack.world.trees["alice-access"]["/Shared"] = ([entry(f"/Shared/f{i}") for i in range(600)], [])
        body = self.alice.get("/folders?path=/Shared").get_data(as_text=True)
        self.assertEqual(body.count("/folders?path=/Shared/f"), 500)
        self.assertIn("first 500", body)

    def test_bad_paths_are_refused_before_egnyte_is_called(self):
        before = len(self.stack.world.clients)
        for path in ("/", "/Shared/../Private", "/Shared/./x", "\\Shared", "/Shared\\x", "/Shared/\x00", "/Shared/\n",
                     "/" + "a" * 600, "/Shared/%2e%2e"):
            if path.endswith("%2e%2e"):
                continue  # percent-encoding is decoded once by the web server, then checked like any other path
            with self.subTest(path=path):
                self.assertEqual(self.alice.get("/folders", query_string={"path": path}).status_code, 400)
                self.assertEqual(self.alice.get("/file", query_string={"path": path}).status_code, 400)
        self.assertEqual(self.alice.get("/file").status_code, 400)
        self.assertEqual(len(self.stack.world.clients), before)

    def test_a_missing_folder_is_a_404(self):
        self.assertEqual(self.alice.get("/folders?path=/Shared/Nope").status_code, 404)


class DownloadTests(Base):
    def setUp(self):
        super().setUp()
        self.link(self.alice, "code-alice")

    def test_downloads_are_attachments_that_browsers_will_not_render(self):
        response = self.alice.get("/file?path=/Shared/a.txt")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.data, b"abc")
        self.assertEqual(response.mimetype, "application/octet-stream")
        self.assertTrue(response.headers["Content-Disposition"].startswith("attachment"))
        self.assertIn("a.txt", response.headers["Content-Disposition"])
        self.assertEqual(response.headers["X-Content-Type-Options"], "nosniff")

    def test_non_ascii_file_names_are_encoded_in_the_header(self):
        self.stack.world.trees["alice-access"]["/Shared"] = ([], [entry("/Shared/héllo wörld.txt", 3)])
        self.stack.world.contents["/Shared/héllo wörld.txt"] = b"abc"
        response = self.alice.get("/file", query_string={"path": "/Shared/héllo wörld.txt"})
        self.assertEqual(response.status_code, 200)
        self.assertIn("filename*=", response.headers["Content-Disposition"])

    def test_large_files_are_refused_without_downloading(self):
        import app as app_module
        original = app_module.MAX_DOWNLOAD_BYTES
        app_module.MAX_DOWNLOAD_BYTES = 2
        self.addCleanup(setattr, app_module, "MAX_DOWNLOAD_BYTES", original)
        self.assertEqual(self.alice.get("/file?path=/Shared/a.txt").status_code, 413)

    def test_a_missing_file_is_a_404(self):
        self.assertEqual(self.alice.get("/file?path=/Shared/missing.txt").status_code, 404)


class LoggingTests(Base):
    """Whatever the app logs, in success and failure, must not contain secrets or tokens."""

    def test_no_log_line_contains_a_secret_or_token(self):
        import logging
        records = []

        class Capture(logging.Handler):
            def emit(self, record):
                records.append(record.getMessage())
        handler = Capture(level=logging.DEBUG)
        root = logging.getLogger()
        previous = root.level
        root.addHandler(handler)
        root.setLevel(logging.DEBUG)
        self.addCleanup(root.removeHandler, handler)
        self.addCleanup(root.setLevel, previous)

        self.link(self.alice, "code-alice")                                  # success
        connect_user(self, self.bob, "bad-code")                              # Egnyte rejects the code
        self.alice.get(f"/egnyte/callback?error=access_denied&state={start_signin(self, self.alice)}")
        self.stack.world.trees["refreshed-access"] = self.stack.world.trees["alice-access"]
        self.stack.world.rejected.add("alice-access")
        self.stack.oauth.refresh_fails = True
        self.alice.get("/folders?path=/Shared")                               # refresh fails, user disconnected
        self.link(self.alice, "code-alice")
        self.stack.world.fail_with = exc.EgnyteError("https://x?token=alice-access", {"headers": "alice-refresh"})
        self.alice.get("/folders?path=/Shared")                               # unexpected Egnyte error

        self.assertTrue(records)
        for message in records:
            for needle in (SECRET, "alice-access", "alice-refresh", "bob-access", "code-alice"):
                self.assertNotIn(needle, message)


class AzureAuthenticationWarningTests(unittest.TestCase):
    def build(self, auth_flag):
        import os
        from unittest import mock
        env = {"WEBSITE_AUTH_ENABLED": auth_flag} if auth_flag is not None else {}
        with mock.patch.dict(os.environ, env, clear=False):
            if auth_flag is None:
                os.environ.pop("WEBSITE_AUTH_ENABLED", None)
            return build_stack(self, on_azure=True)

    def test_warns_when_app_service_authentication_does_not_look_enabled(self):
        with self.assertLogs("app", "WARNING") as logs:
            self.build(None)
        self.assertIn("Authentication does not look enabled", logs.output[0])

    def test_quiet_when_it_is_enabled(self):
        import logging
        with self.assertNoLogs("app", logging.WARNING):
            self.build("True")


class DevModeTests(unittest.TestCase):
    def setUp(self):
        self.stack = build_stack(self, allow_dev_user=True, redirect_uri="http://localhost:5000/egnyte/callback")

    def test_dev_sign_in_gives_each_browser_its_own_identity(self):
        one, two = self.stack.app.test_client(), self.stack.app.test_client()
        self.assertEqual(one.get("/").status_code, 401)
        self.assertEqual(one.get("/dev/as/alice").status_code, 302)
        two.get("/dev/as/bob")
        self.assertIn("alice (dev)", one.get("/").get_data(as_text=True))
        self.assertIn("bob (dev)", two.get("/").get_data(as_text=True))

    def test_bad_dev_names_are_refused(self):
        self.assertEqual(self.stack.app.test_client().get("/dev/as/Bad Name").status_code, 400)

    def test_cookies_work_over_plain_http_locally(self):
        cookie = self.stack.app.test_client().get("/dev/as/alice").headers.get("Set-Cookie", "")
        self.assertNotIn("Secure", cookie)


class CleanPathTests(unittest.TestCase):
    def test_normalisation(self):
        from app import clean_path, create_app  # noqa: F401
        stack = build_stack(self)
        with stack.app.test_request_context():
            self.assertEqual(clean_path("/Shared/Team A/"), "/Shared/Team A")
            self.assertEqual(clean_path("Shared/x"), "/Shared/x")
            self.assertEqual(clean_path("  /Shared  "), "/Shared")


if __name__ == "__main__":
    unittest.main()
