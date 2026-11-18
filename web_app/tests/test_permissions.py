"""The permission test section: three buttons on the configured Egnyte folder, run as the signed-in user."""
import hashlib
import json
import unittest
from types import SimpleNamespace
from urllib.parse import quote, unquote, urlsplit

import requests

import identity
import permission_check as pc
from egnyte import exc
from egnyte.client import EgnyteClient
from helpers import (ALICE, BOB, TENANT, as_user, build_stack, connect_user, csrf_from, page_text, principal)
from settings import DEFAULT_PERMISSION_FOLDER

FOLDER = DEFAULT_PERMISSION_FOLDER
ENCODED = quote(FOLDER, safe="/")          # how the library writes the folder into a URL
CAROL = "cccccccc-cccc-cccc-cccc-cccccccccccc"


class Base(unittest.TestCase):
    """Alice can write, Bob can only read, and anyone else has no access (see FakeEgnyte)."""

    def setUp(self):
        self.stack = build_stack(self)
        self.world = self.stack.world
        self.anon = self.stack.app.test_client()
        self.alice = as_user(self.stack.app.test_client(), ALICE, "alice@example.com")
        self.bob = as_user(self.stack.app.test_client(), BOB, "bob@example.com")
        for client, code in ((self.alice, "code-alice"), (self.bob, "code-bob")):
            self.assertEqual(connect_user(self, client, code).status_code, 302)

    def press(self, client, action):
        """Press a button the way a browser does: with the page's CSRF token, following the redirect."""
        token = csrf_from(client.get("/permissions"))
        return client.post(f"/permissions/{action}", data={"csrf": token}, follow_redirects=True)

    def files(self):
        return dict(self.world.authz_files)


class PageTests(Base):
    def test_everything_needs_sign_in_and_a_connected_account(self):
        self.assertEqual(self.anon.get("/permissions").status_code, 401)
        for action in ("edit", "create", "delete"):
            self.assertEqual(self.anon.post(f"/permissions/{action}").status_code, 401)
        stranger = as_user(self.stack.app.test_client(), CAROL, "carol@example.com")
        response = stranger.get("/permissions")
        self.assertEqual(response.status_code, 409)
        self.assertIn("/egnyte/connect", response.get_data(as_text=True))

    def test_the_home_page_links_to_it(self):
        self.assertIn('href="/permissions"', self.alice.get("/").get_data(as_text=True))

    def test_shows_the_file_its_contents_and_who_changed_it(self):
        text = page_text(self.alice.get("/permissions"))
        self.assertIn("Text Test.txt", text)
        self.assertIn("first line", text)
        self.assertIn("(11 bytes)", text)
        self.assertIn("Last modified Wed, 18 Nov 2026 01:00:00 GMT by someone.eg", text)
        self.assertIn("alice.eg", text)                      # the Egnyte account it runs as
        self.assertIn("alice@example.com", text)             # and the signed-in user, who the edit line names
        self.assertIn('adds the line "edited by alice@example.com"', text)
        for action in ("edit", "create", "delete"):
            self.assertIn(f'action="/permissions/{action}"', text)

    def test_a_read_only_user_sees_the_contents_too(self):
        self.assertIn("first line", page_text(self.bob.get("/permissions")))

    def test_a_user_with_no_access_gets_an_explanation_and_still_has_the_buttons(self):
        self.world.authz_levels["bob-access"] = "none"
        text = page_text(self.bob.get("/permissions"))
        self.assertIn("not allowed to open this folder", text)
        self.assertNotIn("first line", text)
        self.assertIn('action="/permissions/edit"', text)

    def test_missing_folder_and_missing_file_are_explained(self):
        self.world.authz_files.clear()
        self.assertIn("does not exist in the folder", page_text(self.alice.get("/permissions")))
        self.world.authz_exists = False
        self.assertIn("does not exist, or your Egnyte account can't see it", page_text(self.alice.get("/permissions")))

    def test_a_listing_that_can_be_read_but_a_file_that_cannot(self):
        original = self.world.authz_levels["bob-access"]
        self.world.authz_levels["bob-access"] = "read"
        client_class = type(self.world.factory(None, "bob-access", None))
        patched = client_class._authz_file

        def unreadable(self_, path):
            file = patched(self_, path)
            file.download = lambda: (_ for _ in ()).throw(exc.InsufficientPermissions("no"))
            return file
        client_class._authz_file = unreadable
        self.addCleanup(setattr, client_class, "_authz_file", patched)
        self.addCleanup(self.world.authz_levels.__setitem__, "bob-access", original)
        self.assertIn("is not allowed to read the file", page_text(self.bob.get("/permissions")))

    def test_large_files_are_not_loaded(self):
        self.world.authz_files["Text Test.txt"] = b"x" * (pc.MAX_EDIT_BYTES + 1)
        text = page_text(self.alice.get("/permissions"))
        self.assertIn("too large to show or edit", text)
        self.assertNotIn("xxxxxxxx", text)

    def test_tokens_never_appear(self):
        for client in (self.alice, self.bob):
            body = page_text(client.get("/permissions"))
            for needle in ("alice-access", "bob-access", "alice-refresh", "bob-refresh"):
                self.assertNotIn(needle, body)


class EditTests(Base):
    def test_adds_a_line_naming_the_signed_in_user(self):
        response = self.press(self.alice, "edit")
        self.assertEqual(self.files()["Text Test.txt"], b"first line\nedited by alice@example.com\n")
        text = page_text(response)
        self.assertIn('Added the line "edited by alice@example.com" to Text Test.txt, as the Egnyte account alice.eg.', text)
        self.assertIn("edited by alice@example.com", text.split("Last modified")[1])      # the preview shows it
        self.assertEqual(self.world.authz_writes, [("alice-access", "upload", "Text Test.txt")])

    def test_two_people_editing_leave_two_lines_in_order(self):
        self.world.authz_levels["bob-access"] = "write"
        self.press(self.alice, "edit")
        self.press(self.bob, "edit")
        self.assertEqual(self.files()["Text Test.txt"],
                         b"first line\nedited by alice@example.com\nedited by bob@example.com\n")

    def test_a_missing_final_newline_is_added_and_an_empty_file_is_handled(self):
        self.world.authz_files["Text Test.txt"] = b"no newline"
        self.press(self.alice, "edit")
        self.assertEqual(self.files()["Text Test.txt"], b"no newline\nedited by alice@example.com\n")
        self.world.authz_files["Text Test.txt"] = b""
        self.press(self.alice, "edit")
        self.assertEqual(self.files()["Text Test.txt"], b"edited by alice@example.com\n")

    def test_existing_content_is_kept_byte_for_byte(self):
        original = "héllo\r\nzażółć\n".encode("utf-8")
        self.world.authz_files["Text Test.txt"] = original
        self.press(self.alice, "edit")
        self.assertEqual(self.files()["Text Test.txt"], original + b"edited by alice@example.com\n")

    def test_a_read_only_user_is_refused_and_nothing_changes(self):
        response = self.press(self.bob, "edit")
        self.assertEqual(self.files()["Text Test.txt"], b"first line\n")
        self.assertEqual(self.world.authz_writes, [])
        self.assertIn(f"Egnyte refused: the Egnyte account bob.eg is not allowed to edit files in {FOLDER}.",
                      page_text(response))
        self.assertIn("notice-denied", response.get_data(as_text=True))

    def test_a_user_with_no_access_is_refused_too(self):
        self.world.authz_levels["bob-access"] = "none"
        response = self.press(self.bob, "edit")
        self.assertIn("Egnyte refused: the Egnyte account bob.eg is not allowed to edit files", page_text(response))
        self.assertEqual(self.files()["Text Test.txt"], b"first line\n")

    def test_a_missing_file_is_reported_and_not_created(self):
        self.world.authz_files.clear()
        response = self.press(self.alice, "edit")
        self.assertIn("Text Test does not exist yet. Use Create file first.", page_text(response))
        self.assertEqual(self.files(), {})

    def test_either_name_works_in_any_capitals(self):
        for name in ("Text Test", "text test.TXT", "TEXT TEST.txt"):
            with self.subTest(name=name):
                self.world.authz_files.clear()
                self.world.authz_files[name] = b"x\n"
                self.press(self.alice, "edit")
                self.assertEqual(self.files(), {name: b"x\nedited by alice@example.com\n"})   # edited in place, no copy

    def test_a_name_cannot_inject_extra_lines(self):
        evil = as_user(self.stack.app.test_client(), ALICE, "evil\nedited by admin")
        self.press(evil, "edit")
        content = self.files()["Text Test.txt"].decode()
        self.assertEqual(content.count("\n"), 2)                   # the first line and exactly one new line
        self.assertNotIn("\nedited by admin", content)

    def test_large_files_are_not_edited(self):
        big = b"x" * (pc.MAX_EDIT_BYTES + 1)
        self.world.authz_files["Text Test.txt"] = big
        response = self.press(self.alice, "edit")
        self.assertIn("too large to edit here", page_text(response))
        self.assertEqual(self.files()["Text Test.txt"], big)

    def test_a_missing_folder_is_reported(self):
        self.world.authz_exists = False
        self.assertIn("does not exist, or your Egnyte account can't see it", page_text(self.press(self.alice, "edit")))


class CreateTests(Base):
    def test_creates_the_file_when_it_is_missing(self):
        self.world.authz_files.clear()
        response = self.press(self.alice, "create")
        self.assertEqual(self.files(), {"Text Test.txt": b"created by alice@example.com\n"})
        self.assertIn("Created Text Test.txt, as the Egnyte account alice.eg.", page_text(response))

    def test_does_nothing_when_it_already_exists(self):
        response = self.press(self.alice, "create")
        self.assertIn("Text Test.txt already exists, so nothing was changed.", page_text(response))
        self.assertEqual(self.files(), {"Text Test.txt": b"first line\n"})
        self.assertEqual(self.world.authz_writes, [])

    def test_an_existing_file_without_the_extension_is_not_duplicated(self):
        self.world.authz_files.clear()
        self.world.authz_files["Text Test"] = b"x\n"
        self.assertIn("Text Test already exists", page_text(self.press(self.alice, "create")))
        self.assertEqual(self.files(), {"Text Test": b"x\n"})

    def test_a_read_only_user_cannot_create(self):
        self.world.authz_files.clear()
        response = self.press(self.bob, "create")
        self.assertIn(f"Egnyte refused: the Egnyte account bob.eg is not allowed to create files in {FOLDER}.",
                      page_text(response))
        self.assertEqual(self.files(), {})

    def test_a_user_with_no_access_cannot_create(self):
        self.world.authz_files.clear()
        self.world.authz_levels["bob-access"] = "none"
        self.assertIn("Egnyte refused", page_text(self.press(self.bob, "create")))
        self.assertEqual(self.files(), {})

    def test_a_missing_folder_is_reported_and_nothing_is_created(self):
        self.world.authz_exists = False
        self.world.authz_files.clear()
        self.assertIn("does not exist, or your Egnyte account can't see it", page_text(self.press(self.alice, "create")))
        self.assertEqual(self.files(), {})


class DeleteTests(Base):
    def test_deletes_the_file(self):
        response = self.press(self.alice, "delete")
        self.assertEqual(self.files(), {})
        self.assertIn("Deleted Text Test.txt, as the Egnyte account alice.eg.", page_text(response))
        self.assertIn("does not exist in the folder", page_text(response))
        self.assertEqual(self.world.authz_writes, [("alice-access", "delete", "Text Test.txt")])

    def test_deleting_a_missing_file_is_reported(self):
        self.world.authz_files.clear()
        self.assertIn("Text Test does not exist, so there is nothing to delete.", page_text(self.press(self.alice, "delete")))

    def test_a_read_only_user_cannot_delete(self):
        response = self.press(self.bob, "delete")
        self.assertIn(f"Egnyte refused: the Egnyte account bob.eg is not allowed to delete files in {FOLDER}.",
                      page_text(response))
        self.assertEqual(self.files(), {"Text Test.txt": b"first line\n"})

    def test_a_user_with_no_access_cannot_delete(self):
        self.world.authz_levels["bob-access"] = "none"
        self.assertIn("Egnyte refused", page_text(self.press(self.bob, "delete")))
        self.assertEqual(self.files(), {"Text Test.txt": b"first line\n"})

    def test_either_name_is_found(self):
        for name in ("Text Test", "text test.TXT"):
            with self.subTest(name=name):
                self.world.authz_files.clear()
                self.world.authz_files[name] = b"x\n"
                self.press(self.alice, "delete")
                self.assertEqual(self.files(), {})

    def test_the_whole_lifecycle(self):
        self.press(self.alice, "delete")
        self.press(self.alice, "create")
        self.press(self.alice, "edit")
        self.assertEqual(self.files(), {"Text Test.txt": b"created by alice@example.com\nedited by alice@example.com\n"})
        self.press(self.alice, "delete")
        self.assertEqual(self.files(), {})


class SafetyTests(Base):
    def test_every_button_needs_the_csrf_token(self):
        for action in ("edit", "create", "delete"):
            with self.subTest(action=action):
                self.assertEqual(self.alice.post(f"/permissions/{action}").status_code, 400)
                self.assertEqual(self.alice.post(f"/permissions/{action}", data={"csrf": "guess"}).status_code, 400)
        self.assertEqual(self.files(), {"Text Test.txt": b"first line\n"})
        self.assertEqual(self.world.authz_writes, [])

    def test_another_users_token_does_not_work(self):
        bobs_token = csrf_from(self.bob.get("/permissions"))
        self.assertEqual(self.alice.post("/permissions/delete", data={"csrf": bobs_token}).status_code, 400)
        self.assertEqual(self.files(), {"Text Test.txt": b"first line\n"})

    def test_the_buttons_cannot_be_triggered_with_a_get(self):
        for action in ("edit", "create", "delete"):
            self.assertEqual(self.alice.get(f"/permissions/{action}").status_code, 405)
        self.assertEqual(self.files(), {"Text Test.txt": b"first line\n"})

    def test_a_user_who_has_not_connected_cannot_press_anything(self):
        stranger = as_user(self.stack.app.test_client(), CAROL, "carol@example.com")
        self.assertEqual(stranger.post("/permissions/delete").status_code, 400)       # no CSRF token yet
        token = csrf_from(self.alice.get("/permissions"))
        with stranger.session_transaction() as session:
            session["csrf"] = token
        self.assertEqual(stranger.post("/permissions/delete", data={"csrf": token}).status_code, 409)
        self.assertEqual(self.files(), {"Text Test.txt": b"first line\n"})

    def test_a_message_is_shown_once(self):
        self.press(self.alice, "edit")
        self.assertNotIn("Added the line", page_text(self.alice.get("/permissions")))

    def test_messages_are_escaped(self):
        markup = as_user(self.stack.app.test_client(), ALICE, "<b>x</b>")
        body = self.press(markup, "edit").get_data(as_text=True)
        self.assertNotIn("<b>x</b>", body)
        self.assertIn("&lt;b&gt;x&lt;/b&gt;", body)

    def test_the_fixed_path_is_never_taken_from_the_request(self):
        token = csrf_from(self.alice.get("/permissions"))
        self.alice.post("/permissions/delete?path=/Shared/Other&name=x", data={"csrf": token, "path": "/Shared/Other"})
        self.assertEqual(self.world.authz_writes, [("alice-access", "delete", "Text Test.txt")])


class ConfiguredFolderTests(unittest.TestCase):
    """The folder comes from the PERMISSION_TEST_FOLDER setting, not from the code."""

    OTHER = "/Shared/Other Team/My Test"

    def setUp(self):
        self.stack = build_stack(self, permission_folder=self.OTHER)
        self.world = self.stack.world
        self.world.authz_folder = self.OTHER          # the fake Egnyte has the folder where it is configured
        self.alice = as_user(self.stack.app.test_client(), ALICE, "alice@example.com")
        self.bob = as_user(self.stack.app.test_client(), BOB, "bob@example.com")
        for client, code in ((self.alice, "code-alice"), (self.bob, "code-bob")):
            self.assertEqual(connect_user(self, client, code).status_code, 302)

    def press(self, client, action):
        token = csrf_from(client.get("/permissions"))
        return client.post(f"/permissions/{action}", data={"csrf": token}, follow_redirects=True)

    def test_the_page_shows_and_reads_the_configured_folder(self):
        text = page_text(self.alice.get("/permissions"))
        self.assertIn(self.OTHER, text)
        self.assertNotIn(DEFAULT_PERMISSION_FOLDER, text)
        self.assertIn("first line", text)             # it found the file there, so it looked in the right place

    def test_the_buttons_act_in_the_configured_folder(self):
        self.press(self.alice, "edit")
        self.assertEqual(self.world.authz_files["Text Test.txt"], b"first line\nedited by alice@example.com\n")
        self.press(self.alice, "delete")
        self.assertEqual(self.world.authz_files, {})
        self.press(self.alice, "create")
        self.assertEqual(self.world.authz_files, {"Text Test.txt": b"created by alice@example.com\n"})

    def test_a_refusal_names_the_configured_folder(self):
        text = page_text(self.press(self.bob, "edit"))
        self.assertIn(f"Egnyte refused: the Egnyte account bob.eg is not allowed to edit files in {self.OTHER}.", text)
        self.assertNotIn(DEFAULT_PERMISSION_FOLDER, text)

    def test_nothing_is_done_in_the_default_folder_when_it_is_not_the_configured_one(self):
        # The fake only knows the configured folder: if the app used the default instead it would find no folder.
        self.world.authz_folder = DEFAULT_PERMISSION_FOLDER
        text = page_text(self.press(self.alice, "edit"))
        self.assertIn(f"The folder {self.OTHER} does not exist, or your Egnyte account can't see it.", text)
        self.assertEqual(self.world.authz_writes, [])


# ------------------------------------------------------------------------------------------------
# The same code over the REAL egnyte library, with only the HTTP layer faked. This is what catches a
# fake that has drifted from the library: URL encoding of the spaces, what a listing looks like, how an
# upload is sent, how a refusal (403) surfaces.

class FakeEgnyteHttp:
    """Stands in for requests.Session.request under the real library, for the permission-test folder."""

    def __init__(self, files, level="write"):
        self.files, self.level, self.requests = files, level, []

    @staticmethod
    def reply(status, body=b"", headers=None):
        response = requests.Response()
        response.status_code, response._content, response._content_consumed = status, body, True
        response.encoding = "utf-8"
        response.headers.update(headers or {})
        return response

    def __call__(self, method, url, **kwargs):
        path = unquote(urlsplit(url).path)
        self.requests.append((method, urlsplit(url).path))
        listing, content, entry = "/pubapi/v1/fs" + FOLDER, "/pubapi/v1/fs-content" + FOLDER + "/", "/pubapi/v1/fs" + FOLDER + "/"
        if self.level == "none":
            return self.reply(403, json.dumps({"errorMessage": "forbidden"}).encode())
        if method == "GET" and path == listing:
            files = [{"name": n, "path": f"{FOLDER}/{n}", "is_folder": False, "size": len(d),
                      "checksum": hashlib.sha512(d).hexdigest(), "last_modified": "Wed, 18 Nov 2026 01:00:00 GMT",
                      "uploaded_by": "someone.eg", "entry_id": "e", "num_versions": 1} for n, d in self.files.items()]
            body = {"name": FOLDER.rsplit("/", 1)[-1], "path": FOLDER, "is_folder": True, "folder_id": "f",
                    "folders": [], "files": files}
            return self.reply(200, json.dumps(body).encode(), {"content-type": "application/json"})
        if method == "GET" and path.startswith(content):
            name = path[len(content):]
            if name not in self.files:
                return self.reply(404, json.dumps({"errorMessage": "not found"}).encode())
            return self.reply(200, self.files[name], {"content-length": str(len(self.files[name]))})
        if method == "POST" and path.startswith(content):
            if self.level != "write":
                return self.reply(403, json.dumps({"errorMessage": "forbidden"}).encode())
            body = kwargs["data"].read()           # the library hashes the upload as it is read
            self.files[path[len(content):]] = body
            return self.reply(200, b"{}", {"X-Sha512-Checksum": hashlib.sha512(body).hexdigest()})
        if method == "DELETE" and path.startswith(entry):
            if self.level != "write":
                return self.reply(403, json.dumps({"errorMessage": "forbidden"}).encode())
            if self.files.pop(path[len(entry):], None) is None:
                return self.reply(404, json.dumps({"errorMessage": "not found"}).encode())
            return self.reply(200, b"{}")
        return self.reply(404, json.dumps({"errorMessage": f"unexpected {method} {path}"}).encode())


def real_client(http):
    client = EgnyteClient({"domain": "stout.egnyte.com", "access_token": "t"})
    client._session.request = http
    return client


class RealLibraryTests(unittest.TestCase):
    def setUp(self):
        self.files = {"Text Test.txt": b"first line\n"}
        self.http = FakeEgnyteHttp(self.files)
        self.client = real_client(self.http)

    def test_inspect_reads_the_listing_and_the_file(self):
        state = pc.inspect(self.client, FOLDER)
        self.assertEqual(state["folder_status"], "ok")
        self.assertEqual(state["file"], {"name": "Text Test.txt", "size": 11, "modified": "Wed, 18 Nov 2026 01:00:00 GMT",
                                         "modified_by": "someone.eg"})
        self.assertEqual(state["preview"], "first line\n")
        self.assertEqual(self.http.requests, [
            ("GET", "/pubapi/v1/fs" + ENCODED),
            ("GET", "/pubapi/v1/fs-content" + ENCODED + "/Text%20Test.txt")])

    def test_edit_downloads_then_uploads_the_whole_file_to_the_same_path(self):
        self.assertEqual(pc.edit(self.client, FOLDER, "alice@example.com"), "Text Test.txt")
        self.assertEqual(self.files["Text Test.txt"], b"first line\nedited by alice@example.com\n")
        self.assertEqual(self.http.requests[-1], ("POST", "/pubapi/v1/fs-content" + ENCODED + "/Text%20Test.txt"))

    def test_create_posts_a_new_file(self):
        self.files.clear()
        self.assertEqual(pc.create(self.client, FOLDER, "alice@example.com"), "Text Test.txt")
        self.assertEqual(self.files, {"Text Test.txt": b"created by alice@example.com\n"})
        self.assertEqual(self.http.requests[-1], ("POST", "/pubapi/v1/fs-content" + ENCODED + "/Text%20Test.txt"))

    def test_delete_sends_a_delete(self):
        self.assertEqual(pc.delete(self.client, FOLDER), "Text Test.txt")
        self.assertEqual(self.files, {})
        self.assertEqual(self.http.requests[-1], ("DELETE", "/pubapi/v1/fs" + ENCODED + "/Text%20Test.txt"))

    def test_a_read_only_user_gets_a_403_that_surfaces_as_insufficient_permissions(self):
        self.http.level = "read"
        with self.assertRaises(exc.InsufficientPermissions):
            pc.edit(self.client, FOLDER, "bob@example.com")
        with self.assertRaises(exc.InsufficientPermissions):
            pc.delete(self.client, FOLDER)
        self.assertEqual(self.files, {"Text Test.txt": b"first line\n"})

    def test_a_user_with_no_access_is_denied_the_listing(self):
        self.http.level = "none"
        self.assertEqual(pc.inspect(self.client, FOLDER)["folder_status"], "denied")
        with self.assertRaises(exc.InsufficientPermissions):
            pc.create(self.client, FOLDER, "carol@example.com")

    def test_the_whole_web_flow_over_the_real_library(self):
        # Alice may write, Bob may only read; both go through the real client and the real error mapping.
        levels = {"alice-access": "write", "bob-access": "read"}
        shared = {"Text Test.txt": b"first line\n"}

        def factory(settings, access_token, limiter):
            client = EgnyteClient({"domain": settings.domain, "access_token": access_token})
            client._session.request = FakeEgnyteHttp(shared, levels[access_token])
            return client

        stack = build_stack(self, client_factory=factory)
        alice = as_user(stack.app.test_client(), ALICE, "alice@example.com")
        bob = as_user(stack.app.test_client(), BOB, "bob@example.com")
        for client, code in ((alice, "code-alice"), (bob, "code-bob")):
            self.assertEqual(connect_user(self, client, code).status_code, 302)

        def press(client, action):
            token = csrf_from(client.get("/permissions"))
            return page_text(client.post(f"/permissions/{action}", data={"csrf": token}, follow_redirects=True))

        self.assertIn("first line", page_text(bob.get("/permissions")))
        self.assertIn("Added the line", press(alice, "edit"))
        self.assertIn("Egnyte refused: the Egnyte account bob.eg is not allowed to edit files", press(bob, "edit"))
        self.assertIn("Egnyte refused: the Egnyte account bob.eg is not allowed to delete files", press(bob, "delete"))
        self.assertEqual(shared["Text Test.txt"], b"first line\nedited by alice@example.com\n")
        self.assertIn("Deleted Text Test.txt", press(alice, "delete"))
        self.assertEqual(shared, {})
        self.assertIn("Created Text Test.txt", press(alice, "create"))
        self.assertEqual(shared, {"Text Test.txt": b"created by alice@example.com\n"})


if __name__ == "__main__":
    unittest.main()
