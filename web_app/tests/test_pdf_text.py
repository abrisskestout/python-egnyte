"""The "Show text layer" button of the permission test section: the text already inside a PDF in the test folder."""
import re
import unittest
from unittest import mock
from urllib.parse import quote

import permission_check as pc
from egnyte.client import EgnyteClient
from helpers import ALICE, BOB, as_user, build_stack, connect_user, page_text
from pdfs import blank_pdf, locked_pdf, restricted_pdf, text_pdf
from test_permissions import CAROL, ENCODED, FOLDER, Base, FakeEgnyteHttp, real_client


class ExtractTests(unittest.TestCase):
    """permission_check.extract_pdf_text on real (tiny) PDFs."""

    def test_each_page_is_a_block_in_order(self):
        result = pc.extract_pdf_text(text_pdf("First page text", "Second page text"))
        self.assertEqual(result["text"], "--- Page 1 ---\nFirst page text\n\n--- Page 2 ---\nSecond page text")
        self.assertEqual((result["pages"], result["pages_read"], result["pages_with_text"]), (2, 2, 2))
        self.assertEqual(result["notes"], [])

    def test_parentheses_survive(self):
        self.assertIn("Hello (world)", pc.extract_pdf_text(text_pdf("Hello (world)"))["text"])

    def test_a_scan_has_no_text_layer_and_the_result_says_so(self):
        result = pc.extract_pdf_text(blank_pdf(2))
        self.assertEqual((result["pages"], result["pages_with_text"]), (2, 0))
        self.assertEqual(len(result["notes"]), 1)
        self.assertIn("No text layer was found", result["notes"][0])
        self.assertIn("needs OCR", result["notes"][0])

    def test_a_document_that_is_partly_scanned_says_how_many_pages_have_no_text(self):
        result = pc.extract_pdf_text(text_pdf("Has text", ""))
        self.assertEqual((result["pages_read"], result["pages_with_text"]), (2, 1))
        self.assertEqual(result["notes"], ["1 of the 2 pages read have no text layer (probably scans)."])

    def test_only_the_first_pages_are_read(self):
        pages = [f"page number {n}" for n in range(1, pc.MAX_PDF_PAGES + 6)]
        result = pc.extract_pdf_text(text_pdf(*pages))
        self.assertEqual((result["pages"], result["pages_read"]), (pc.MAX_PDF_PAGES + 5, pc.MAX_PDF_PAGES))
        self.assertIn(f"page number {pc.MAX_PDF_PAGES}", result["text"])
        self.assertNotIn(f"page number {pc.MAX_PDF_PAGES + 1}", result["text"])
        self.assertEqual(result["notes"], [f"Only the first {pc.MAX_PDF_PAGES} of {pc.MAX_PDF_PAGES + 5} pages were read."])

    def test_long_text_is_cut_off_at_the_limit_and_says_so(self):
        with mock.patch.object(pc, "MAX_PDF_TEXT_CHARS", 100):
            result = pc.extract_pdf_text(text_pdf(*[f"line {n} " + "x" * 30 for n in range(10)]))
        self.assertLessEqual(len(result["text"]), 100)
        self.assertLess(result["pages_read"], 10)                    # it stops reading once there is enough
        self.assertTrue(any("cut off after 100 characters" in note for note in result["notes"]), result["notes"])

    def test_a_password_protected_pdf_is_refused(self):
        with self.assertRaises(pc.ActionRefused) as caught:
            pc.extract_pdf_text(locked_pdf("secret text"))
        self.assertIn("password-protected", str(caught.exception))
        self.assertNotIn("secret text", str(caught.exception))

    def test_a_pdf_that_only_restricts_editing_can_be_read(self):
        self.assertIn("Owner only", pc.extract_pdf_text(restricted_pdf("Owner only"))["text"])

    def test_damaged_files_are_refused_not_crashes(self):
        good = text_pdf("some text")
        damaged = {"empty": b"", "not a pdf": b"this is not a pdf at all", "header only": b"%PDF-1.4\n",
                   "random bytes": bytes(range(256)) * 20, "cut short": good[:60]}
        for label, data in damaged.items():
            with self.subTest(label), self.assertLogs("egnyte.permissions", "WARNING") as logs:
                with self.assertRaises(pc.ActionRefused) as caught:
                    pc.extract_pdf_text(data)
            self.assertIn("could not be read as a PDF", str(caught.exception))
            self.assertNotIn("some text", "\n".join(logs.output))     # the log names the error type, never the content

    def test_control_characters_are_removed_but_tabs_and_newlines_stay(self):
        self.assertEqual(pc._clean("a\x00b\x07c\r\nd\re\tf\x7fg"), "abc\nd\ne\tfg")


class PdfButtonTests(Base):
    def setUp(self):
        super().setUp()
        self.world.authz_files["Report.pdf"] = text_pdf("Quarterly report text")
        self.world.authz_files["Scan.PDF"] = blank_pdf(1)

    def show(self, client, name, **kwargs):
        return client.get("/permissions/pdf", query_string={"name": name}, **kwargs)

    def read_calls(self):
        """Patch the downloader so a test can see whether any file was fetched."""
        spy = mock.patch.object(pc, "read_all", wraps=pc.read_all)
        started = spy.start()
        self.addCleanup(spy.stop)
        return started

    # ---------------------------------------------------------------- the page

    def test_every_pdf_gets_its_own_button_and_other_files_do_not(self):
        html = self.alice.get("/permissions").get_data(as_text=True)
        self.assertEqual(html.count('action="/permissions/pdf"'), 2)
        self.assertIn('name="name" value="Report.pdf"', html)
        self.assertIn('name="name" value="Scan.PDF"', html)          # any capitals
        self.assertNotIn('value="Text Test.txt"', html)
        self.assertIn("Show text layer", page_text(self.alice.get("/permissions")))

    def test_the_buttons_only_read_so_they_are_get_forms(self):
        html = self.alice.get("/permissions").get_data(as_text=True)
        forms = re.findall(r'<form[^>]*action="/permissions/pdf"[^>]*>', html)
        self.assertEqual(len(forms), 2)
        for form in forms:
            self.assertIn('method="get"', form)

    def test_with_no_pdf_in_the_folder_the_page_says_so(self):
        del self.world.authz_files["Report.pdf"], self.world.authz_files["Scan.PDF"]
        html = self.alice.get("/permissions").get_data(as_text=True)
        self.assertIn("There is no PDF in the folder", page_text(self.alice.get("/permissions")))
        self.assertNotIn('action="/permissions/pdf"', html)

    def test_no_pdf_section_when_the_folder_cannot_be_opened(self):
        self.world.authz_levels["bob-access"] = "none"
        self.assertNotIn("PDF text layer", page_text(self.bob.get("/permissions")))

    def test_only_the_first_pdfs_are_listed_and_the_rest_are_counted(self):
        for n in range(pc.MAX_PDF_BUTTONS + 3):
            self.world.authz_files[f"extra {n:02d}.pdf"] = b"%PDF"
        html = self.alice.get("/permissions").get_data(as_text=True)
        self.assertEqual(html.count('action="/permissions/pdf"'), pc.MAX_PDF_BUTTONS)
        self.assertIn("5 more PDFs in the folder not listed", page_text(self.alice.get("/permissions")))

    # ---------------------------------------------------------------- showing the text

    def test_pressing_the_button_shows_the_text_layer(self):
        response = self.show(self.alice, "Report.pdf")
        self.assertEqual(response.status_code, 200)
        text = page_text(response)
        self.assertIn("Quarterly report text", text)
        self.assertIn("--- Page 1 ---", text)
        self.assertIn("Report.pdf", text)
        self.assertIn("alice.eg", text)                    # whose token read it
        self.assertIn("no OCR was run", text)
        self.assertIn("1 page;", text)
        self.assertIn('href="/permissions"', response.get_data(as_text=True))

    def test_a_scan_shows_no_text_and_explains_why(self):
        response = self.show(self.alice, "Scan.PDF")
        self.assertEqual(response.status_code, 200)
        self.assertIn("No text layer was found", page_text(response))
        self.assertNotIn('class="preview pdf-text"', response.get_data(as_text=True))

    def test_a_read_only_user_can_read_it_too_with_their_own_token(self):
        before = len(self.world.tokens_used())
        self.assertIn("Quarterly report text", page_text(self.show(self.bob, "Report.pdf")))
        self.assertEqual(set(self.world.tokens_used()[before:]), {"bob-access"})

    def test_text_from_the_pdf_is_escaped(self):
        self.world.authz_files["Evil.pdf"] = text_pdf("<script>alert(1)</script> & <b>bold</b>")
        html = self.show(self.alice, "Evil.pdf").get_data(as_text=True)
        self.assertIn("&lt;script&gt;alert(1)&lt;/script&gt;", html)
        self.assertNotIn("<script>alert", html)
        self.assertNotIn("<b>bold</b>", html)

    def test_reading_changes_nothing_in_egnyte(self):
        before = self.files()
        self.show(self.alice, "Report.pdf")
        self.show(self.alice, "Scan.PDF")
        self.assertEqual(self.files(), before)
        self.assertEqual(self.world.authz_writes, [])

    def test_tokens_never_appear(self):
        for client in (self.alice, self.bob):
            body = page_text(self.show(client, "Report.pdf"))
            for needle in ("alice-access", "bob-access", "alice-refresh", "bob-refresh"):
                self.assertNotIn(needle, body)

    # ---------------------------------------------------------------- who may use it, and what it refuses

    def test_it_needs_sign_in_and_a_connected_account(self):
        self.assertEqual(self.show(self.anon, "Report.pdf").status_code, 401)
        stranger = as_user(self.stack.app.test_client(), CAROL, "carol@example.com")
        response = self.show(stranger, "Report.pdf")
        self.assertEqual(response.status_code, 409)
        self.assertIn("/egnyte/connect", response.get_data(as_text=True))

    def test_egnyte_refusing_the_user_is_shown(self):
        self.world.authz_levels["bob-access"] = "none"
        text = page_text(self.show(self.bob, "Report.pdf", follow_redirects=True))
        self.assertIn("Egnyte refused: the Egnyte account bob.eg is not allowed to read that PDF", text)

    def test_a_file_the_user_can_list_but_not_read_is_shown_as_refused(self):
        client_class = type(self.world.factory(None, "bob-access", None))
        patched = client_class._authz_file

        def unreadable(self_, path):
            file = patched(self_, path)
            file.download = lambda: (_ for _ in ()).throw(pc.exc.InsufficientPermissions("no"))
            return file
        client_class._authz_file = unreadable
        self.addCleanup(setattr, client_class, "_authz_file", patched)
        text = page_text(self.show(self.bob, "Report.pdf", follow_redirects=True))
        self.assertIn("not allowed to read that PDF", text)

    def test_names_that_are_not_pdfs_in_the_folder_are_refused_and_nothing_is_downloaded(self):
        reads = self.read_calls()
        for name in ("nope.pdf", "../Report.pdf", "/Shared/Report.pdf", "Text Test.txt", "", "report.pdf",
                     "Report.pdf\x00", "Report.pdf ", "x" * 5000):
            with self.subTest(name=name[:30]):
                reads.reset_mock()
                refused = self.show(self.alice, name)            # not followed: the redirect target reads Text Test.txt
                self.assertEqual((refused.status_code, refused.headers["Location"]), (302, "/permissions"))
                reads.assert_not_called()                        # nothing was downloaded for the refused request
                text = page_text(self.alice.get("/permissions"))     # the notice is shown on the page it goes back to
                self.assertIn("That PDF is not in the folder", text)
                if name.strip() and name not in self.world.authz_files:
                    self.assertNotIn(name, text)             # a name that isn't in the folder is never echoed

    def test_a_missing_name_parameter_is_just_refused(self):
        response = self.alice.get("/permissions/pdf", follow_redirects=True)
        self.assertIn("That PDF is not in the folder", page_text(response))

    def test_a_pdf_removed_after_the_page_loaded_is_explained(self):
        del self.world.authz_files["Report.pdf"]
        self.assertIn("not in the folder", page_text(self.show(self.alice, "Report.pdf", follow_redirects=True)))

    def test_a_pdf_that_is_too_large_is_not_downloaded(self):
        reads = self.read_calls()
        self.world.authz_files["Big.pdf"] = b"%PDF" + b"x" * pc.MAX_PDF_BYTES
        refused = self.show(self.alice, "Big.pdf")
        self.assertEqual(refused.status_code, 302)
        reads.assert_not_called()
        self.assertIn("Big.pdf is too large to read here (the limit is 10 MB)", page_text(self.alice.get("/permissions")))

    def test_a_damaged_pdf_gets_a_notice_not_an_error_page(self):
        self.world.authz_files["Broken.pdf"] = b"definitely not a pdf"
        with self.assertLogs("egnyte.permissions", "WARNING"):
            response = self.show(self.alice, "Broken.pdf", follow_redirects=True)
        self.assertEqual(response.status_code, 200)
        text = page_text(response)
        self.assertIn("could not be read as a PDF", text)
        self.assertNotIn("Traceback", text)

    def test_a_password_protected_pdf_gets_a_notice(self):
        self.world.authz_files["Locked.pdf"] = locked_pdf("hidden words")
        text = page_text(self.show(self.alice, "Locked.pdf", follow_redirects=True))
        self.assertIn("password-protected", text)
        self.assertNotIn("hidden words", text)


# The same flow over the REAL egnyte library, with only the HTTP layer faked (see test_permissions.RealLibraryTests):
# real URL encoding for a name with spaces and accents, and a real binary download.

class RealLibraryPdfTests(unittest.TestCase):
    NAME = "Q3 Report é.pdf"

    def setUp(self):
        self.files = {"Text Test.txt": b"first line\n", self.NAME: text_pdf("Revenue grew (a lot)"), "Scan.pdf": blank_pdf(1)}
        self.http = FakeEgnyteHttp(self.files)
        self.client = real_client(self.http)

    def test_the_listing_finds_the_pdfs(self):
        state = pc.inspect(self.client, FOLDER)
        self.assertEqual([pdf["name"] for pdf in state["pdfs"]], [self.NAME, "Scan.pdf"])
        self.assertEqual(state["pdfs"][0]["size"], len(self.files[self.NAME]))

    def test_the_pdf_is_downloaded_once_by_the_path_egnyte_listed_and_read(self):
        result = pc.pdf_text(self.client, FOLDER, self.NAME)
        self.assertIn("Revenue grew (a lot)", result["text"])
        self.assertEqual(result["size"], len(self.files[self.NAME]))
        downloads = [request for request in self.http.requests if request[1].startswith("/pubapi/v1/fs-content")]
        self.assertEqual(downloads, [("GET", f"/pubapi/v1/fs-content{ENCODED}/{quote(self.NAME)}")])

    def test_a_user_with_no_access_is_refused_by_egnyte(self):
        self.http.level = "none"
        with self.assertRaises(pc.exc.InsufficientPermissions):
            pc.pdf_text(self.client, FOLDER, self.NAME)

    def test_the_whole_web_flow(self):
        levels = {"alice-access": "write", "bob-access": "read"}

        def factory(settings, access_token, limiter):
            client = EgnyteClient({"domain": settings.domain, "access_token": access_token})
            client._session.request = FakeEgnyteHttp(self.files, levels[access_token])
            return client

        stack = build_stack(self, client_factory=factory)
        alice = as_user(stack.app.test_client(), ALICE, "alice@example.com")
        bob = as_user(stack.app.test_client(), BOB, "bob@example.com")
        for client, code in ((alice, "code-alice"), (bob, "code-bob")):
            self.assertEqual(connect_user(self, client, code).status_code, 302)
        for client in (alice, bob):                      # a read-only account reads it too
            text = page_text(client.get("/permissions/pdf", query_string={"name": self.NAME}))
            self.assertIn("Revenue grew (a lot)", text)
        self.assertIn(self.NAME, page_text(bob.get("/permissions")))
        levels["bob-access"] = "none"
        denied = page_text(bob.get("/permissions/pdf", query_string={"name": self.NAME}, follow_redirects=True))
        self.assertIn("Egnyte refused: the Egnyte account bob.eg is not allowed to read that PDF", denied)


if __name__ == "__main__":
    unittest.main()
