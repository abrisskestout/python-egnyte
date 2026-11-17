import unittest
import urllib.parse
from types import SimpleNamespace
from unittest import mock

import requests

import egnyte_oauth as eo
from helpers import SECRET


def response(status=200, payload=None, json_error=False):
    def fail():
        raise ValueError("not json")
    return SimpleNamespace(status_code=status, json=fail if json_error else (lambda: payload))


TOKEN_PAYLOAD = {"access_token": "ACCESS", "token_type": "bearer", "expires_in": 2591999, "refresh_token": "REFRESH"}


class InputTests(unittest.TestCase):
    def test_domain_normalisation(self):
        self.assertEqual(eo.normalize_domain("Stout"), "stout.egnyte.com")
        self.assertEqual(eo.normalize_domain("stout.egnyte.com"), "stout.egnyte.com")
        for bad in ("", "a b", "https://x.egnyte.com", "x.egnyte.com:8443", "x/y", "x@y", "-x", "x..com", "ü"):
            with self.subTest(bad=bad), self.assertRaises(ValueError):
                eo.normalize_domain(bad)

    def test_redirect_uri_rules(self):
        self.assertEqual(eo.validate_redirect_uri("https://a.example/cb"), "https://a.example/cb")
        self.assertEqual(eo.validate_redirect_uri("http://localhost:5000/cb", allow_loopback_http=True),
                         "http://localhost:5000/cb")
        for bad in ("http://a.example/cb", "http://localhost/cb", "https://u:p@a.example/cb", "https://a.example/cb#x",
                    "https://a.example/cb?x=1", "ftp://a.example", "https:///cb", "https://a.example:99999/cb"):
            with self.subTest(bad=bad), self.assertRaises(ValueError):
                eo.validate_redirect_uri(bad)

    def test_scope_rules(self):
        self.assertEqual(eo.resolve_scope(None), "Egnyte.filesystem")
        self.assertEqual(eo.resolve_scope("Egnyte.filesystem Egnyte.filesystem"), "Egnyte.filesystem")
        with self.assertRaises(ValueError):
            eo.resolve_scope("Egnyte.filesystem Egnyte.bogus")


class UrlAndCallbackTests(unittest.TestCase):
    def test_authorize_url(self):
        url = eo.build_auth_url("stout.egnyte.com", "CLIENT123", "https://a.example/cb", "Egnyte.filesystem", "STATE1")
        parts = urllib.parse.urlsplit(url)
        self.assertEqual((parts.scheme, parts.netloc, parts.path), ("https", "stout.egnyte.com", "/puboauth/token"))
        self.assertEqual(urllib.parse.parse_qs(parts.query), {
            "client_id": ["CLIENT123"], "redirect_uri": ["https://a.example/cb"], "scope": ["Egnyte.filesystem"],
            "state": ["STATE1"], "response_type": ["code"]})

    def test_states_are_random(self):
        self.assertNotEqual(eo.new_state(), eo.new_state())
        self.assertGreaterEqual(len(eo.new_state()), 40)

    def test_callback_shapes(self):
        ok, problem = eo.parse_callback("code=abc&state=s1")
        self.assertEqual((ok, problem), ({"state": "s1", "code": "abc"}, None))
        self.assertEqual(eo.parse_callback("error=access_denied&state=s1&error_description=no")[0],
                         {"state": "s1", "error": "access_denied", "error_description": "no"})
        bad = ["", "code=abc", "state=s1", "code=abc&error=x&state=s1", "code=a&code=b&state=s1", "code=abc&state=s&state=t",
               "code=&state=s1", "code=" + "a" * 2049 + "&state=s1", "code=abc&state=" + "s" * 257]
        for query in bad:
            with self.subTest(query=query[:40]):
                self.assertIsNone(eo.parse_callback(query)[0])

    def test_error_text_is_sanitised(self):
        text = eo.callback_error_text({"error": "<script>", "error_description": "bad\x00\nthing"})
        self.assertIn("unrecognized_error", text)
        self.assertNotIn("<script>", text)
        self.assertNotIn("\x00", text)


class TokenExchangeTests(unittest.TestCase):
    def exchange(self, reply, **kwargs):
        with mock.patch.object(eo.requests, "post", return_value=reply) as post:
            result = eo.exchange_code("stout.egnyte.com", "CLIENT123", SECRET, "https://a.example/cb", "THECODE", **kwargs)
        return result, post

    def test_request_and_result(self):
        tokens, post = self.exchange(response(200, TOKEN_PAYLOAD), now=1000.0)
        (url,), kwargs = post.call_args
        self.assertEqual(url, "https://stout.egnyte.com/puboauth/token")
        self.assertEqual(kwargs["data"], {"client_id": "CLIENT123", "client_secret": SECRET, "redirect_uri": "https://a.example/cb",
                                          "code": "THECODE", "grant_type": "authorization_code"})
        self.assertIs(kwargs["allow_redirects"], False)
        self.assertIs(kwargs["verify"], True)
        self.assertEqual(kwargs["timeout"], eo.REQUEST_TIMEOUT)
        self.assertEqual((tokens.access_token, tokens.refresh_token, tokens.expires_at), ("ACCESS", "REFRESH", 1000.0 + 2591999))

    def test_tokens_stay_out_of_repr(self):
        tokens, _ = self.exchange(response(200, TOKEN_PAYLOAD))
        self.assertNotIn("ACCESS", repr(tokens))
        self.assertNotIn("REFRESH", repr(tokens))

    def test_missing_refresh_token_and_lifetime_are_tolerated(self):
        tokens, _ = self.exchange(response(200, {"access_token": "A"}))
        self.assertEqual((tokens.refresh_token, tokens.expires_at), (None, None))
        for lifetime in (-5, 0, "soon", True):
            with self.subTest(lifetime=lifetime):
                tokens, _ = self.exchange(response(200, {"access_token": "A", "expires_in": lifetime}))
                self.assertIsNone(tokens.expires_at)

    def test_unusable_access_tokens_are_refused(self):
        for payload in ({}, {"access_token": ""}, {"access_token": 5}, {"access_token": "x" * 5000}):
            with self.subTest(payload=str(payload)[:30]), self.assertRaises(eo.OAuthError):
                self.exchange(response(200, payload))

    def test_errors_carry_only_the_status_and_a_known_error_code(self):
        with self.assertRaises(eo.OAuthError) as caught:
            self.exchange(response(400, {"error": "invalid_grant", "error_description": "BODYTEXT" + SECRET}))
        message = str(caught.exception)
        self.assertEqual((message, caught.exception.status), ("Token request failed: HTTP 400 (invalid_grant)", 400))
        with self.assertRaises(eo.OAuthError) as caught:
            self.exchange(response(500, {"error": "made-up<script>"}))
        self.assertEqual(str(caught.exception), "Token request failed: HTTP 500")

    def test_redirects_html_and_non_objects_are_refused(self):
        for reply, text in ((response(302, {}), "redirect"), (response(200, json_error=True), "not valid JSON"),
                            (response(200, [1, 2]), "unexpected response")):
            with self.subTest(text=text), self.assertRaises(eo.OAuthError) as caught:
                self.exchange(reply)
            self.assertIn(text, str(caught.exception))

    def test_network_errors_show_only_the_type(self):
        with mock.patch.object(eo.requests, "post", side_effect=requests.ConnectionError("https://secret-url SECRET")):
            with self.assertRaises(eo.OAuthError) as caught:
                eo.exchange_code("stout.egnyte.com", "C", SECRET, "https://a.example/cb", "code")
        self.assertIn("ConnectionError", str(caught.exception))
        self.assertNotIn("secret-url", str(caught.exception))


class RefreshTests(unittest.TestCase):
    def refresh(self, payload, now=2000.0):
        with mock.patch.object(eo.requests, "post", return_value=response(200, payload)) as post:
            tokens = eo.refresh_access_token("stout.egnyte.com", "CLIENT123", SECRET, "OLD-REFRESH", now=now)
        return tokens, post

    def test_request_shape(self):
        _, post = self.refresh(TOKEN_PAYLOAD)
        self.assertEqual(post.call_args.kwargs["data"], {"client_id": "CLIENT123", "client_secret": SECRET,
                                                         "refresh_token": "OLD-REFRESH", "grant_type": "refresh_token"})
        self.assertIs(post.call_args.kwargs["allow_redirects"], False)

    def test_a_new_refresh_token_replaces_the_old_one(self):
        tokens, _ = self.refresh(TOKEN_PAYLOAD)
        self.assertEqual((tokens.access_token, tokens.refresh_token), ("ACCESS", "REFRESH"))

    def test_the_old_refresh_token_is_kept_when_none_comes_back(self):
        tokens, _ = self.refresh({"access_token": "NEW", "expires_in": 100})
        self.assertEqual((tokens.refresh_token, tokens.expires_at), ("OLD-REFRESH", 2100.0))


class UserInfoTests(unittest.TestCase):
    def fetch(self, reply):
        with mock.patch.object(eo.requests, "get", return_value=reply) as get:
            return eo.fetch_userinfo("stout.egnyte.com", "TOKEN"), get

    def test_sends_the_bearer_token_and_returns_safe_text(self):
        info, get = self.fetch(response(200, {"username": "alice\x00.eg", "email": "a@x.com", "other": "ignored"}))
        self.assertEqual(get.call_args.kwargs["headers"], {"Authorization": "Bearer TOKEN"})
        self.assertIs(get.call_args.kwargs["allow_redirects"], False)
        self.assertEqual(info, {"username": "alice.eg", "email": "a@x.com"})

    def test_email_is_optional_and_username_defaults(self):
        info, _ = self.fetch(response(200, {}))
        self.assertEqual(info, {"username": "unknown"})

    def test_401_means_the_token_is_invalid(self):
        with self.assertRaises(eo.InvalidToken):
            self.fetch(response(401, {"errorMessage": "Invalid access token"}))

    def test_other_failures_are_plain_oauth_errors(self):
        with self.assertRaises(eo.OAuthError) as caught:
            self.fetch(response(503, {}))
        self.assertNotIsInstance(caught.exception, eo.InvalidToken)


if __name__ == "__main__":
    unittest.main()
