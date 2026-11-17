import base64
import json
import os
import threading
import unittest
from types import SimpleNamespace

from cryptography.fernet import Fernet

import identity
from helpers import ALICE, BOB, KEY, TENANT, make_settings, principal
from token_store import FileTokenStore, PendingStates, TokenRecord


class PrincipalTests(unittest.TestCase):
    def test_reads_tenant_object_id_and_name(self):
        user = identity.parse_principal(principal(ALICE.upper(), "alice@example.com", tenant=TENANT.upper()))
        self.assertEqual(user.key, f"{TENANT}:{ALICE}")           # lowercased, so one person has one key
        self.assertEqual(user.name, "alice@example.com")

    def test_short_claim_names_work_too(self):
        value = principal(ALICE, "a", claim_types={"tenant": "tid", "oid": "oid"})
        self.assertEqual(identity.parse_principal(value).object_id, ALICE)

    def test_unusable_headers_give_no_user(self):
        def encode(obj):
            return base64.b64encode(json.dumps(obj).encode()).decode()
        no_oid = encode({"claims": [{"typ": "tid", "val": TENANT}]})
        bad = ["", None, "not base64!!", base64.b64encode(b"not json").decode(), encode([1, 2]), encode({"claims": "x"}),
               no_oid, principal("../../etc/passwd", "x"), principal(ALICE, "x", tenant="nope"), "A" * 20000]
        for value in bad:
            with self.subTest(value=str(value)[:30]):
                self.assertIsNone(identity.parse_principal(value))

    def test_display_name_is_cleaned_but_never_used_as_the_key(self):
        user = identity.parse_principal(principal(ALICE, "bad\x00name\n" + "x" * 500))
        self.assertNotIn("\x00", user.name)
        self.assertNotIn("\n", user.name)
        self.assertLessEqual(len(user.name), 140)
        self.assertNotIn("bad", user.key)


class CurrentUserTests(unittest.TestCase):
    def setUp(self):
        self.closed = make_settings("x")
        self.dev = make_settings("x", allow_dev_user=True)

    def test_header_identifies_the_user(self):
        user = identity.current_user({identity.PRINCIPAL_HEADER: principal(ALICE, "a")}, {}, self.closed)
        self.assertEqual(user.object_id, ALICE)

    def test_dev_cookie_is_ignored_unless_dev_mode_is_on(self):
        self.assertIsNone(identity.current_user({}, {identity.DEV_COOKIE: "alice"}, self.closed))
        self.assertEqual(identity.current_user({}, {identity.DEV_COOKIE: "alice"}, self.dev).name, "alice (dev)")

    def test_dev_users_are_stable_and_distinct(self):
        a1, a2, b = identity.dev_user("alice"), identity.dev_user("alice"), identity.dev_user("bob")
        self.assertEqual(a1.key, a2.key)
        self.assertNotEqual(a1.key, b.key)

    def test_bad_dev_names_are_refused(self):
        for name in ("", "A", "has space", "x" * 33, "../x", None):
            with self.subTest(name=name):
                self.assertIsNone(identity.dev_user(name))

    def test_a_real_header_beats_the_dev_cookie(self):
        user = identity.current_user({identity.PRINCIPAL_HEADER: principal(BOB, "b")}, {identity.DEV_COOKIE: "alice"}, self.dev)
        self.assertEqual(user.object_id, BOB)


def record(access="access-1", refresh="refresh-1", name="alice.eg"):
    return TokenRecord(access, refresh, 5_000_000_000.0, name, 1_700_000_000.0)


class TokenStoreTests(unittest.TestCase):
    def setUp(self):
        import tempfile
        folder = tempfile.TemporaryDirectory()
        self.addCleanup(folder.cleanup)
        self.dir = folder.name
        self.store = FileTokenStore(self.dir, [KEY])

    def files(self):
        return [name for name in os.listdir(self.dir)]

    def test_round_trip(self):
        self.store.save("u1", record())
        self.assertEqual(self.store.load("u1"), record())

    def test_nothing_readable_is_on_disk(self):
        self.store.save(f"{TENANT}:{ALICE}", record(access="PLAINTEXT-ACCESS", refresh="PLAINTEXT-REFRESH"))
        for name in self.files():
            with open(os.path.join(self.dir, name), "rb") as fp:
                data = fp.read()
            for needle in (b"PLAINTEXT-ACCESS", b"PLAINTEXT-REFRESH", b"alice.eg", ALICE.encode()):
                self.assertNotIn(needle, data)
            self.assertNotIn(ALICE, name)

    def test_users_are_kept_apart(self):
        self.store.save("alice", record(access="A"))
        self.store.save("bob", record(access="B"))
        self.assertEqual(self.store.load("alice").access_token, "A")
        self.assertEqual(self.store.load("bob").access_token, "B")
        self.store.delete("alice")
        self.assertIsNone(self.store.load("alice"))
        self.assertEqual(self.store.load("bob").access_token, "B")

    def test_missing_and_double_delete_are_fine(self):
        self.assertIsNone(self.store.load("nobody"))
        self.store.delete("nobody")

    def test_save_leaves_no_temp_files_and_overwrites(self):
        self.store.save("u", record(access="one"))
        self.store.save("u", record(access="two"))
        self.assertEqual(self.store.load("u").access_token, "two")
        self.assertEqual(len(self.files()), 1)
        self.assertTrue(self.files()[0].endswith(".tok"))

    def test_wrong_key_reads_as_not_connected(self):
        self.store.save("u", record())
        other = FileTokenStore(self.dir, [Fernet.generate_key().decode()])
        with self.assertLogs("egnyte.tokenstore", "WARNING"):
            self.assertIsNone(other.load("u"))

    def test_key_rotation_reads_old_data_and_writes_with_the_new_key(self):
        self.store.save("u", record(access="old"))
        new_key = Fernet.generate_key().decode()
        rotated = FileTokenStore(self.dir, [new_key, KEY])
        self.assertEqual(rotated.load("u").access_token, "old")
        rotated.save("u", record(access="new"))
        self.assertEqual(FileTokenStore(self.dir, [new_key]).load("u").access_token, "new")

    def test_corrupt_files_read_as_not_connected(self):
        self.store.save("u", record())
        path = os.path.join(self.dir, self.files()[0])
        with open(path, "wb") as fp:
            fp.write(b"garbage")
        with self.assertLogs("egnyte.tokenstore", "WARNING"):
            self.assertIsNone(self.store.load("u"))

    def test_malformed_keys_and_no_keys_are_refused(self):
        with self.assertRaises(ValueError):
            FileTokenStore(self.dir, ["not-a-fernet-key"])
        with self.assertRaises(ValueError):
            FileTokenStore(self.dir, [])

    def test_one_lock_per_user(self):
        self.assertIs(self.store.lock_for("a"), self.store.lock_for("a"))
        self.assertIsNot(self.store.lock_for("a"), self.store.lock_for("b"))

    def test_concurrent_saves_and_loads_never_fail_or_tear_the_file(self):
        errors = []

        def writer(n):
            try:
                for i in range(20):
                    self.store.save("u", record(access=f"token-{n}-{i}"))
                    self.assertTrue(self.store.load("u").access_token.startswith("token-"))
            except BaseException as e:  # a failure in a thread must fail the test, not just print
                errors.append(e)
        threads = [threading.Thread(target=writer, args=(n,)) for n in range(4)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        self.assertEqual(errors, [])
        self.assertEqual(len(self.files()), 1)

    def test_the_lock_can_be_held_while_saving(self):
        # A refresh holds the user's lock and then saves; that must not deadlock.
        with self.store.lock_for("u"):
            self.store.save("u", record())
            self.assertIsNotNone(self.store.load("u"))


class PendingStatesTests(unittest.TestCase):
    def setUp(self):
        self.clock = SimpleNamespace(now=100.0)
        self.pending = PendingStates(ttl=600, max_entries=3, clock=lambda: self.clock.now)

    def test_a_state_works_once(self):
        state = self.pending.create("alice")
        self.assertTrue(self.pending.consume(state, "alice"))
        self.assertFalse(self.pending.consume(state, "alice"))

    def test_only_the_user_who_started_it_can_finish_it(self):
        state = self.pending.create("alice")
        self.assertFalse(self.pending.consume(state, "bob"))
        self.assertFalse(self.pending.consume(state, "alice"))   # and a failed try uses it up

    def test_expires(self):
        state = self.pending.create("alice")
        self.clock.now += 601
        self.assertFalse(self.pending.consume(state, "alice"))

    def test_unknown_and_empty_states(self):
        self.assertFalse(self.pending.consume("nope", "alice"))
        self.assertFalse(self.pending.consume("", "alice"))

    def test_states_are_unique_and_unguessable_length(self):
        states = {self.pending.create("u") for _ in range(3)}
        self.assertEqual(len(states), 3)
        self.assertTrue(all(len(s) >= 40 for s in states))

    def test_capacity_drops_the_oldest(self):
        first = self.pending.create("u")
        for _ in range(3):
            self.pending.create("u")
        self.assertFalse(self.pending.consume(first, "u"))

    def test_expired_entries_are_purged(self):
        self.pending.create("u")
        self.clock.now += 601
        self.pending.create("u")
        self.assertEqual(len(self.pending._items), 1)


if __name__ == "__main__":
    unittest.main()
