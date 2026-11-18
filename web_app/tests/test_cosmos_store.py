"""The Cosmos DB token store, against a fake container: no network, no Azure account.

The fake raises the Azure SDK's real exception types, so the error handling tested here is the real one.
"""
import hashlib
import json
import threading
import unittest
from types import SimpleNamespace
from unittest import mock

from azure.core.exceptions import ClientAuthenticationError, ServiceRequestError
from azure.cosmos import exceptions as cosmos_errors
from cryptography.fernet import Fernet

from helpers import ALICE, BOB, KEY, TENANT, csrf_from, as_user, build_stack, connect_user, make_settings, page_text
from token_store import (CosmosContainerSource, CosmosTokenStore, FileTokenStore, TokenRecord, TokenStoreError,
                         build_token_store, user_id)

ENDPOINT = "https://cosmos-egnyte-test-abc123.documents.azure.com:443/"
SECRET_DETAIL = "details that must never reach a web page"


def record(access="access-1", refresh="refresh-1", name="alice.eg"):
    return TokenRecord(access, refresh, 5_000_000_000.0, name, 1_700_000_000.0)


def http_error(status, sub_status=None):
    error = cosmos_errors.CosmosHttpResponseError(status_code=status, message=SECRET_DETAIL)
    error.sub_status = sub_status
    return error


def not_found(sub_status=None):
    error = cosmos_errors.CosmosResourceNotFoundError(status_code=404, message="Entity does not exist")
    error.sub_status = sub_status
    return error


class FakeContainer:
    """The three container calls the store makes. Documents are kept as JSON text, like the service keeps them."""

    def __init__(self):
        self.items = {}
        self.calls = []
        self.fail_with = None        # an exception raised by every call
        self._guard = threading.Lock()

    def _enter(self, name):
        self.calls.append(name)
        if self.fail_with is not None:
            raise self.fail_with

    def upsert_item(self, body):
        self._enter("upsert")
        with self._guard:
            self.items[body["id"]] = json.dumps(body)
        return body

    def read_item(self, item, partition_key):
        self._enter("read")
        assert partition_key == item, "the container's partition key path is /id"
        with self._guard:
            if item not in self.items:
                raise not_found()
            return json.loads(self.items[item])

    def delete_item(self, item, partition_key):
        self._enter("delete")
        assert partition_key == item, "the container's partition key path is /id"
        with self._guard:
            if item not in self.items:
                raise not_found()
            del self.items[item]

    def documents(self):
        return [json.loads(text) for text in self.items.values()]


class StoreTests(unittest.TestCase):
    def setUp(self):
        self.container = FakeContainer()
        self.store = CosmosTokenStore(self.container, [KEY])

    def test_round_trip(self):
        self.store.save("u1", record())
        self.assertEqual(self.store.load("u1"), record())

    def test_users_are_kept_apart(self):
        self.store.save("alice", record(access="A"))
        self.store.save("bob", record(access="B"))
        self.assertEqual(self.store.load("alice").access_token, "A")
        self.assertEqual(self.store.load("bob").access_token, "B")
        self.store.delete("alice")
        self.assertIsNone(self.store.load("alice"))
        self.assertEqual(self.store.load("bob").access_token, "B")
        self.assertEqual(len(self.container.items), 1)

    def test_the_document_id_is_a_hash_and_is_also_the_partition_key(self):
        user_key = f"{TENANT}:{ALICE}"
        self.store.save(user_key, record())
        self.assertEqual(list(self.container.items), [hashlib.sha256(user_key.encode()).hexdigest()])
        self.assertEqual(user_id(user_key), list(self.container.items)[0])
        self.store.load(user_key)       # the fake asserts partition key == id on every read and delete
        self.store.delete(user_key)
        self.assertEqual(self.container.items, {})

    def test_nothing_readable_is_stored(self):
        user_key = f"{TENANT}:{ALICE}"
        self.store.save(user_key, record(access="PLAINTEXT-ACCESS", refresh="PLAINTEXT-REFRESH"))
        everything = "\n".join(self.container.items.values()) + "".join(self.container.items)
        for needle in ("PLAINTEXT-ACCESS", "PLAINTEXT-REFRESH", "alice.eg", ALICE, TENANT):
            self.assertNotIn(needle, everything)
        self.assertEqual(set(self.container.documents()[0]), {"id", "v", "updated", "data"})

    def test_saving_again_replaces_the_one_document(self):
        self.store.save("u", record(access="one"))
        self.store.save("u", record(access="two"))
        self.assertEqual(self.store.load("u").access_token, "two")
        self.assertEqual(len(self.container.items), 1)

    def test_a_user_with_no_token_loads_as_none_and_deleting_nothing_is_fine(self):
        self.assertIsNone(self.store.load("nobody"))
        self.store.delete("nobody")

    def test_wrong_key_reads_as_not_connected(self):
        self.store.save("u", record())
        other = CosmosTokenStore(self.container, [Fernet.generate_key().decode()])
        with self.assertLogs("egnyte.tokenstore", "WARNING"):
            self.assertIsNone(other.load("u"))

    def test_key_rotation_reads_old_data_and_writes_with_the_new_key(self):
        self.store.save("u", record(access="old"))
        new_key = Fernet.generate_key().decode()
        rotated = CosmosTokenStore(self.container, [new_key, KEY])
        self.assertEqual(rotated.load("u").access_token, "old")
        rotated.save("u", record(access="new"))
        self.assertEqual(CosmosTokenStore(self.container, [new_key]).load("u").access_token, "new")

    def test_damaged_encrypted_data_reads_as_not_connected_and_is_logged(self):
        item_id = user_id("u")
        for data in ("garbage", "é"):
            with self.subTest(data=data):
                self.container.items[item_id] = json.dumps({"id": item_id, "v": 1, "data": data})
                with self.assertLogs("egnyte.tokenstore", "WARNING"):
                    self.assertIsNone(self.store.load("u"))

    def test_documents_of_another_shape_read_as_not_connected(self):
        item_id = user_id("u")
        for document in ({"id": item_id, "v": 2, "data": "x"}, {"id": item_id, "v": 1, "data": 5}, {"id": item_id}):
            with self.subTest(document=document):
                self.container.items[item_id] = json.dumps(document)
                self.assertIsNone(self.store.load("u"))

    def test_malformed_keys_and_no_keys_are_refused(self):
        with self.assertRaises(ValueError):
            CosmosTokenStore(self.container, ["not-a-fernet-key"])
        with self.assertRaises(ValueError):
            CosmosTokenStore(self.container, [])

    def test_one_lock_per_user_and_it_can_be_held_while_saving(self):
        self.assertIs(self.store.lock_for("a"), self.store.lock_for("a"))
        self.assertIsNot(self.store.lock_for("a"), self.store.lock_for("b"))
        with self.store.lock_for("u"):      # a refresh holds the user's lock and then saves
            self.store.save("u", record())
            self.assertIsNotNone(self.store.load("u"))

    def test_concurrent_saves_and_loads_never_fail(self):
        errors = []

        def worker(n):
            try:
                for i in range(20):
                    self.store.save("u", record(access=f"token-{n}-{i}"))
                    self.assertTrue(self.store.load("u").access_token.startswith("token-"))
            except BaseException as e:      # a failure in a thread must fail the test, not just print
                errors.append(e)
        threads = [threading.Thread(target=worker, args=(n,)) for n in range(4)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        self.assertEqual(errors, [])
        self.assertEqual(len(self.container.items), 1)

    def test_only_point_operations_are_used(self):
        self.store.save("u", record())
        self.store.load("u")
        self.store.delete("u")
        self.assertEqual(self.container.calls, ["upsert", "read", "delete"])    # no query, so no index or scan needed


class FailureTests(unittest.TestCase):
    """A broken database must be an error, never 'this user has no token' (which would send them to reconnect)."""

    def setUp(self):
        self.container = FakeContainer()
        self.store = CosmosTokenStore(self.container, [KEY])
        self.store.save("u", record())

    def failing(self, error):
        self.container.fail_with = error

    def test_a_refusal_is_an_error_with_only_the_status_in_the_message(self):
        for status in (401, 403, 429, 500, 503):
            self.failing(http_error(status))
            for call in (lambda: self.store.load("u"), lambda: self.store.save("u", record()),
                         lambda: self.store.delete("u")):
                with self.subTest(status=status), self.assertLogs("egnyte.tokenstore", "WARNING") as logs:
                    with self.assertRaises(TokenStoreError) as caught:
                        call()
                self.assertIn(f"HTTP {status}", str(caught.exception))
                self.assertNotIn(SECRET_DETAIL, str(caught.exception))
                self.assertIn(SECRET_DETAIL, "\n".join(logs.output))     # but the operator can find it in the log

    def test_a_failed_sign_in_of_the_identity_is_an_error(self):
        self.failing(ClientAuthenticationError("managed identity endpoint unavailable " + SECRET_DETAIL))
        with self.assertLogs("egnyte.tokenstore", "WARNING"), self.assertRaises(TokenStoreError) as caught:
            self.store.load("u")
        self.assertIn("ClientAuthenticationError", str(caught.exception))
        self.assertNotIn(SECRET_DETAIL, str(caught.exception))

    def test_a_network_failure_is_an_error(self):
        self.failing(ServiceRequestError("connection reset"))
        with self.assertLogs("egnyte.tokenstore", "WARNING"), self.assertRaises(TokenStoreError):
            self.store.load("u")

    def test_a_missing_container_is_not_mistaken_for_a_user_without_a_token(self):
        self.failing(not_found(sub_status=1003))        # 404 / 1003: the database or container doesn't exist
        for call in (lambda: self.store.load("u"), lambda: self.store.delete("u")):
            with self.assertLogs("egnyte.tokenstore", "WARNING"), self.assertRaises(TokenStoreError):
                call()

    def test_saving_to_a_missing_container_fails(self):
        self.failing(not_found())
        with self.assertLogs("egnyte.tokenstore", "WARNING"), self.assertRaises(TokenStoreError):
            self.store.save("u", record())

    def test_a_plain_missing_document_is_just_no_token(self):
        self.failing(not_found())
        self.assertIsNone(self.store.load("u"))
        self.store.delete("u")

    def test_programming_errors_are_not_disguised(self):
        self.failing(RuntimeError("a bug"))
        with self.assertRaises(RuntimeError):
            self.store.load("u")

    def test_recovery_needs_no_restart(self):
        self.failing(http_error(503))
        with self.assertLogs("egnyte.tokenstore", "WARNING"), self.assertRaises(TokenStoreError):
            self.store.load("u")
        self.container.fail_with = None
        self.assertEqual(self.store.load("u"), record())


class FakeClient:
    """Stands in for azure.cosmos.CosmosClient and records how it was created."""
    created = []

    def __init__(self, endpoint, credential):        # exactly these two: there is no way to hand it a key
        self.endpoint, self.credential, self.databases = endpoint, credential, []
        self.container = FakeContainer()
        FakeClient.created.append(self)

    def get_database_client(self, name):
        self.databases.append(name)
        return SimpleNamespace(get_container_client=lambda container: self._container_client(name, container))

    def _container_client(self, database, container):
        self.opened = (database, container)
        return self.container


class ContainerSourceTests(unittest.TestCase):
    def setUp(self):
        FakeClient.created = []

    def source(self, **kwargs):
        defaults = dict(endpoint=ENDPOINT, database="egnyte-auth", container="tokens", client_factory=FakeClient)
        defaults.update(kwargs)
        return CosmosContainerSource(**defaults)

    def test_nothing_is_contacted_until_the_first_use(self):
        source = self.source(credential=object())
        self.assertEqual(FakeClient.created, [])
        source()
        self.assertEqual(len(FakeClient.created), 1)
        source()
        self.assertEqual(len(FakeClient.created), 1)        # one client, reused

    def test_it_opens_the_configured_database_and_container_at_the_endpoint(self):
        credential = object()
        container = self.source(credential=credential, database="db1", container="c1")()
        client = FakeClient.created[0]
        self.assertEqual((client.endpoint, client.opened), (ENDPOINT, ("db1", "c1")))
        self.assertIs(client.credential, credential)
        self.assertIs(container, client.container)

    def test_on_azure_the_credential_is_the_managed_identity_and_nothing_else(self):
        with mock.patch("azure.identity.ManagedIdentityCredential") as managed, \
                mock.patch("azure.identity.DefaultAzureCredential") as default:
            self.source(on_azure=True)()
        managed.assert_called_once_with()
        default.assert_not_called()
        self.assertIs(FakeClient.created[0].credential, managed.return_value)

    def test_on_a_pc_the_credential_is_the_developers_az_login(self):
        with mock.patch("azure.identity.ManagedIdentityCredential") as managed, \
                mock.patch("azure.identity.DefaultAzureCredential") as default:
            self.source(on_azure=False)()
        default.assert_called_once_with()
        managed.assert_not_called()
        self.assertIs(FakeClient.created[0].credential, default.return_value)

    def test_the_credential_is_a_credential_object_never_a_key_string(self):
        with mock.patch("azure.identity.ManagedIdentityCredential"):
            self.source(on_azure=True)()
        self.assertNotIsInstance(FakeClient.created[0].credential, (str, bytes, dict))

    def test_a_failure_to_open_is_an_error_and_the_next_call_tries_again(self):
        calls = []

        def flaky(endpoint, credential):
            calls.append(1)
            if len(calls) == 1:
                raise ClientAuthenticationError("identity not ready")
            return FakeClient(endpoint, credential)
        source = self.source(credential=object(), client_factory=flaky)
        with self.assertLogs("egnyte.tokenstore", "WARNING"), self.assertRaises(TokenStoreError):
            source()
        self.assertIsNotNone(source())
        self.assertEqual(len(calls), 2)

    def test_the_store_opens_it_lazily_and_reports_an_open_failure_as_a_store_error(self):
        def broken(endpoint, credential):
            raise http_error(403)
        store = CosmosTokenStore(self.source(credential=object(), client_factory=broken), [KEY])   # no error yet
        with self.assertLogs("egnyte.tokenstore", "WARNING"), self.assertRaises(TokenStoreError) as caught:
            store.load("u")
        self.assertIn("HTTP 403", str(caught.exception))


class BuildStoreTests(unittest.TestCase):
    def test_cosmos_when_an_endpoint_is_configured_and_nothing_is_contacted_at_start_up(self):
        with mock.patch("azure.cosmos.CosmosClient") as client, mock.patch("azure.identity.ManagedIdentityCredential"), \
                mock.patch("azure.identity.DefaultAzureCredential"):
            store = build_token_store(make_settings("unused", cosmos_endpoint=ENDPOINT, on_azure=True))
        self.assertIsInstance(store, CosmosTokenStore)
        client.assert_not_called()

    def test_the_real_client_gets_the_endpoint_and_a_credential_only(self):
        with mock.patch("azure.cosmos.CosmosClient") as client, mock.patch("azure.identity.ManagedIdentityCredential") as managed:
            store = build_token_store(make_settings("unused", cosmos_endpoint=ENDPOINT, on_azure=True,
                                                    cosmos_database="d", cosmos_container="c"))
            store.load("u")
        client.assert_called_once_with(ENDPOINT, credential=managed.return_value)
        client.return_value.get_database_client.assert_called_once_with("d")
        client.return_value.get_database_client.return_value.get_container_client.assert_called_once_with("c")

    def test_files_when_there_is_no_endpoint(self):
        import tempfile
        with tempfile.TemporaryDirectory() as folder:
            self.assertIsInstance(build_token_store(make_settings(folder)), FileTokenStore)


# ---------------------------------------------------------------------------- the whole site over Cosmos DB

class SiteOverCosmosTests(unittest.TestCase):
    def setUp(self):
        self.container = FakeContainer()
        self.stack = build_stack(self, store_factory=lambda s: CosmosTokenStore(self.container, s.encryption_keys))
        self.alice = as_user(self.stack.app.test_client(), ALICE, "alice@example.com")
        self.bob = as_user(self.stack.app.test_client(), BOB, "bob@example.com")

    def test_connecting_stores_an_encrypted_document_per_person(self):
        self.assertEqual(connect_user(self, self.alice, "code-alice").status_code, 302)
        self.assertEqual(connect_user(self, self.bob, "code-bob").status_code, 302)
        self.assertEqual(len(self.container.items), 2)
        everything = "\n".join(self.container.items.values())
        for needle in ("alice-access", "alice-refresh", "bob-access", "bob-refresh", "alice.eg", "bob.eg"):
            self.assertNotIn(needle, everything)
        self.assertIn("alice.eg", page_text(self.alice.get("/")))
        self.assertIn("bob.eg", page_text(self.bob.get("/")))

    def test_each_person_browses_with_their_own_stored_token(self):
        connect_user(self, self.alice, "code-alice")
        connect_user(self, self.bob, "code-bob")
        self.alice.get("/folders?path=/Shared")
        self.bob.get("/folders?path=/Shared")
        self.assertEqual(self.stack.world.tokens_used(), ["alice-access", "bob-access"])

    def test_disconnecting_deletes_only_that_persons_document(self):
        connect_user(self, self.alice, "code-alice")
        connect_user(self, self.bob, "code-bob")
        token = csrf_from(self.alice.get("/"))
        self.assertEqual(self.alice.post("/egnyte/disconnect", data={"csrf": token}).status_code, 302)
        self.assertEqual(len(self.container.items), 1)
        self.assertIn("Connect to Egnyte", page_text(self.alice.get("/")))     # she has to connect again
        self.assertIn("bob.eg", page_text(self.bob.get("/")))                   # he is untouched

    def test_a_refreshed_token_is_written_back_to_cosmos(self):
        connect_user(self, self.alice, "code-alice")
        world = self.stack.world
        world.trees["refreshed-access"] = world.trees["alice-access"]
        world.rejected.add("alice-access")                 # Egnyte stops accepting the stored access token
        self.assertEqual(self.alice.get("/folders?path=/Shared").status_code, 200)
        saved = self.stack.store.load(f"{TENANT}:{ALICE}")
        self.assertEqual((saved.access_token, saved.refresh_token), ("refreshed-access", "rotated-refresh"))
        self.assertEqual(len(self.container.items), 1)      # replaced, not duplicated

    def test_an_outage_is_a_503_and_never_disconnects_anyone(self):
        connect_user(self, self.alice, "code-alice")
        self.container.fail_with = http_error(403)
        with self.assertLogs("egnyte.tokenstore", "WARNING"):
            down = self.alice.get("/folders?path=/Shared")
        self.assertEqual(down.status_code, 503)
        text = page_text(down)
        self.assertIn("Token database unavailable", text)
        self.assertIn("HTTP 403", text)
        self.assertNotIn(SECRET_DETAIL, text)
        self.assertNotIn("alice-access", text)
        self.container.fail_with = None
        self.assertEqual(len(self.container.items), 1)      # her stored link is untouched
        self.assertEqual(self.alice.get("/folders?path=/Shared").status_code, 200)
        self.assertIn("alice.eg", page_text(self.alice.get("/")))

    def test_the_health_check_does_not_depend_on_the_database(self):
        self.container.fail_with = http_error(503)
        self.assertEqual(self.stack.app.test_client().get("/healthz").status_code, 200)
        self.assertEqual(self.container.calls, [])


if __name__ == "__main__":
    unittest.main()
