#!/usr/bin/env python
"""Smoke-test the python-egnyte library against your own Egnyte folder.

Each check prints PASS, FAIL or SKIP:

* Read-only checks: log in, list the target folder, download one existing file
  and verify it against the server's checksum.
* Write checks (skipped with --read-only) run inside a brand-new scratch folder,
  "python-egnyte-test-<timestamp>", created under the target folder: upload,
  download, versions, copy, move, listing, notes, search and bulk transfer.
  The scratch folder is deleted at the end; nothing outside it is changed.

The egnyte package is imported from this repository checkout, so you are testing
the code in this working tree. Setup instructions: README.md next to this file.
"""
import argparse
import collections
import datetime
import getpass
import hashlib
import io
import os
import re
import shutil
import sys
import tempfile
import textwrap
import time
import traceback
import uuid

import requests

HERE = os.path.dirname(os.path.abspath(__file__))
REPO_ROOT = os.path.dirname(HERE)
sys.path.insert(0, HERE)
if os.path.isdir(os.path.join(REPO_ROOT, "egnyte")):
    sys.path.insert(0, REPO_ROOT)

import egnyte  # noqa: E402  (must come after the sys.path changes above)
import egnyte_credentials  # noqa: E402
from egnyte import base, configuration, exc, resources  # noqa: E402

SCRATCH_PREFIX = "python-egnyte-test-"
TEXT_NAME = "héllo wörld.txt"
TEXT_V1 = "Hello from the python-egnyte test app!\nUnicode: Zażółć gęślą jaźń ✓\n".encode("utf-8")
TEXT_V2 = TEXT_V1 + b"This line was added in version 2.\n"
DEFAULT_REQUESTS_PER_SECOND = 2
EXISTING_FILE_MAX_BYTES = 20 * 1024 * 1024
LISTING_LIMIT = 15
INDENT = " " * 9

ENV_VARS = {
    "domain": "EGNYTE_DOMAIN",
    "access_token": "EGNYTE_ACCESS_TOKEN",
    "api_key": "EGNYTE_API_KEY",
    "login": "EGNYTE_USERNAME",
    "password": "EGNYTE_PASSWORD",
}

SETUP_HELP = """\
No usable Egnyte credentials found. Put one of these in {path}
(or set the environment variables shown):

  Option A - you already have an access token:
    {{"domain": "yourcompany", "access_token": "..."}}
    EGNYTE_DOMAIN, EGNYTE_ACCESS_TOKEN

  Option B - get a token with your Egnyte username and password
  (needs an API key registered as an internal application):
    {{"domain": "yourcompany", "api_key": "...", "login": "your.username"}}
    EGNYTE_DOMAIN, EGNYTE_API_KEY, EGNYTE_USERNAME
    and run with --save-token so the password is asked for only once.

See test_app/README.md for details."""


# --------------------------------------------------------------------------- helpers

class Skip(Exception):
    """Raised by a check that cannot run here (reported as SKIP, not FAIL)."""


def ensure(condition, message):
    if not condition:
        raise AssertionError(message)


def expect_not_found(obj):
    try:
        obj.check()
    except exc.NotFound:
        return
    raise AssertionError(f"{obj.path} still exists")


def describe_error(error):
    """One-line description of an exception, without the bulky response headers."""
    if isinstance(error, AssertionError):
        return str(error)
    if isinstance(error, exc.EgnyteError):
        parts = []
        for arg in error.args:
            if isinstance(arg, dict):
                parts.extend(f"{key}: {value}" for key, value in arg.items() if key != "headers")
            else:
                parts.append(str(arg))
        return f"{type(error).__name__}: {'; '.join(parts)}"
    return f"{type(error).__name__}: {error}"


def count_requests(client):
    """Count every HTTP request the client makes (library retries included), by method.

    Returns a Counter that keeps filling as the client is used. Requests made outside the client,
    such as the token request for --save-token, are not counted."""
    counts = collections.Counter()
    send = client._session.request

    def counting_request(method, *args, **kwargs):
        counts[str(method).upper()] += 1
        return send(method, *args, **kwargs)

    client._session.request = counting_request
    return counts


def describe_request_counts(counts):
    total = sum(counts.values())
    detail = ", ".join(f"{n} {method}" for method, n in sorted(counts.items()))
    return f"{total} HTTP request(s) to Egnyte through the library" + (f" ({detail})" if detail else "")


def sha512(data):
    return hashlib.sha512(data).hexdigest()


def fetch_bytes(file_obj, download_range=None):
    buffer = io.BytesIO()
    file_obj.download(download_range).write_to(buffer)
    return buffer.getvalue()


def entry_name(item):
    # vars() avoids triggering the library's lazy attribute fetch (one API call per item).
    return vars(item).get("name") or item.path.rsplit("/", 1)[-1]


def human_size(size):
    if size is None:
        return "size unknown"
    for unit in ("bytes", "KB", "MB", "GB"):
        if size < 1024 or unit == "GB":
            return f"{size} {unit}" if unit == "bytes" else f"{size:.1f} {unit}"
        size /= 1024


def read_tree(root):
    """Map every file under root (as a forward-slash relative path) to its contents."""
    tree = {}
    for dirpath, _, filenames in os.walk(root):
        for name in filenames:
            full = os.path.join(dirpath, name)
            with open(full, "rb") as fp:
                tree[os.path.relpath(full, root).replace(os.sep, "/")] = fp.read()
    return tree


class Runner:
    """Runs checks one by one, prints each outcome and keeps score."""

    def __init__(self, verbose):
        self.verbose = verbose
        self.results = []

    def step(self, title, check, needs=True):
        """Run one check; return True if it passed. needs=False skips it."""
        if not needs:
            return self._record("SKIP", title, "an earlier check it depends on did not pass", None)
        start = time.monotonic()
        try:
            status, detail = "PASS", check()
        except Skip as e:
            status, detail = "SKIP", str(e)
        except Exception as e:
            status, detail = "FAIL", describe_error(e)
            if self.verbose:
                traceback.print_exc()
        return self._record(status, title, detail, time.monotonic() - start)

    def _record(self, status, title, detail, seconds):
        line = f"[{status}] {title}" + (f" ({seconds:.1f}s)" if seconds is not None else "")
        if detail and status == "FAIL":
            line += "\n" + textwrap.indent(detail, INDENT)
        elif detail:
            line += f" - {detail}"
        print(line, flush=True)
        self.results.append((status, title))
        return status == "PASS"

    def summary(self):
        """Print totals; return True if nothing failed."""
        count = {s: sum(1 for status, _ in self.results if status == s) for s in ("PASS", "FAIL", "SKIP")}
        print(f"\n{count['PASS']} passed, {count['FAIL']} failed, {count['SKIP']} skipped")
        for status, title in self.results:
            if status == "FAIL":
                print(f"  FAIL: {title}")
        return count["FAIL"] == 0


# --------------------------------------------------------------------------- checks

class SmokeTest:
    """The individual checks. Each returns a short detail string or raises."""

    def __init__(self, client, runner, args):
        self.client = client
        self.runner = runner
        self.args = args
        self.target = args.folder  # None means "your private folder", filled in after login
        self.listing = None
        self.scratch = None
        self.scratch_parent = None
        self.scratch_name = None
        self.scratch_created = False
        self.local_dir = None
        self.text_file = None
        self.sub = None
        self.copied = None
        self.moved = None

    def run(self):
        step = self.runner.step
        if not step("log in and read user info", self.user_info):
            return
        if not step("list " + self.target, self.list_target):
            return
        self.print_listing()
        step("download an existing file and verify its checksum", self.download_existing)
        if self.args.read_only:
            return

        print(f"\nWrite checks run inside a new scratch folder under {self.target}"
              + ("." if self.args.keep else " that is deleted at the end."))
        if not step("create the scratch folder", self.create_scratch):
            return
        step("create() again with ignore_if_exists=True is a no-op", self.recreate_scratch)
        up = step("upload a text file from bytes (non-ASCII name)", self.upload_text)
        step("read file metadata (size, SHA-512 checksum)", self.metadata, needs=up)
        step("download exact bytes with write_to()", self.download_exact, needs=up)
        step("download as text with read()", self.download_text, needs=up)
        step("download a byte range", self.download_range, needs=up)
        step("upload a second version", self.new_version, needs=up)
        step("upload a binary file from disk", self.upload_binary)
        step("client.get() returns File and Folder objects", self.get_types, needs=up)
        sub = step("create a subfolder", self.create_subfolder)
        copied = step("copy a file", self.copy_file, needs=up and sub)
        moved = step("move (rename) a file", self.move_file, needs=copied)
        step("list the scratch folder", self.list_scratch, needs=up and sub)
        step("notes: add, list, delete", self.notes, needs=up)
        step("search, scoped to the scratch folder", self.search)
        step("search with a modified_after date", self.search_by_date)
        step("bulk_upload a local folder, then bulk_download it", self.bulk_transfer)
        if self.args.links:
            step("links: create, list, delete a domain-only link", self.links, needs=up)
        step("delete a file", self.delete_file, needs=moved)

    def cleanup(self):
        if self.local_dir:
            shutil.rmtree(self.local_dir, ignore_errors=True)
        if not self.scratch_created:
            return
        if self.args.keep:
            print(f"\nKept the scratch folder (delete it when you're done): {self.scratch.path}")
        elif not self.runner.step("delete the scratch folder", self.delete_scratch):
            print(f"{INDENT}Delete it manually: {self.scratch.path}")

    # ---- read-only

    def user_info(self):
        info = self.client.user_info
        username = info["username"]
        if self.target is None:
            self.target = f"/Private/{username}"
        full_name = " ".join(filter(None, (info.get("first_name"), info.get("last_name"))))
        return f"logged in as {username}" + (f" ({full_name})" if full_name else "")

    def list_target(self):
        folder = self.client.folder(self.target)
        try:
            result = folder.list()
        except exc.NotFound as e:
            raise AssertionError(f"{describe_error(e)}\nUse --folder to pick a folder you can access.") from e
        ensure(isinstance(result, resources.Folder), f"{self.target} is a file, not a folder")
        self.listing = folder
        return f"{len(folder.folders)} folder(s), {len(folder.files)} file(s)"

    def print_listing(self):
        entries = [f"[dir ] {entry_name(f)}" for f in self.listing.folders]
        entries += [f"[file] {entry_name(f)}  ({human_size(vars(f).get('size'))})" for f in self.listing.files]
        for entry in entries[:LISTING_LIMIT]:
            print(INDENT + entry)
        if len(entries) > LISTING_LIMIT:
            print(f"{INDENT}... and {len(entries) - LISTING_LIMIT} more")

    def download_existing(self):
        files = [f for f in self.listing.files if (vars(f).get("size") or 0) > 0]
        if not files:
            raise Skip("no non-empty files directly inside the target folder")
        smallest = min(files, key=lambda f: vars(f)["size"])
        size = vars(smallest)["size"]
        if size > EXISTING_FILE_MAX_BYTES:
            raise Skip(f"the smallest file is {human_size(size)}; not downloading that")
        data = fetch_bytes(smallest)
        ensure(len(data) == size, f"downloaded {len(data)} bytes, but the listing says {size}")
        checksum = getattr(smallest, "checksum", None)
        if checksum:
            ensure(sha512(data) == checksum, "SHA-512 of the downloaded data doesn't match the server checksum")
        return f"{entry_name(smallest)} ({human_size(size)})" + ("" if checksum else ", no server checksum")

    # ---- write (everything below happens inside the scratch folder)

    def create_scratch(self):
        parent = self.client.folder(self.target)
        self.scratch_parent = parent.path
        self.scratch_name = f"{SCRATCH_PREFIX}{datetime.datetime.now():%Y%m%d-%H%M%S}-{uuid.uuid4().hex[:4]}"
        self.scratch = parent.folder(self.scratch_name)
        self.scratch.create(ignore_if_exists=False)  # raises if it exists, so we never adopt someone's folder
        self.scratch_created = True
        self.scratch.check()
        return self.scratch.path

    def recreate_scratch(self):
        self.scratch.create(ignore_if_exists=True)
        self.scratch.check()
        return "no error raised"

    def upload_text(self):
        self.text_file = self.scratch.file(TEXT_NAME)
        self.text_file.upload(TEXT_V1)
        return f"{len(TEXT_V1)} bytes"

    def metadata(self):
        fresh = self.client.file(self.text_file.path)  # new object, so attributes come from the server
        ensure(fresh.size == len(TEXT_V1), f"size is {fresh.size}, expected {len(TEXT_V1)}")
        ensure(fresh.checksum == sha512(TEXT_V1), "checksum doesn't match the SHA-512 of the uploaded bytes")
        ensure(fresh.is_folder is False, "is_folder should be False for a file")
        return f"size={fresh.size}, num_versions={getattr(fresh, 'num_versions', '?')}"

    def download_exact(self):
        data = fetch_bytes(self.text_file)
        ensure(data == TEXT_V1, f"content differs: {data[:60]!r}")
        return f"{len(data)} bytes match"

    def download_text(self):
        with self.text_file.download() as download:
            text = download.read()
            response = download.response
            encoding = response.encoding or f"auto-detected {response.apparent_encoding}"
        ensure(isinstance(text, str), f"read() returned {type(text).__name__}, expected str")
        expected = TEXT_V1.decode("utf-8")
        at = next((i for i, (a, b) in enumerate(zip(text, expected)) if a != b), min(len(text), len(expected)))
        ensure(text == expected,
               f"read() decoded the file as {encoding}: expected {expected[at:at + 12]!r}, got {text[at:at + 12]!r}\n"
               "FileDownload.read() returns response.text; use write_to() or iter_content() for exact bytes.")
        return f"decoded as {encoding}"

    def download_range(self):
        data = fetch_bytes(self.text_file, (0, 4))
        ensure(data == TEXT_V1[:5], f"got {data!r}, expected {TEXT_V1[:5]!r}")
        return "bytes 0-4"

    def new_version(self):
        self.text_file.upload(TEXT_V2)
        self.text_file.check()  # refresh the cached metadata
        versions = getattr(self.text_file, "num_versions", None)
        ensure(versions == 2, f"num_versions is {versions}, expected 2 (is versioning enabled on your domain?)")
        ensure(fetch_bytes(self.text_file) == TEXT_V2, "download didn't return the new version")
        return "num_versions=2, download returns the new content"

    def upload_binary(self):
        data = os.urandom(256 * 1024)
        local_path = os.path.join(self.tmp(), "random.bin")
        with open(local_path, "wb") as fp:
            fp.write(data)
        remote = self.scratch.file("random.bin")
        with open(local_path, "rb") as fp:
            remote.upload(fp)
        ensure(fetch_bytes(remote) == data, "downloaded bytes differ from the uploaded file")
        ensure(self.client.file(remote.path).checksum == sha512(data), "server checksum differs from local SHA-512")
        return f"{human_size(len(data))} round-tripped"

    def get_types(self):
        as_file = self.client.get(self.text_file.path)
        as_folder = self.client.get(self.scratch.path)
        ensure(isinstance(as_file, resources.File), f"got {type(as_file).__name__} for a file")
        ensure(isinstance(as_folder, resources.Folder), f"got {type(as_folder).__name__} for a folder")
        return "File, Folder"

    def create_subfolder(self):
        self.sub = self.scratch.folder("sub folder")
        self.sub.create()
        self.sub.check()
        return self.sub.path

    def copy_file(self):
        self.copied = self.text_file.copy(f"{self.sub.path}/copy of {TEXT_NAME}")
        self.copied.check()
        self.text_file.check()  # the original must still exist
        return self.copied.path

    def move_file(self):
        self.moved = self.copied.move(f"{self.sub.path}/renamed.txt")
        self.moved.check()
        expect_not_found(self.copied)
        return self.moved.path

    def list_scratch(self):
        self.scratch.list()
        files = sorted(entry_name(f) for f in self.scratch.files)
        folders = sorted(entry_name(f) for f in self.scratch.folders)
        ensure(TEXT_NAME in files, f"{TEXT_NAME!r} missing from files {files}")
        ensure("sub folder" in folders, f"'sub folder' missing from folders {folders}")
        return f"files {files}, folders {folders}"

    def notes(self):
        note = self.text_file.add_note("Added by the python-egnyte test app")
        try:
            ids = [n.id for n in self.text_file.get_notes()]
            ensure(note.id in ids, f"new note {note.id} not among {ids}")
        finally:
            note.delete()
        return f"note {note.id}"

    def search(self):
        results = self.client.search.files("hello", folder=self.scratch.path)
        return f"API call OK, {results.total_count} result(s); new files can take minutes to be indexed"

    def search_by_date(self):
        since = datetime.date.today() - datetime.timedelta(days=1)
        try:
            results = self.client.search.files("hello", folder=self.scratch.path, modified_after=since)
        except ValueError as e:
            if os.name == "nt" and "Invalid format string" in str(e):
                raise AssertionError(f"ValueError: {e}\nLikely cause: egnyte.base.date_in_ms() uses "
                                     "strftime('%s'), which Windows doesn't support.") from e
            raise
        return f"API call OK, {results.total_count} result(s)"

    def bulk_transfer(self):
        src = os.path.join(self.tmp(), "bulkdata")
        expected = {"a.txt": b"alpha\n", "b.bin": os.urandom(10 * 1024), "sub/c.txt": "çé\n".encode("utf-8")}
        for rel, data in expected.items():
            path = os.path.join(src, *rel.split("/"))
            os.makedirs(os.path.dirname(path), exist_ok=True)
            with open(path, "wb") as fp:
                fp.write(data)
        cloud_target = self.scratch.path + "/bulk"
        bad_paths = [cloud for _, _, cloud in base.generate_paths([src]) if "\\" in cloud]
        try:
            self.client.bulk_upload([src], cloud_target)
            dest = os.path.join(self.tmp(), "downloaded")
            os.makedirs(dest)
            self.client.bulk_download([cloud_target + "/bulkdata"], dest, overwrite=True)
            got = read_tree(os.path.join(dest, "bulkdata"))
            if got != expected:
                listing = self.client.folder(cloud_target).list()
                in_cloud = sorted(entry_name(x) for x in listing.folders + listing.files)
                raise AssertionError(
                    f"round trip mismatch - missing: {sorted(set(expected) - set(got))}, "
                    f"unexpected: {sorted(set(got) - set(expected))}, "
                    f"changed: {sorted(k for k in expected if k in got and got[k] != expected[k])}\n"
                    f"{cloud_target} contains {in_cloud}")
        except Exception as e:
            if not bad_paths:
                raise
            raise AssertionError(f"{describe_error(e)}\nLikely cause: egnyte.base.generate_paths() builds cloud "
                                 f"paths with Windows backslashes, e.g. {bad_paths[0]!r}") from e
        return f"{len(expected)} files round-tripped"

    def links(self):
        created = self.text_file.link("Domain")
        try:
            ensure(created, "no link was returned")
            listed = [link.id for link in self.client.links.list(path=self.text_file.path)]
            ensure(created[0].id in listed, f"link {created[0].id} not among {listed}")
        finally:
            for link in created:
                link.delete()
        return f"link {created[0].id} created and deleted"

    def delete_file(self):
        self.moved.delete()
        expect_not_found(self.moved)
        return self.moved.path

    def delete_scratch(self):
        # Safety net: only ever delete the folder this run created.
        ensure(self.scratch.path == f"{self.scratch_parent}/{self.scratch_name}"
               and self.scratch_name.startswith(SCRATCH_PREFIX),
               f"refusing to delete unexpected path {self.scratch.path!r}")
        self.scratch.delete()
        expect_not_found(self.scratch)
        return self.scratch.path

    def tmp(self):
        if self.local_dir is None:
            self.local_dir = tempfile.mkdtemp(prefix="egnyte-test-app-")
        return self.local_dir


# --------------------------------------------------------------------------- setup

def egnyte_folder(value):
    """argparse type: normalise an Egnyte folder path like /Private/me."""
    path = value.strip().replace("\\", "/")
    if re.match(r"^[A-Za-z]:", path):
        raise argparse.ArgumentTypeError(
            f"{value!r} looks like a local path; Egnyte paths look like /Private/you or /Shared/Team "
            "(Git Bash rewrites arguments starting with /; use PowerShell or set MSYS_NO_PATHCONV=1)")
    return "/" + path.strip("/")


def parse_args(argv):
    parser = argparse.ArgumentParser(description="Smoke-test the python-egnyte library against your Egnyte folder.")
    parser.add_argument("--folder", type=egnyte_folder,
                        help="Egnyte folder to test in (default: /Private/<your username>)")
    parser.add_argument("--read-only", action="store_true", help="only run checks that change nothing")
    parser.add_argument("--keep", action="store_true", help="keep the scratch folder so you can inspect it")
    parser.add_argument("--links", action="store_true", help="also create (and delete) a domain-only share link")
    parser.add_argument("--save-token", action="store_true",
                        help="store a token obtained with username/password in the config file")
    parser.add_argument("--config", help="config file (default ~/.egnyte/config.json; relative paths are "
                                         "resolved under ~/.egnyte/, like the egnyte CLI)")
    parser.add_argument("-v", "--verbose", action="store_true", help="print full tracebacks for failures")
    return parser.parse_args(argv)


def load_config(path):
    config = configuration.load(path)  # {} when the file doesn't exist
    config.update({key: os.environ[var] for key, var in ENV_VARS.items() if os.environ.get(var)})
    ref = config.get("access_token_ref")  # written by egnyte_oauth_login.py: the token is in the OS credential store
    if ref and not config.get("access_token"):
        config["access_token"] = egnyte_credentials.load_token(ref)
    return config


def obtain_token(config, config_path, save):
    """Return the configured access token, or get one with username and password."""
    if config.get("access_token"):
        return config["access_token"]
    if not (config.get("api_key") and config.get("login")):
        return None
    password = config.get("password") or getpass.getpass(f"Egnyte password for {config['login']}: ")
    token = base.get_access_token(dict(config, password=password))
    if save:
        stored = configuration.load(config_path)
        stored.update({key: config[key] for key in ("domain", "api_key", "login")})
        stored["access_token"] = token  # the password is never written
        configuration.save(stored, config_path)
        print(f"Saved the access token to {config_path}\n")
    else:
        print("Got an access token (run with --save-token to store it and skip the password next time).\n")
    return token


def main(argv=None):
    args = parse_args(argv)
    try:
        sys.stdout.reconfigure(errors="replace")  # don't crash on unusual file names in a legacy console
    except AttributeError:
        pass

    config_path = configuration.add_directory(args.config or "config.json")
    try:
        config = load_config(config_path)
    except ValueError as e:
        print(f"Could not parse {config_path}: {e}")
        return 2
    except egnyte_credentials.CredentialStoreError as e:
        print(f"Could not read the saved token: {e}")
        return 2
    if not config.get("domain"):
        print(SETUP_HELP.format(path=config_path))
        return 2
    domain = config["domain"] if "." in config["domain"] else config["domain"] + ".egnyte.com"

    print("python-egnyte test app")
    print(f"  library: {os.path.dirname(os.path.abspath(egnyte.__file__))}")
    print(f"  domain : {domain}")
    print(f"  config : {config_path}" + ("" if os.path.exists(config_path) else " (not found; using environment)"))
    print()

    try:
        token = obtain_token(config, config_path, args.save_token)
    except (exc.EgnyteError, requests.RequestException) as e:
        print(f"Could not get an access token: {describe_error(e)}")
        return 2
    if not token:
        print(SETUP_HELP.format(path=config_path))
        return 2

    client_config = {
        "domain": domain,
        "access_token": token,
        "requests_per_second": config.get("requests_per_second", DEFAULT_REQUESTS_PER_SECOND),
    }
    if config.get("timeout"):
        client_config["timeout"] = config["timeout"]
    client = egnyte.EgnyteClient(client_config)
    request_counts = count_requests(client)

    runner = Runner(args.verbose)
    smoke = SmokeTest(client, runner, args)
    interrupted = False
    try:
        smoke.run()
    except KeyboardInterrupt:
        interrupted = True
        print("\nInterrupted - cleaning up.")
    finally:
        smoke.cleanup()
        client.close()
    passed = runner.summary()
    print(describe_request_counts(request_counts))
    return 130 if interrupted else (0 if passed else 1)


if __name__ == "__main__":
    sys.exit(main())
