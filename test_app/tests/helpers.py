"""Shared helpers for the OAuth login tests."""
import http.client
import os
import re
import socket
import subprocess
import sys
import time

APP_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if APP_DIR not in sys.path:
    sys.path.insert(0, APP_DIR)


class FakeBackend:
    """In-memory stand-in for the `keyring` module."""

    def __init__(self):
        self.items = {}

    def set_password(self, service, name, password):
        self.items[(service, name)] = password

    def get_password(self, service, name):
        return self.items.get((service, name))

    def delete_password(self, service, name):
        del self.items[(service, name)]


class FakeResponse:
    def __init__(self, status=200, body=None, text=None):
        self.status_code = status
        self._body = body
        self.text = text if text is not None else repr(body)

    def json(self):
        if self._body is None:
            raise ValueError("not JSON")
        return self._body


def fetch(port, target):
    """GET http://127.0.0.1:port/target without going through any proxy: (status, body, headers)."""
    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
    try:
        conn.request("GET", target)
        response = conn.getresponse()
        return response.status, response.read().decode("utf-8", "replace"), dict(response.getheaders())
    finally:
        conn.close()


def free_port():
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        return probe.getsockname()[1]


def wait_for_close(sock, limit):
    """Seconds until the server closes the connection; fails the caller's assertions if it never does."""
    start = time.monotonic()
    sock.settimeout(0.1)
    while time.monotonic() - start < limit:
        try:
            if sock.recv(100) == b"":
                return time.monotonic() - start
        except TimeoutError:
            continue
        except ConnectionError:
            return time.monotonic() - start
    return float("inf")


def whoami():
    return subprocess.run(["whoami"], capture_output=True, text=True, check=True).stdout.strip()


def acl_principals(path):
    """Who has an access-control entry on path (Windows, via icacls)."""
    output = subprocess.run(["icacls", path], capture_output=True, text=True, check=True).stdout
    principals = []
    for line in output.splitlines():
        line = line.strip()
        if line.startswith(path):
            line = line[len(path):].strip()
        found = re.match(r"^(.+?):\(", line)
        if found:
            principals.append(found.group(1))
    return principals
