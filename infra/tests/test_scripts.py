"""Tests for the deployment shell scripts, with a fake `az` and a fake `curl` (no network, no Azure).

    python -m unittest discover -s infra/tests -v

They need bash. On Windows that is Git Bash; the tests are skipped if it can't be found.
"""
import base64
import os
import shutil
import stat
import subprocess
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
SCRIPTS = os.path.join(os.path.dirname(HERE), "scripts")


def find_bash():
    for candidate in (r"C:\Program Files\Git\bin\bash.exe", r"C:\Program Files\Git\usr\bin\bash.exe"):
        if os.path.exists(candidate):
            return candidate
    return shutil.which("bash")   # on Linux and macOS this is the real thing


BASH = find_bash()

FAKE_AZ = r"""#!/usr/bin/env bash
state="$FAKE_AZ_STATE"
echo "$*" >> "$state/argv.log"
group="$1 $2"
sub="$3"
name=""; file=""
while [ $# -gt 0 ]; do
  case "$1" in --name|-n) name="$2"; shift;; --file) file="$2"; shift;; esac
  shift
done
case "$group" in
  "keyvault secret")
    case "$sub" in
      show)
        if [ -f "$state/always_forbidden" ]; then echo "(Forbidden) Caller is not authorized" >&2; exit 1; fi
        if [ -f "$state/forbidden_remaining" ] && [ "$(cat "$state/forbidden_remaining")" -gt 0 ]; then
          left=$(cat "$state/forbidden_remaining"); echo $((left - 1)) > "$state/forbidden_remaining"
          echo "(Forbidden) Caller is not authorized" >&2; exit 1
        fi
        if [ -f "$state/secret_$name" ]; then echo "https://vault.example/secrets/$name/id"; exit 0; fi
        echo "(SecretNotFound) A secret with (name/id) $name was not found in this key vault." >&2; exit 3;;
      set) cp "$file" "$state/secret_$name"; exit 0;;
    esac;;
esac
echo "fake az: unexpected call: $*" >&2; exit 99
"""

FAKE_CURL = r"""#!/usr/bin/env bash
state="$FAKE_CURL_STATE"
url="${@: -1}"
case "$url" in
  */healthz)
    calls=$(cat "$state/health_calls" 2>/dev/null || echo 0); echo $((calls + 1)) > "$state/health_calls"
    IFS=' ' read -r -a codes <<< "$FAKE_CURL_HEALTH"
    index=$calls; [ "$index" -ge "${#codes[@]}" ] && index=$(( ${#codes[@]} - 1 ))
    printf '%s' "${codes[$index]}";;
  *) printf '%s' "${FAKE_CURL_ROOT:-302}";;
esac
"""


def posix(path):
    return path.replace("\\", "/")


@unittest.skipUnless(BASH, "bash is not available")
class ScriptCase(unittest.TestCase):
    def setUp(self):
        folder = tempfile.TemporaryDirectory()
        self.addCleanup(folder.cleanup)
        self.tmp = folder.name
        self.bin = os.path.join(self.tmp, "bin")
        self.state = os.path.join(self.tmp, "state")
        os.makedirs(self.bin)
        os.makedirs(self.state)
        for name, body in (("az", FAKE_AZ), ("curl", FAKE_CURL)):
            path = os.path.join(self.bin, name)
            with open(path, "w", newline="\n") as fp:
                fp.write(body)
            os.chmod(path, os.stat(path).st_mode | stat.S_IEXEC)

    def run_script(self, name, *args, **env):
        environment = dict(os.environ)
        # `az` is found through PATH. Git Bash puts its own folders (and so the real curl) ahead of an inherited
        # PATH, so curl is handed over explicitly through the script's CURL override.
        environment.update(PATH=posix(self.bin) + os.pathsep + os.environ["PATH"], CURL=posix(os.path.join(self.bin, "curl")),
                           FAKE_AZ_STATE=posix(self.state), FAKE_CURL_STATE=posix(self.state), RETRY_DELAY="0")
        environment.update({key: str(value) for key, value in env.items()})
        return subprocess.run([BASH, posix(os.path.join(SCRIPTS, name)), *args], env=environment, cwd=self.tmp,
                              capture_output=True, text=True, timeout=120)

    def secret(self, name):
        path = os.path.join(self.state, f"secret_{name}")
        if not os.path.exists(path):
            return None
        with open(path) as fp:
            return fp.read()

    def put_secret(self, name, value):
        with open(os.path.join(self.state, f"secret_{name}"), "w") as fp:
            fp.write(value)

    def argv_log(self):
        path = os.path.join(self.state, "argv.log")
        if not os.path.exists(path):
            return ""
        with open(path) as fp:
            return fp.read()

    def write_state(self, name, value):
        with open(os.path.join(self.state, name), "w") as fp:
            fp.write(value)


class FilesTests(unittest.TestCase):
    def test_scripts_have_unix_line_endings_and_valid_syntax(self):
        for name in sorted(os.listdir(SCRIPTS)):
            path = os.path.join(SCRIPTS, name)
            with open(path, "rb") as fp:
                self.assertNotIn(b"\r", fp.read(), f"{name} has Windows line endings; bash would choke on them")
            if BASH:
                result = subprocess.run([BASH, "-n", posix(path)], capture_output=True, text=True)
                self.assertEqual(result.returncode, 0, f"{name}: {result.stderr}")


class EnsureGeneratedSecretsTests(ScriptCase):
    def run_ensure(self, **env):
        return self.run_script("ensure-generated-secrets.sh", KEY_VAULT_NAME="kv-test", **env)

    def test_creates_both_secrets_with_usable_values(self):
        result = self.run_ensure()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        flask_key, fernet_key = self.secret("flask-secret-key"), self.secret("token-encryption-keys")
        self.assertGreaterEqual(len(flask_key), 32)
        self.assertEqual(len(base64.urlsafe_b64decode(fernet_key)), 32)      # a valid Fernet key
        self.assertNotIn("\n", flask_key + fernet_key)                       # no trailing newline stored

    def test_existing_secrets_are_never_replaced(self):
        self.put_secret("flask-secret-key", "keep-this-one")
        self.put_secret("token-encryption-keys", "and-this-one")
        result = self.run_ensure()
        self.assertEqual(result.returncode, 0)
        self.assertEqual((self.secret("flask-secret-key"), self.secret("token-encryption-keys")),
                         ("keep-this-one", "and-this-one"))
        self.assertNotIn("secret set", self.argv_log())

    def test_running_twice_changes_nothing(self):
        self.run_ensure()
        first = (self.secret("flask-secret-key"), self.secret("token-encryption-keys"))
        self.assertEqual(self.run_ensure().returncode, 0)
        self.assertEqual((self.secret("flask-secret-key"), self.secret("token-encryption-keys")), first)

    def test_values_never_reach_the_command_line_or_the_terminal(self):
        result = self.run_ensure()
        shown = result.stdout + result.stderr
        self.assertNotIn("::add-mask::", shown)      # a mask command would print the secret on a terminal
        for name in ("flask-secret-key", "token-encryption-keys"):
            value = self.secret(name)
            self.assertTrue(value)
            self.assertNotIn(value, self.argv_log())
            self.assertNotIn(value, shown)

    def test_waits_for_permissions_to_take_effect(self):
        self.write_state("forbidden_remaining", "3")
        result = self.run_ensure()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("did not work yet", result.stdout)
        self.assertIsNotNone(self.secret("flask-secret-key"))

    def test_gives_up_with_a_clear_error(self):
        self.write_state("always_forbidden", "1")
        result = self.run_ensure(MAX_ATTEMPTS=3)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("ERROR: Could not read or create the Key Vault secret 'flask-secret-key'", result.stderr)
        self.assertEqual(self.argv_log().count("secret show"), 3)

    def test_needs_a_vault_name(self):
        env = dict(os.environ, PATH=posix(self.bin) + os.pathsep + os.environ["PATH"])
        env.pop("KEY_VAULT_NAME", None)
        result = subprocess.run([BASH, posix(os.path.join(SCRIPTS, "ensure-generated-secrets.sh"))], env=env,
                                capture_output=True, text=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("KEY_VAULT_NAME", result.stderr)


class RequireSecretsTests(ScriptCase):
    def test_passes_when_everything_is_there(self):
        self.put_secret("egnyte-client-secret", "TOPSECRET1")
        self.put_secret("entra-client-secret", "TOPSECRET2")
        result = self.run_script("require-secrets.sh", "egnyte-client-secret", "entra-client-secret", KEY_VAULT_NAME="kv-test")
        self.assertEqual(result.returncode, 0)
        self.assertNotIn("TOPSECRET", result.stdout + result.stderr)

    def test_names_what_is_missing_and_says_what_to_do(self):
        self.put_secret("entra-client-secret", "TOPSECRET2")
        result = self.run_script("require-secrets.sh", "egnyte-client-secret", "entra-client-secret", KEY_VAULT_NAME="kv-test")
        self.assertEqual(result.returncode, 1)
        self.assertIn("missing, or your account cannot read: egnyte-client-secret", result.stderr)
        self.assertNotIn("entra-client-secret", result.stderr.split("cannot read:")[1].splitlines()[0])   # only the missing one
        self.assertIn("run this check again", result.stderr)
        self.assertIn("kv-test", result.stderr)
        self.assertNotIn("TOPSECRET", result.stdout + result.stderr)

    def test_never_reads_a_value(self):
        self.put_secret("egnyte-client-secret", "TOPSECRET1")
        self.run_script("require-secrets.sh", "egnyte-client-secret", KEY_VAULT_NAME="kv-test")
        self.assertIn("--query id", self.argv_log())
        self.assertNotIn("--query value", self.argv_log())

    def test_needs_at_least_one_name(self):
        self.assertEqual(self.run_script("require-secrets.sh", KEY_VAULT_NAME="kv-test").returncode, 2)


class SmokeTestTests(ScriptCase):
    def smoke(self, health, root=None, **env):
        env.update(FAKE_CURL_HEALTH=health, MAX_ATTEMPTS=5)
        if root is not None:
            env["FAKE_CURL_ROOT"] = root
        return self.run_script("smoke-test.sh", "https://egnyte-test.example/", **env)

    def test_waits_until_healthy_then_confirms_sign_in_is_enforced(self):
        result = self.smoke("503 502 200")
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("Site is up", result.stdout)
        self.assertIn("Sign-in is enforced", result.stdout)
        self.assertEqual(self.read_calls(), 3)

    def test_accepts_401_and_403_as_protected(self):
        for code in ("401", "403", "302"):
            with self.subTest(code=code):
                self.assertEqual(self.smoke("200", root=code).returncode, 0)

    def test_fails_when_the_site_never_comes_up(self):
        result = self.smoke("503")
        self.assertEqual(result.returncode, 1)
        self.assertIn("never answered 200", result.stderr)
        self.assertEqual(self.read_calls(), 5)

    def test_fails_when_the_site_is_not_protected(self):
        result = self.smoke("200", root="200")
        self.assertEqual(result.returncode, 1)
        self.assertIn("NOT protecting the site", result.stderr)

    def test_fails_on_a_server_error_at_the_root(self):
        self.assertEqual(self.smoke("200", root="500").returncode, 1)

    def read_calls(self):
        with open(os.path.join(self.state, "health_calls")) as fp:
            return int(fp.read())


if __name__ == "__main__":
    unittest.main()
