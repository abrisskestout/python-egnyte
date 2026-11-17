"""Where the OAuth login script keeps secrets.

* The OS credential store (Windows Credential Manager, macOS Keychain, Secret Service) through the
  maintained `keyring` package. The config file then holds only a reference to the token.
* Or, if you must have the token in the config file (the `python -m egnyte` CLI reads it from
  there), a file that is written atomically, refuses symbolic links and reparse points, and is
  limited to the current user.

Standard library only; `keyring` is imported when a credential store is actually used.
"""
import csv
import json
import os
import secrets
import stat
import subprocess

KEYRING_SERVICE = "python-egnyte"
REF_PREFIX = "keyring:"


class CredentialStoreError(Exception):
    """A credential could not be stored or loaded safely. The message is safe to print."""


# --------------------------------------------------------------------------- OS credential store

def token_ref(domain):
    """The reference kept in the config file instead of the token itself."""
    return f"{REF_PREFIX}{KEYRING_SERVICE}:{domain}"


def split_ref(ref):
    if not isinstance(ref, str) or not ref.startswith(REF_PREFIX):
        raise CredentialStoreError("Unsupported credential reference in the config file.")
    service, separator, name = ref[len(REF_PREFIX):].partition(":")
    if not (service and separator and name):
        raise CredentialStoreError("Malformed credential reference in the config file.")
    return service, name


def default_backend():
    """The `keyring` module, after checking that it has a real credential store behind it."""
    try:
        import keyring
        from keyring.backends import fail
    except ImportError as e:
        raise CredentialStoreError(
            "The 'keyring' package is needed to use the OS credential store: pip install keyring") from e
    if isinstance(keyring.get_keyring(), fail.Keyring):
        raise CredentialStoreError("The 'keyring' package found no usable OS credential store.")
    return keyring


def store_token(domain, token, backend=None):
    """Save the token in the credential store; returns the reference to put in the config file."""
    backend = backend or default_backend()
    service, name = split_ref(token_ref(domain))
    try:
        backend.set_password(service, name, token)
    except Exception as e:  # keyring backends raise their own error types
        raise CredentialStoreError(f"The credential store refused the token ({type(e).__name__}).") from None
    return token_ref(domain)


def load_token(ref, backend=None):
    service, name = split_ref(ref)
    backend = backend or default_backend()
    try:
        token = backend.get_password(service, name)
    except Exception as e:
        raise CredentialStoreError(f"The credential store could not be read ({type(e).__name__}).") from None
    if not token:
        raise CredentialStoreError("No token is stored for this config; run egnyte_oauth_login.py again.")
    return token


def delete_token(ref, backend=None):
    service, name = split_ref(ref)
    backend = backend or default_backend()
    try:
        backend.delete_password(service, name)
    except Exception as e:
        raise CredentialStoreError(f"The credential could not be deleted ({type(e).__name__}).") from None


# --------------------------------------------------------------------------- locked-down file

def reject_link(path):
    """Refuse symbolic links, junctions and other reparse points."""
    try:
        info = os.lstat(path)
    except FileNotFoundError:
        return
    attributes = getattr(info, "st_file_attributes", 0)
    if stat.S_ISLNK(info.st_mode) or attributes & stat.FILE_ATTRIBUTE_REPARSE_POINT:
        raise CredentialStoreError(f"Refusing to use {path}: it is a symbolic link or reparse point.")


def current_sid():
    """The Windows SID of the user running this process."""
    result = subprocess.run(["whoami", "/user", "/fo", "csv", "/nh"], capture_output=True, text=True, check=True)
    return next(csv.reader([result.stdout.strip()]))[1]


def restrict_to_current_user(path, directory):
    """Leave only the current user with access to path (directory=True also covers new children)."""
    if os.name == "nt":
        try:
            grant = f"*{current_sid()}:" + ("(OI)(CI)F" if directory else "F")
            subprocess.run(["icacls", path, "/reset"], capture_output=True, check=True)
            subprocess.run(["icacls", path, "/inheritance:r", "/grant:r", grant], capture_output=True, check=True)
        except (OSError, subprocess.CalledProcessError, StopIteration, IndexError):
            raise CredentialStoreError(f"Could not restrict {path} to the current user.") from None
    else:
        os.chmod(path, 0o700 if directory else 0o600)


def write_private_json(path, data, restrict=True):
    """Write data as JSON atomically (temp file in the same folder, then replace).

    Refuses a folder or file that is a link or reparse point. With restrict=True the folder and
    the file are also limited to the current user, and nothing is written if that fails.
    """
    path = os.path.abspath(path)
    directory = os.path.dirname(path)
    reject_link(directory)
    os.makedirs(directory, mode=0o700, exist_ok=True)
    reject_link(directory)
    reject_link(path)
    if restrict:
        restrict_to_current_user(directory, directory=True)

    temp = os.path.join(directory, f".{os.path.basename(path)}.{secrets.token_hex(4)}.tmp")
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_BINARY", 0)
    fd = os.open(temp, flags, 0o600)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fp:
            if restrict:
                restrict_to_current_user(temp, directory=False)
            json.dump(data, fp, indent=2, sort_keys=True)
            fp.flush()
            os.fsync(fp.fileno())
        os.replace(temp, path)
    except BaseException:
        try:
            os.remove(temp)
        except OSError:
            pass
        raise
