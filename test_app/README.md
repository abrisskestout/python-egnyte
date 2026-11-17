# python-egnyte test app

`egnyte_test_app.py` exercises this checkout of the `egnyte` library against your own Egnyte
folder and prints PASS / FAIL / SKIP for each check.

- **Read-only checks:** log in, list the target folder, download one existing file and verify
  it against the server's SHA-512 checksum.
- **Write checks:** run inside a new scratch folder, `python-egnyte-test-<timestamp>`, under the
  target folder: upload, metadata, download (bytes, text, byte range), versions, `client.get()`,
  copy, move, listing, notes, search and bulk upload/download. The scratch folder is deleted at
  the end; nothing outside it is changed.

The target folder defaults to your private folder, `/Private/<your username>`.

## 1. Credentials

The app reads `~/.egnyte/config.json` (on Windows `C:\Users\<you>\.egnyte\config.json`), the
same file the library's `egnyte` CLI uses. Environment variables override it.

**Option A: you already have an access token**

```json
{ "domain": "yourcompany", "access_token": "..." }
```

**Option B: username and password.** This needs an API key from
<https://developers.egnyte.com> registered as an internal application.

```json
{ "domain": "yourcompany", "api_key": "...", "login": "your.username" }
```

Run once with `--save-token`. The app asks for your password, gets a token and stores only the
token in the config file. If you sign in to Egnyte through SSO you may not have an Egnyte
password. In that case use option C below.

**Option C: browser sign-in (works with SSO).** `egnyte_oauth_login.py` runs Egnyte's OAuth
authorization code flow (<https://developers.egnyte.com/docs/read/Public_API_Authentication>).
It needs a **Public** API key with a redirect URI registered in Egnyte, and that key's client ID
and secret. One-time setup:

```powershell
pip install keyring                              # Windows Credential Manager access
$env:EGNYTE_APPROVED_DOMAINS = "yourcompany"     # or edit APPROVED_DOMAINS in the script
```

Then, each time:

```powershell
$env:EGNYTE_CLIENT_SECRET = "..."      # or leave unset and type it when asked
python test_app/egnyte_oauth_login.py --domain yourcompany --client-id KEY --redirect-uri "https://localhost/callback"
python test_app/egnyte_test_app.py --read-only
```

What it does and why:

- **Approved domains only.** The domain must exactly match an entry in `EGNYTE_APPROVED_DOMAINS`
  (comma-separated; `yourcompany` means `yourcompany.egnyte.com`) or `APPROVED_DOMAINS` in the
  script. Credentials, ports, paths, queries and fragments in the domain are rejected, before the
  secret prompt or the browser.
- **Redirect URI.** It must match the registered one exactly. Egnyte's docs say HTTPS. For an
  `https` URI the browser shows an error page after you sign in. That is expected: copy the full
  address and paste it into the terminal (the input is hidden). A loopback
  `http://localhost:PORT/path` URI is received automatically, if Egnyte accepts it. Callbacks are
  accepted only for the exact path, with the one-time `state`, and exactly one of `code` or
  `error`; anything else is refused and the script keeps waiting until `--timeout`.
- **Where the token goes.** By default into Windows Credential Manager. The config file keeps only
  `domain`, `api_key` (the client ID) and `access_token_ref`, and `egnyte_test_app.py` reads the
  token from the credential store. `python -m egnyte` can't: use `--store file` to keep the token
  in the config file instead, which is then limited to your Windows user and written atomically.
  Links and reparse points are refused either way, and so is a `--config` path inside this repository.
- **Never stored:** the client secret and the refresh token.
- **Token lifetime.** Egnyte says 30 days. Run the script again for a new token; it reuses the
  saved domain and client ID.
- **TLS and redirects.** Certificates are always verified, and the token request and the final
  `/userinfo` check refuse to follow any redirect.
- **PKCE.** `--pkce` sends a PKCE challenge, but it is off by default: Egnyte's documentation
  doesn't say it supports PKCE, and if the server ignored the challenge you would get no protection
  while believing you had it. The client secret protects the code exchange instead.
- **Output.** Response bodies are never printed, only the HTTP status and a standard OAuth error
  code. Text that comes from outside (error descriptions, the user name) has control characters
  removed and its length limited.

Scopes are least-privilege. Request more only when you need the feature:

| Feature | Scope | How to get it |
|---|---|---|
| Everything `egnyte_test_app.py` does by default (files, folders, versions, copy, move, notes, search, bulk) | `Egnyte.filesystem` | default |
| `egnyte_test_app.py --links` | `Egnyte.link` | `--links` |
| The login script's own `/userinfo` check | none documented | |
| Anything else (user, audit, permission, ...) | see Egnyte's scope list | explicit `--scope "Egnyte.filesystem Egnyte.audit"` |

If you ever signed in with broader scopes than this table needs, delete the stored token (the
`access_token` or `access_token_ref` entry and the credential) and sign in again with the defaults.

Run the tests for the login script with `python -m unittest discover -s test_app/tests -v`. They
use no network and no real Egnyte account. One test round-trips a fake token through the real
Windows Credential Manager when `keyring` is installed.

Instead of the file you can set environment variables for the current PowerShell session:

```powershell
$env:EGNYTE_DOMAIN = "yourcompany"
$env:EGNYTE_ACCESS_TOKEN = "..."
```

`EGNYTE_API_KEY`, `EGNYTE_USERNAME` and `EGNYTE_PASSWORD` work for option B.

## 2. Run

From the repository root:

```powershell
python test_app/egnyte_test_app.py --read-only    # first run: changes nothing
python test_app/egnyte_test_app.py                # full run
python test_app/egnyte_test_app.py --folder "/Shared/My Team/sandbox" --keep
```

| Option | Effect |
|---|---|
| `--folder PATH` | Egnyte folder to test in (default `/Private/<you>`) |
| `--read-only` | only run checks that change nothing |
| `--keep` | keep the scratch folder so you can inspect it in Egnyte |
| `--links` | also create, list and delete a domain-only share link |
| `--save-token` | store a token obtained with username/password in the config file |
| `--config PATH` | use another config file; relative paths resolve under `~/.egnyte/`, as with the `egnyte` CLI |
| `-v` | print full tracebacks for failures |

Exit codes: 0 when nothing failed, 1 when a check failed, 2 for setup problems.

## Notes

- The only dependency is `requests`. Don't `pip install -e .`, because `setup.py` caps Python
  below 3.10. The script imports `egnyte` straight from this checkout.
- Egnyte rate-limits API keys per second and per day. The app throttles itself to 2 requests
  per second (set `"requests_per_second"` in the config to change it). A full run makes about
  45 API calls.
- On Windows, two checks fail because of library bugs, and the app prints the likely cause:
  - **search with a modified_after date**: `egnyte.base.date_in_ms()` calls `strftime('%s')`,
    which Windows doesn't support.
  - **bulk_upload**: `egnyte.base.generate_paths()` builds cloud paths with Windows
    backslashes (`'\bulkdata/a.txt'`), so files inside a folder don't land where they should.
- If **download as text with read()** fails, `FileDownload.read()` decoded the file with the
  encoding the server's `Content-Type` implied. `write_to()` and `iter_content()` return exact
  bytes.
- The uploads, downloads and deletions show up in your domain's audit log like any other
  activity.
