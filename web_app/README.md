# Egnyte per-user test site

A small web app for testing Egnyte access **as each individual user**. Several people sign in with
Microsoft Entra ID, each connects their own Egnyte account once, and from then on every Egnyte call the
site makes for them uses their own access token. Egnyte enforces their permissions, so two people looking
at the same folder can see different things.

- Secrets (Egnyte client secret, session key, token-encryption key) come from **Azure Key Vault**.
- The Egnyte client ID and other plain settings come from **App Settings**.
- Egnyte tokens, including the refresh token, are stored encrypted, one document per user, in **Azure Cosmos DB**
  (NoSQL). The app signs in to Cosmos DB with its **managed identity**: there is no account key and no connection
  string anywhere, and the account has key-based access switched off.
- Built for **Azure App Service on Linux**. The `egnyte/` library is bundled into the package, not
  installed from PyPI (PyPI only has a 2017 release for modern Python).

## What the site does

| Page | What it does |
|---|---|
| `/` | Shows who you are (Entra) and whether an Egnyte account is connected. Connect, reconnect, disconnect. |
| `/egnyte/connect` → `/egnyte/callback` | The OAuth sign-in. The one-time `state` is tied to your session and works once. |
| `/folders?path=/Shared` | Lists folders and files **as you**. Defaults to `/Private/<your Egnyte username>`. |
| `/file?path=...` | Downloads a file (up to 25 MB) as an attachment. |
| `/permissions` | **Permission test.** Three buttons on one file, `Text Test`, in the folder set by `PERMISSION_TEST_FOLDER` (default `/Shared/Teams/IT/Infrastructure/Azure App Test`): *Edit file* adds the line `edited by <you>`, *Create file* creates it if it doesn't exist, *Delete file* removes it. Each runs as the signed-in user's own Egnyte account, so Egnyte allows or refuses it per person and the page shows the answer. |
| `/healthz` | Plain `ok`, no sign-in. |

## 1. Build the package

```powershell
python web_app/package.py --list
```

This writes `web_app/dist/egnyte-webapp.zip`: the app, the `egnyte/` folder from this checkout (without
its tests and CLI), `LICENSE.txt`, and a `.deployment` file that makes App Service install
`requirements.txt`. Only a fixed list of files goes in, so stored tokens or `.env` files can't leak into it.

## 2. Egnyte: register the redirect URI

On your API key (a **Public** app in the Egnyte developer portal) add the redirect URI

```
https://<APP>.azurewebsites.net/egnyte/callback
```

It must match `EGNYTE_REDIRECT_URI` exactly. Check whether the portal allows more than one redirect URI
per key; if not, this key can serve only one deployment.

## 3. Create the Azure resources

**Alternative:** [infra/](../infra/README.md) holds a Bicep template that does steps 3 to 6 for resource group
`rg-egnyte-test` and app `egnyte-test` (North Central US), including Microsoft sign-in, with the commands to deploy it
and the app from your machine. The manual commands below do the same thing by hand.

PowerShell with the Azure CLI. Pick globally unique names for `$APP` and `$KV`, and check which Python
versions App Service offers with `az webapp list-runtimes --os linux`.

```powershell
$RG   = "rg-egnyte-test"
$LOC  = "eastus"
$PLAN = "plan-egnyte-test"
$APP  = "<globally-unique-app-name>"
$KV   = "<globally-unique-vault-name>"

az group create -n $RG -l $LOC
az appservice plan create -g $RG -n $PLAN --is-linux --sku B1
az webapp create -g $RG -p $PLAN -n $APP --runtime "PYTHON:3.13"

# The app's identity: this is what lets it read Key Vault, with no password anywhere.
$PRINCIPAL = az webapp identity assign -g $RG -n $APP --query principalId -o tsv

az keyvault create -g $RG -n $KV -l $LOC --enable-rbac-authorization true
$KVID = az keyvault show -g $RG -n $KV --query id -o tsv
$ME   = az ad signed-in-user show --query id -o tsv
az role assignment create --role "Key Vault Secrets Officer" --assignee-object-id $ME --assignee-principal-type User --scope $KVID
az role assignment create --role "Key Vault Secrets User" --assignee-object-id $PRINCIPAL --assignee-principal-type ServicePrincipal --scope $KVID
```

Role assignments can take a minute or two to take effect.

## 4. Put the secrets in Key Vault

`--output none` matters: without it `az` prints the secret you just stored.

```powershell
# Egnyte client secret: typed at a hidden prompt, passed through a temporary file, never in shell history.
$secure = Read-Host "Egnyte client secret" -AsSecureString
[System.Net.NetworkCredential]::new("", $secure).Password | Set-Content -NoNewline -Path "$env:TEMP\egnyte-secret.txt"
az keyvault secret set --vault-name $KV -n egnyte-client-secret --file "$env:TEMP\egnyte-secret.txt" --output none
Remove-Item "$env:TEMP\egnyte-secret.txt"

# Two secrets the app needs that you generate: a session-signing key and a token-encryption key.
az keyvault secret set --vault-name $KV -n flask-secret-key --output none --value (python -c "import secrets; print(secrets.token_urlsafe(48))")
az keyvault secret set --vault-name $KV -n token-encryption-keys --output none --value (python -c "import base64, os; print(base64.urlsafe_b64encode(os.urandom(32)).decode())")
```

(You can also create all three in the portal: Key Vault, Secrets, Generate/Import. The names must be exactly
`egnyte-client-secret`, `flask-secret-key` and `token-encryption-keys`.)

## 5. Configure the app

The client ID is an App Setting. The three secrets are **Key Vault references**: App Service reads them from the
vault with the app's identity and hands them to the app as ordinary environment variables.

```powershell
$vault = "https://$KV.vault.azure.net/secrets"
az webapp config appsettings set -g $RG -n $APP --output none --settings `
  "EGNYTE_DOMAIN=stout" `
  "EGNYTE_CLIENT_ID=<your client id>" `
  "EGNYTE_REDIRECT_URI=https://$APP.azurewebsites.net/egnyte/callback" `
  "EGNYTE_CLIENT_SECRET=@Microsoft.KeyVault(SecretUri=$vault/egnyte-client-secret/)" `
  "FLASK_SECRET_KEY=@Microsoft.KeyVault(SecretUri=$vault/flask-secret-key/)" `
  "TOKEN_ENCRYPTION_KEYS=@Microsoft.KeyVault(SecretUri=$vault/token-encryption-keys/)" `
  "SCM_DO_BUILD_DURING_DEPLOYMENT=true"

# One worker with several threads: token refresh locks and pending sign-ins live in memory (see Limits).
az webapp config set -g $RG -n $APP --output none `
  --startup-file "gunicorn --bind=0.0.0.0 --timeout 120 --workers 1 --threads 8 wsgi:app"
```

If a Key Vault reference can't be resolved (identity not enabled, role missing, wrong name), App Service
passes the literal `@Microsoft.KeyVault(...)` text to the app. The app detects that and refuses to start
with `EGNYTE_CLIENT_SECRET still holds an unresolved Key Vault reference`; see the log stream.

Optional settings: `EGNYTE_SCOPE` (default `Egnyte.filesystem`), `EGNYTE_MAX_RPS` (default 2, shared by all
users), and `PERMISSION_TEST_FOLDER` (the Egnyte folder for the Permission test page, default
`/Shared/Teams/IT/Infrastructure/Azure App Test`).

**Where the tokens are kept.** On App Service the site needs `COSMOS_ENDPOINT` (the account's
`https://<account>.documents.azure.com:443/` address) and refuses to start without it; `COSMOS_DATABASE` (default
`egnyte-auth`) and `COSMOS_CONTAINER` (default `tokens`) name the container, which must already exist and be
partitioned on `/id`. [infra/main.bicep](../infra/main.bicep) creates all of that and sets the three settings. These are
addresses and names, not credentials: the site signs in with the web app's system-assigned managed identity, which
needs the data role *Cosmos DB Built-in Data Contributor* on that container (the Bicep assigns it). The connection is
opened on first use, so a mistake in this setup shows as an error page ("Token database unavailable (HTTP 403)")
and a log line, not as a site that won't start.

Running on your own PC without Cosmos DB: leave `COSMOS_ENDPOINT` unset and the site falls back to encrypted files
under `TOKEN_STORE_DIR` (default `./.egnyte-tokens`). That fallback is refused on App Service. To try the real
thing from your PC, set `COSMOS_ENDPOINT` to the account, run `az login`, and give your own user a Cosmos DB data role
(see [infra/README.md](../infra/README.md)).

## 6. Turn on Microsoft sign-in (required)

In the portal: your web app, **Settings, Authentication, Add identity provider, Microsoft**. Choose your
tenant, set **Restrict access: Require authentication** and **Unauthenticated requests: HTTP 302 redirect**.

**This step is a security requirement, not a convenience.** The app trusts the identity headers App Service
adds. They can only be trusted when authentication is on and set to *require* sign-in; otherwise anyone could
send those headers themselves and pretend to be someone else. To limit who can use it, set *Assignment
required* on the app's enterprise application in Entra and assign the testers.

Check it after deploying: an unauthenticated request must be redirected to the Microsoft login.

```powershell
curl.exe -sI https://$APP.azurewebsites.net/        # expect: HTTP 302 and a Location containing /.auth/login/
```

If `/healthz` is used for App Service health checks, exclude it from authentication or leave health checks off.

## 7. Deploy

```powershell
python web_app/package.py
az webapp deploy -g $RG -n $APP --src-path web_app/dist/egnyte-webapp.zip --type zip
az webapp log config -g $RG -n $APP --application-logging filesystem --level information
az webapp log tail -g $RG -n $APP
```

## The permission test

Open **Permission test** on the home page (or `/permissions`). The folder is the **`PERMISSION_TEST_FOLDER` app setting**
and defaults to `/Shared/Teams/IT/Infrastructure/Azure App Test`. Either slash style is accepted
(`\Shared\Teams\IT\...` is read as `/Shared/Teams/IT/...`), it must be at least two levels deep, and it is checked when the
app starts. To point it somewhere else, set the setting (or the `permissionTestFolder` parameter in
[infra/main.bicep](../infra/main.bicep), which sets it) and restart. The file name is fixed in
[permission_check.py](permission_check.py) (`FILE_BASENAME`, `CREATE_AS`).

- **What it shows:** whether the folder and file exist *for you*, the file's current contents, who last modified it,
  and the Egnyte account everything runs as.
- **Edit file** reads the file, adds a final line `edited by <the name you signed in to this site with>`, and uploads it
  again, so each edit is a new version in Egnyte's version history. Existing content is kept byte for byte.
- **Create file** creates `Text Test.txt` (containing `created by <you>`) only if no `Text Test` or `Text Test.txt`
  exists. It doesn't create the folder.
- **Delete file** deletes it.
- The file is found as `Text Test` or `Text Test.txt`, in any capitals, so it works whichever name it already has.
- **A refusal is shown, not hidden:** a person whose Egnyte account may not edit, create or delete in that folder sees
  `Egnyte refused: the Egnyte account <name> is not allowed to <action> files in <folder>`; someone who can't open the
  folder sees that explained on the page.
- It needs no new Egnyte permission: `Egnyte.filesystem`, which everyone already granted when connecting, covers
  reading, writing and deleting files.
- It is a read-then-write, so two people pressing *Edit* at the same instant can lose one line. Fine for a test.

## 8. Test with more than one user

1. Browser profile 1: open `https://<APP>.azurewebsites.net/`, sign in with Microsoft, press **Connect to
   Egnyte**, sign in to Egnyte and press **Allow**. You land back on the home page showing your Egnyte username.
2. Browser profile 2 (or a private window): do the same as a **different person**.
3. Both open `/folders?path=/Shared`. Each sees only what their own Egnyte account can open.
4. Person 2 opens `/folders?path=/Private/<person 1's Egnyte username>`: the site answers "not found in
   Egnyte", because Egnyte, not this app, refuses it.
5. **Disconnect** on one user: the other stays connected.

## What is and isn't verified

Verified by the test suite (`python -m unittest discover -s web_app/tests -v`, no network, no Azure, fake Egnyte):
each request uses only its own user's token; a sign-in `state` works once, only for the user who started it, and
expires; the secret and tokens never appear in pages, URLs or logs; tokens are encrypted before they reach the store
(a database reader sees only ciphertext and a hashed user id); disconnect needs a CSRF token; file names are escaped;
downloads are attachments; the packaged zip starts from a clean folder and uses its bundled `egnyte/`. The Cosmos DB
store is tested against a fake container that raises the Azure SDK's real exception types: a refusal, a failed
identity sign-in, a network failure or a missing container is an error page and **never** looks like "not connected"
(so an outage can't disconnect anyone), the credential is the managed identity and never a key, and a refreshed
token is written back.

**Not verified against the real services**, so expect to look at these on the first deployment:

- **The refresh grant.** Egnyte does return a `refresh_token` and a 30-day access token (confirmed on a real tenant),
  but no one has yet checked that Egnyte accepts `grant_type=refresh_token`, how long a refresh token lives, or whether
  it changes on use. If a refresh fails, the user is simply asked to connect again.
- **App Service Authentication's header format.** The app reads `X-MS-CLIENT-PRINCIPAL` (tenant id and object id
  claims) as documented, but it has only been tested with headers built to match. If `/` answers "Sign-in required"
  even when signed in, check what claims the header carries.
- **`WEBSITE_AUTH_ENABLED`.** The app logs a warning if that variable isn't `True` on App Service; confirm the check
  matches how your app reports it.
- **The Egnyte redirect.** `https://<APP>.azurewebsites.net/egnyte/callback` has to be accepted for your API key.
- **Cosmos DB with the real service.** The store has only been run against a fake container. On the first
  deployment check: that the managed identity can read and write (container-scoped data role; Microsoft documents
  container scope as supported, but this has not been seen working here), that the account firewall lets the app in
  (the template adds the web app's outbound addresses), and that a missing document reads as "not connected" rather
  than an error.

## Limits (fine for a test, change before production)

- **One worker, one instance.** Token refresh locks and in-flight sign-ins are in memory. Cosmos DB would let several
  instances share the tokens, but two instances could refresh the same user's token at the same moment, and the loser
  would be disconnected if Egnyte rotates refresh tokens. Before scaling out, add a lock or an ETag check around refresh,
  and move the in-flight sign-in states out of memory.
- **Tokens are Cosmos DB documents** (`id` = SHA-256 of `<tenant id>:<object id>`), encrypted by the app with Fernet before
  they are stored. Rotating the key: put the new key first in `TOKEN_ENCRYPTION_KEYS` (comma separated), keep the old
  one second; each user's document is re-encrypted the next time it is saved. Tokens kept in files by an earlier
  version are not copied over: each person connects to Egnyte once more.
- **One Egnyte API key serves everyone**, and Egnyte rate-limits per key. The site spaces all users' requests at
  `EGNYTE_MAX_RPS` (default 2 per second) across the whole process.
- **No check that the Egnyte account belongs to the Entra user.** The home page shows both side by side. Deciding
  how to match them (the Egnyte username is not always an email address) is still open.
- Downloads are capped at 25 MB and held in memory; listings show the first 500 entries.
- **Logs and the callback URL.** `/egnyte/callback?code=...&state=...` carries Egnyte's one-time code. It is useless once
  the app has exchanged it (a second use is refused), and the app itself never logs it, but web-server access logs
  record full URLs: don't add `--access-logfile` to the startup command, and treat App Service HTTP logging as
  sensitive if you turn it on.

## Running it on your PC

For looking at the pages and the permission behaviour. A stand-in sign-in replaces Microsoft sign-in and is
refused on App Service.

```powershell
python -m venv .venv ; .venv\Scripts\Activate.ps1
pip install -r web_app/requirements.txt
$env:ALLOW_DEV_USER = "1"
$env:EGNYTE_DOMAIN = "stout" ; $env:EGNYTE_CLIENT_ID = "<client id>"
$env:EGNYTE_REDIRECT_URI = "http://localhost:5000/egnyte/callback"
$env:KEY_VAULT_URL = "https://$KV.vault.azure.net"      # reads the three secrets after `az login`
cd web_app ; python -m flask --app wsgi run
# then open http://localhost:5000/dev/as/alice (and /dev/as/bob in another browser profile)
```

Egnyte's documentation says redirect URIs must be HTTPS, so connecting to Egnyte from `localhost` may not work.
The full sign-in is meant to be tested on the deployed site.

## Files

| File | Purpose |
|---|---|
| `app.py` | Routes, CSRF protection, security headers, error pages |
| `egnyte_access.py` | Builds a client from one user's token; refresh, disconnect on rejection, shared rate limit |
| `egnyte_oauth.py` | OAuth authorization-code and refresh helpers (adapted from `test_app/egnyte_oauth_login.py`) |
| `token_store.py` | Encrypted per-user tokens in Cosmos DB (managed identity; local files as a PC-only fallback); one-time sign-in states |
| `identity.py` | Reads the signed-in Entra user from App Service Authentication |
| `settings.py` | App Settings and Key Vault loading |
| `wsgi.py` | gunicorn entry point |
| `package.py` | Builds `dist/egnyte-webapp.zip` |
