# Infrastructure and deployment

A Bicep template that creates the Azure resources for the Egnyte per-user test site
([web_app/](../web_app/README.md)), and the commands to deploy it and the app from your own machine.

| | |
|---|---|
| Resource group | `rg-egnyte-test` |
| Web app | `egnyte-test` (Linux, Python), `https://egnyte-test.azurewebsites.net` |
| Region | North Central US (`northcentralus`) |
| Also created | App Service plan `plan-egnyte-test` (B1), Key Vault `kv-egnyte-test-<6 characters>` (Azure RBAC), the role that lets the web app read the vault, the app settings, Microsoft Entra sign-in, access restrictions that let only the networks in [allowed-ips.json](allowed-ips.json) reach the site, and a Cosmos DB account `cosmos-egnyte-test-<6 characters>` (serverless, database `egnyte-auth`, container `tokens`) that holds each user's Egnyte tokens, with a data role for the web app's managed identity |

The Bicep is split into [main.bicep](main.bicep), which composes everything, and one module per responsibility under
[modules/](modules/): [cosmos-db.bicep](modules/cosmos-db.bicep) (account, database, container) and
[cosmos-data-access.bicep](modules/cosmos-data-access.bicep) (who may read and write the data).

The web app name must be globally unique. If `egnyte-test` is taken, deploy with `appName=<other name>`.

Deploying from GitHub Actions is **parked**, not removed: see [github-actions/README.md](github-actions/README.md).

## Before you start

- **Azure CLI**, signed in to the right subscription: `az login`, then `az account set --subscription <id or name>`.
- **Your account needs a role that can create role assignments on the resource group**: Owner is simplest
  (or Contributor plus User Access Administrator). The template grants the web app access to the vault, and
  Contributor alone can't do that.
- **A Microsoft Entra app registration for sign-in to the site.** Its client ID is the `entraClientId` default in
  `main.bicep`. It needs these settings (the Egnyte API key is a different thing):

  | Setting | Value |
  |---|---|
  | Supported account types | Single tenant |
  | Redirect URI (platform **Web**) | `https://egnyte-test.azurewebsites.net/.auth/login/aad/callback` |
  | Authentication, Implicit grant and hybrid flows | **ID tokens** ticked |
  | Certificates & secrets | a client secret: copy its **Value** (not the Secret ID); it expires, so note the date |

- **The Egnyte client ID** is the `egnyteClientId` default in `main.bicep`. Its secret goes in the vault below.

## Network access

Only the networks in [allowed-ips.json](allowed-ips.json) can reach the web app, and the template refuses everyone
else. The file lists your corporate firewall and the Prisma VPN addresses, one entry each:

```json
{ "priority": 500, "name": "Palo FW CSP NAT", "ipAddress": "65.52.58.84/32" }
```

`main.bicep` turns every entry into an App Service access restriction (`Allow`, same name and priority) with a default
of `Deny`, so a request from any other address gets a 403 before it reaches the app or Microsoft sign-in. Priorities must
be unique (lower is checked first). To change the list, edit the JSON file and repeat step 1 of *Deploy*. The file is
the single source of truth, so other resources that have an allow list can load the same file.

What this means in practice:

- **People must be on the VPN** to use the site, and so must you for the checks in step 5: from any other network
  every request, including `/healthz`, is answered with a 403.
- **The deployment site follows the same list** (`scmIpSecurityRestrictionsUseMain`), so `az webapp deploy` and
  `az webapp log download` only work from an allowed network. Deploying the template itself still works from
  anywhere, because that goes through Azure Resource Manager, not the site.
- **GitHub-hosted runners are not on the list**, so the parked Actions workflow could not deploy the zip. It would need a
  self-hosted runner on an allowed address.
- **Egnyte and Microsoft sign-in are unaffected**: they redirect the person's own browser back to the site, which is
  on the VPN, and neither calls the site directly.

To see what Azure has applied: `az webapp config access-restriction show --resource-group rg-egnyte-test --name egnyte-test`.

### The Cosmos DB firewall

The same list protects the Cosmos DB account, with two differences:

- **The web app's own outbound addresses are added.** They are not on your list, and without them the app would be locked
  out of its own database (its calls to Cosmos DB come from App Service, not from the VPN). `main.bicep` reads them from
  the web app (`outboundIpAddresses` and `possibleOutboundIpAddresses`; 31 addresses on the current B1 plan, 80 rules in
  all). App Service picks one of them at random for each connection, and the set can change when the plan changes tier, so
  **redeploy the template after changing the plan size** to refresh the list. On a Premium v4 plan these properties are
  empty and the template can't do this: use VNet integration instead.
- **Cosmos DB takes plain addresses**, so the template drops the `/32`. Ranges in `10.0.0.0/8`, `100.64.0.0/10`,
  `172.16.0.0/12` and `192.168.0.0/16` can't be enforced by Cosmos DB, and a test fails if one is added to the list.

Firewall changes take up to about 15 minutes to apply. If the site reports "Token database unavailable (HTTP 403)", the log
line (`az webapp log tail`) carries Cosmos DB's own explanation, which will be about either the account firewall or
missing RBAC permissions, and tells you which of the two to fix. You can also reach the data through the portal's Data
Explorer only from an allowed address and only with a data role of your own (below).

Authentication is Microsoft Entra only: the account has no keys and no connection strings (`disableLocalAuth`), so
nothing can be copied out of it or leaked. Azure roles such as Owner and Contributor give **no** access to the data; only
Cosmos DB data roles do.

## Deploy

PowerShell, from the repository root.

**1. Create the resource group and the infrastructure.**

```powershell
az group create --name rg-egnyte-test --location northcentralus

# Optional: see what Azure would create before it does.
az deployment group what-if --resource-group rg-egnyte-test --template-file infra/main.bicep

$out  = az deployment group create --resource-group rg-egnyte-test --template-file infra/main.bicep `
          --query properties.outputs --output json | ConvertFrom-Json
$KV   = $out.keyVaultName.value
$SITE = $out.hostName.value
"Key Vault:           $KV"
"Site:                https://$SITE"
"Egnyte redirect URI: $($out.egnyteRedirectUri.value)"
"Entra redirect URI:  $($out.entraRedirectUri.value)"
"Cosmos DB:           $($out.cosmosAccountName.value)"
```

Register the Egnyte redirect URI on your Egnyte API key, and check the Entra one is on the app registration.

The first deployment that adds Cosmos DB takes several minutes longer than before (creating the account, then its firewall).
If it fails on the data role and the message is about the principal (the web app's new identity), the identity had not
finished replicating through Entra yet: run the same command again. If Azure answers that the region has "high demand" for new Cosmos DB accounts, deploy with
`cosmosLocation=<another region>` (the web app can stay where it is).

Tokens that people stored before this change (in files on the web app) are not copied across: each person connects to
Egnyte once more.

**Optional: look at the data.** The app's tokens are encrypted, so you will only see ids and timestamps, but to open
the container in the portal's Data Explorer or from your PC you need a data role of your own (Owner is not enough):

```powershell
az cosmosdb sql role assignment create --account-name $out.cosmosAccountName.value --resource-group rg-egnyte-test `
  --role-definition-id 00000000-0000-0000-0000-000000000001 `
  --principal-id (az ad signed-in-user show --query id --output tsv) `
  --scope "/dbs/egnyte-auth/colls/tokens"
```

(`...0001` is *Cosmos DB Built-in Data Reader*; the app uses `...0002`, *Data Contributor*. List what the account offers
with `az cosmosdb sql role definition list`.) A person's document id is the SHA-256 hash of `<tenant id>:<object id>`, so
to find or delete one: `python -c "import hashlib; print(hashlib.sha256(b'<tenant>:<oid>').hexdigest())"`.

**2. Give yourself access to the vault's secrets.** The vault uses Azure RBAC, so even an Owner can't read or write
secrets until given a data role. It can take a minute or two to apply.

```powershell
az role assignment create --role "Key Vault Secrets Officer" `
  --assignee-object-id (az ad signed-in-user show --query id --output tsv) --assignee-principal-type User `
  --scope (az keyvault show --name $KV --query id --output tsv) --output none
```

**3. Put the four secrets in the vault.** Two are generated, and only if they don't exist yet. Never replace
`token-encryption-keys` once users have connected: a new key makes every stored Egnyte token unreadable.

```powershell
# Generated: created only when missing.
$generated = @{
  "flask-secret-key"      = "import secrets; print(secrets.token_urlsafe(48))"
  "token-encryption-keys" = "import base64, os; print(base64.urlsafe_b64encode(os.urandom(32)).decode())"
}
foreach ($name in $generated.Keys) {
  az keyvault secret show --vault-name $KV --name $name --query id --output tsv 2>$null | Out-Null
  if ($LASTEXITCODE -eq 0) { "$name already exists; left alone"; continue }
  az keyvault secret set --vault-name $KV --name $name --output none --value (python -c $generated[$name])
  "$name created"
}

# Yours: typed at a hidden prompt, passed through a temporary file, never shown or kept in shell history.
function Set-VaultSecret($name) {
  $secure = Read-Host "Value for $name" -AsSecureString
  $path   = Join-Path $env:TEMP "$name.txt"
  [System.Net.NetworkCredential]::new("", $secure).Password | Set-Content -NoNewline -Path $path
  az keyvault secret set --vault-name $KV --name $name --file $path --output none
  Remove-Item $path
}
Set-VaultSecret "egnyte-client-secret"
Set-VaultSecret "entra-client-secret"
```

The script `infra/scripts/ensure-generated-secrets.sh` does the generated half too, and also keeps the values off the
command line. Run it from Git Bash or WSL with `KEY_VAULT_NAME=$KV`.

Check they are all there (this prints names, never values):

```powershell
foreach ($name in "egnyte-client-secret", "entra-client-secret", "flask-secret-key", "token-encryption-keys") {
  az keyvault secret show --vault-name $KV --name $name --query id --output tsv 2>$null | Out-Null
  "{0,-24} {1}" -f $name, $(if ($LASTEXITCODE -eq 0) { "present" } else { "MISSING" })
}
```

**4. Build and deploy the app.**

```powershell
python web_app/package.py
az webapp deploy --resource-group rg-egnyte-test --name egnyte-test `
  --src-path web_app/dist/egnyte-webapp.zip --type zip --clean true
```

Key Vault references are read when the app starts. If the site reports an unresolved Key Vault reference (the secrets
were created after the app settings), run `az webapp restart --resource-group rg-egnyte-test --name egnyte-test`.

**5. Check it** (from the VPN: any other network gets a 403 from the access restrictions).

```powershell
curl.exe -s -o NUL -w "healthz:                       %{http_code}`n" "https://$SITE/healthz"   # expect 200
curl.exe -s -o NUL -w "/ without signing in:           %{http_code}`n" "https://$SITE/"          # expect 302 (or 401/403), never 200
az webapp log tail --resource-group rg-egnyte-test --name egnyte-test
```

An anonymous `/` that answers **200 means sign-in is not protecting the site**, and the app trusts the identity
headers that sign-in adds. Don't use the site until that answers 302. `bash infra/scripts/smoke-test.sh "https://$SITE"`
runs the same two checks, with retries while the site starts.

To change the infrastructure, edit `main.bicep` and repeat step 1. To change only the app, repeat step 4.

## Things to know

- **Bicep owns the app settings.** A setting added by hand in the portal is removed by the next deployment.
- **Secrets are Key Vault references** (`@Microsoft.KeyVault(SecretUri=...)`), so no secret value appears in the
  template, the parameters or the logs. They have no version in the URI, so a rotated secret is picked up (after a
  restart, or within about a day).
- **One instance only.** The app keeps token-refresh locks and pending sign-ins in memory, so the plan is sized for one
  instance and gunicorn runs one worker. See *Limits* in [web_app/README.md](../web_app/README.md).
- **HTTP logs are off on purpose**: they record full URLs, and the sign-in callback URL carries Egnyte's one-time code.
  Application logs are on (`az webapp log tail`).
- **The Entra client secret expires** (one year by default), and sign-in to the site stops when it does. To rotate,
  create a new secret on the app registration and store its value under the same Key Vault name.
- **Tearing down**: `az group delete --name rg-egnyte-test`. The Key Vault name is derived from the resource group, so a
  vault deleted this way is only soft-deleted: purge it before recreating the group
  (`az keyvault purge --name <vault> --location northcentralus`), or wait 7 days. The Cosmos DB account goes with the
  group, and every stored token with it (there is no soft delete like the vault's to bring it back).
- **Cosmos DB is serverless** (`serverless` parameter of [modules/cosmos-db.bicep](modules/cosmos-db.bicep)): you pay per
  request instead of for reserved throughput, which suits a test site. Per Microsoft, the capacity mode can't be
  changed after the account is created.
- The B1 plan bills while it exists. Delete the resource group when the test is over.

## Checking changes

```powershell
az bicep build --file infra/main.bicep --stdout > $null      # compile and lint
python -m unittest discover -s infra/tests -v                # the script tests (needs bash; Git Bash on Windows)
```

## What has and hasn't been verified

Verified: the template compiles with no linter warnings and every parameter has a default; the three scripts pass their
tests against a fake `az` and `curl` (existing secrets are never replaced, values never reach a command line or the
terminal, retries while role assignments propagate, the smoke test fails on an unprotected site); the Azure CLI flags
used here exist in the installed CLI.

**Cosmos DB, verified:** the template compiles with no warnings; `az deployment group what-if` against `rg-egnyte-test`
accepted it (serverless account with local authentication and key-based metadata writes off, database, partitioned
container, the three `COSMOS_*` settings); the web app reports the outbound addresses the firewall list is built from;
[tests/test_cosmos_infra.py](tests/test_cosmos_infra.py) keeps the template and the app agreeing and fails if a key or
connection string ever appears. **Not verified, because it has not been deployed:** the data role assignment (`what-if`
can't analyse it: its name depends on the web app's identity), that a role scoped to one container is enough for the
Python SDK (Microsoft documents container scope; widen `scope` in
[cosmos-data-access.bicep](modules/cosmos-data-access.bicep) to the database or account if the log shows an RBAC
error), and that the firewall lets the app in.

**Not verified, because nothing has been deployed to a real subscription:** that Azure accepts the template as written,
in particular the `authsettingsV2` block (including the `sts.windows.net` issuer) and the Python 3.13 runtime in North
Central US (`az deployment group what-if` shows Azure's opinion before anything is created); and the PowerShell commands
above, which have only been syntax-checked.
