# Infrastructure and deployment

A Bicep template that creates the Azure resources for the Egnyte per-user test site
([web_app/](../web_app/README.md)), and the commands to deploy it and the app from your own machine.

| | |
|---|---|
| Resource group | `rg-egnyte-test` |
| Web app | `egnyte-test` (Linux, Python), `https://egnyte-test.azurewebsites.net` |
| Region | North Central US (`northcentralus`) |
| Also created | App Service plan `plan-egnyte-test` (B1), Key Vault `kv-egnyte-test-<6 characters>` (Azure RBAC), the role that lets the web app read the vault, the app settings, Microsoft Entra sign-in, access restrictions that let only the networks in [allowed-ips.json](allowed-ips.json) reach the site |

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
```

Register the Egnyte redirect URI on your Egnyte API key, and check the Entra one is on the app registration.

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
  (`az keyvault purge --name <vault> --location northcentralus`), or wait 7 days.
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

**Not verified, because nothing has been deployed to a real subscription:** that Azure accepts the template as written,
in particular the `authsettingsV2` block (including the `sts.windows.net` issuer) and the Python 3.13 runtime in North
Central US (`az deployment group what-if` shows Azure's opinion before anything is created); and the PowerShell commands
above, which have only been syntax-checked.
