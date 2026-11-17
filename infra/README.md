# Infrastructure and deployment

Bicep plus a GitHub Actions workflow that deploy the Egnyte per-user test site ([web_app/](../web_app/README.md))
to Azure:

| | |
|---|---|
| Resource group | `rg-egnyte-test` |
| Web app | `egnyte-test` (Linux, Python), `https://egnyte-test.azurewebsites.net` |
| Region | North Central US (`northcentralus`) |
| Also created | App Service plan `plan-egnyte-test` (B1), Key Vault `kv-egnyte-test-<6 characters>` (Azure RBAC), the role assignments between them, the app settings, Microsoft Entra sign-in |

The web app name must be globally unique. If `egnyte-test` is taken, change `APP_NAME` in
[the workflow](../.github/workflows/deploy-egnyte-test.yml) (and the default in `main.bicep`).

## What the pipeline does

`.github/workflows/deploy-egnyte-test.yml`

```
pull request:   test ─┬─ package
                validate-infra

master / manual: test ──┬─ package ─────────────────────────────┐
                 validate-infra ─ infrastructure ──────────────┴─ deploy
                                  (Bicep, generated secrets)       (secret check, zip deploy, smoke test)
```

- **test**: runs the web app's tests on Linux.
- **validate-infra**: compiles and lints `main.bicep`; tests the shell scripts with a fake `az` and `curl`.
- **package**: builds `egnyte-webapp.zip` with `web_app/package.py` (the app plus the bundled `egnyte/` library).
- **infrastructure**: signs in to Azure, creates the resource group if it is missing, deploys `main.bicep`, then creates
  the two secrets that are generated (`flask-secret-key`, `token-encryption-keys`) **only if they don't exist yet**.
  An existing encryption key is never replaced: that would make every stored Egnyte token unreadable.
- **deploy**: stops with instructions if the two secrets a person has to provide are missing, deploys the zip,
  then smoke-tests the site.

The smoke test waits for `/healthz` to answer 200 and then checks that `/` **without a sign-in** is *not* served
(302, 401 or 403). The app trusts the identity headers that App Service Authentication adds, so a site that answers
200 to an anonymous request fails the deployment.

No secret is stored in GitHub. Azure sign-in uses OpenID Connect (a short-lived token GitHub issues per run), and
secret values only ever exist in Key Vault.

## One-time setup

### 1. A repository you can push to

This checkout's `origin` is the upstream `egnyte/python-egnyte`, which you can't push to. Push to a fork or a new
repository. Note that upstream's own `linter-and-tests.yml` also runs there on every push and needs Egnyte secrets
your repository won't have; delete or disable that workflow in your copy.

### 2. Let GitHub sign in to Azure

Replace `<OWNER>/<REPO>` with your repository.

```powershell
$SUB    = az account show --query id -o tsv
$TENANT = az account show --query tenantId -o tsv
$CLIENT = az ad app create --display-name "github-egnyte-test-deploy" --query appId -o tsv
az ad sp create --id $CLIENT --output none

# Trust runs of the workflow that use the "egnyte-test" GitHub environment (both Azure jobs do).
@'
{ "name": "github-egnyte-test",
  "issuer": "https://token.actions.githubusercontent.com",
  "subject": "repo:<OWNER>/<REPO>:environment:egnyte-test",
  "audiences": ["api://AzureADTokenExchange"] }
'@ | Set-Content -Path "$env:TEMP\federated-credential.json"
az ad app federated-credential create --id $CLIENT --parameters "$env:TEMP\federated-credential.json"

# The resource group, and two roles on it (and only on it).
az group create --name rg-egnyte-test --location northcentralus
$SCOPE = "/subscriptions/$SUB/resourceGroups/rg-egnyte-test"
az role assignment create --assignee $CLIENT --role "Contributor" --scope $SCOPE
az role assignment create --assignee $CLIENT --role "Role Based Access Control Administrator" --scope $SCOPE

"AZURE_CLIENT_ID=$CLIENT"; "AZURE_TENANT_ID=$TENANT"; "AZURE_SUBSCRIPTION_ID=$SUB"   # for step 4
```

*Contributor* creates the resources. *Role Based Access Control Administrator* is needed because the template creates
role assignments (the web app and the pipeline get access to Key Vault); Contributor can't do that. If you create the
resource group yourself as above, the pipeline needs no rights outside it.

### 3. The Microsoft Entra app registration for sign-in to the site

In the Entra admin center, **App registrations, New registration**:

1. Name `egnyte-test-site`, **Single tenant**, redirect URI type **Web**:
   `https://egnyte-test.azurewebsites.net/.auth/login/aad/callback`
2. **Authentication**: tick **ID tokens** under *Implicit grant and hybrid flows*, and save.
3. **Certificates & secrets, New client secret**. Keep the value for step 6; you only see it once.
4. Copy the **Application (client) ID**: that is `ENTRA_CLIENT_ID` below.
5. Optional but sensible: on the matching *Enterprise application*, set **Assignment required** to *Yes* and assign the
   people who should test.

This is a different registration from the Egnyte API key. It only signs people in to the site.

### 4. The GitHub environment and its variables

**Settings, Environments, New environment: `egnyte-test`**. Add these as **variables** (none of them are secrets):

| Variable | Value |
|---|---|
| `AZURE_CLIENT_ID`, `AZURE_TENANT_ID`, `AZURE_SUBSCRIPTION_ID` | from step 2 |
| `EGNYTE_CLIENT_ID` | your Egnyte API key (client ID) |
| `ENTRA_CLIENT_ID` | from step 3 |
| `EGNYTE_DOMAIN` | optional; defaults to `stout` |

You can also add *Required reviewers* on the environment to make each deployment wait for approval.

### 5. Egnyte

After the first run, register the redirect URI the deployment prints in its summary on your Egnyte API key:
`https://egnyte-test.azurewebsites.net/egnyte/callback`.

### 6. First run, and the two secrets only you can supply

Run **Actions, Deploy egnyte-test, Run workflow**. The first run creates everything and then stops in *deploy* with an
error naming the missing Key Vault secrets. That is expected. Add them, then use **Re-run failed jobs**:

| Secret name | Value |
|---|---|
| `egnyte-client-secret` | the client secret of your Egnyte API key |
| `entra-client-secret` | the client secret from step 3 |

In the portal: Key Vault, **Secrets, Generate/Import**, with exactly those names. Or with the CLI, from a file that
holds only the secret (this needs the *Key Vault Secrets Officer* role on the vault for your own account):

```powershell
$KV = "<vault name from the deployment summary>"
az role assignment create --role "Key Vault Secrets Officer" --assignee-object-id (az ad signed-in-user show --query id -o tsv) `
  --assignee-principal-type User --scope (az keyvault show --name $KV --query id -o tsv)
az keyvault secret set --vault-name $KV --name egnyte-client-secret --file .\egnyte-secret.txt --output none
az keyvault secret set --vault-name $KV --name entra-client-secret  --file .\entra-secret.txt  --output none
```

After that, every push to `master` that touches `infra/`, `web_app/` or `egnyte/` redeploys.

## Things to know

- **Bicep owns the app settings.** A setting added by hand in the portal is removed by the next deployment.
- **Secrets are Key Vault references** (`@Microsoft.KeyVault(SecretUri=...)`), so no secret value appears in the
  template, the parameters or the logs. They have no version in the URI, so a rotated secret is picked up.
- **One instance only.** The app keeps token-refresh locks and pending sign-ins in memory, so the plan is sized for one
  instance and gunicorn runs one worker. See *Limits* in [web_app/README.md](../web_app/README.md).
- **HTTP logs are off on purpose**: they record full URLs, and the sign-in callback URL carries Egnyte's one-time code.
  Application logs are on: `az webapp log tail --resource-group rg-egnyte-test --name egnyte-test`.
- **Tearing down**: `az group delete --name rg-egnyte-test`. The Key Vault name is derived from the resource group, so a
  vault deleted this way is only soft-deleted: purge it before recreating the group
  (`az keyvault purge --name <vault> --location northcentralus`), or wait 7 days.
- The B1 plan bills while it exists. Delete the resource group when the test is over.

## Checking changes locally

```powershell
az bicep build --file infra/main.bicep --stdout > $null          # compile and lint
python -m unittest discover -s infra/tests -v                    # the script tests (needs bash; Git Bash on Windows)
```

## What has and hasn't been verified

Verified here: the template compiles with no linter warnings; the workflow validates against GitHub's workflow schema
and every `run:` block passes a bash syntax check; the Azure CLI flags it uses exist in the installed CLI; the four scripts
pass 20 tests against a fake `az` and `curl` (existing secrets are never replaced, values never reach a command line or
the log, retries while role assignments propagate, the smoke test fails on an unprotected site).

**Not verified, because nothing has been deployed to a real subscription:**

- That Azure accepts the template as written: in particular the `authsettingsV2` block (including the
  `sts.windows.net` issuer) and the Python 3.13 runtime in North Central US. Run `az deployment group what-if` against the
  resource group first if you want to see Azure's own opinion before anything is created.
- That 12 attempts, 15 seconds apart (3 minutes), is always enough for the new Key Vault role assignment to take effect.
  If a run fails on that, re-run the failed job.
- That the web app tests, which so far have only run on Windows, pass on the Linux runner.
- GitHub actions are pinned to major versions (`@v4`), not to commit SHAs. Pin them by SHA if your policy requires it.
