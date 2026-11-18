# GitHub Actions deployment (parked)

The workflow here deploys the infrastructure and the app from GitHub Actions. It is **parked**: it sits outside
`.github/workflows`, so GitHub doesn't run it, and `infra/main.bicep` no longer has the parts it needs. Deployment is
done from a local machine for now ([../README.md](../README.md)).

| File | Purpose |
|---|---|
| `deploy-egnyte-test.yml` | The workflow: test, validate the Bicep, package, deploy the infrastructure, deploy the app, smoke test |
| `principal-object-id.sh` | Reads the object ID of the identity the pipeline is signed in as; the template needs it |

## To switch it back on

**1. Put these back into `infra/main.bicep`.** The pipeline's identity needs to write the generated secrets.

```bicep
@description('Object ID of the identity that deploys this template (the GitHub Actions service principal). It gets the Key Vault Secrets Officer role so the pipeline can create the generated secrets.')
param deployerPrincipalId string

// next to the keyVaultSecretsUser variable
var keyVaultSecretsOfficer = 'b86a8fe4-44ce-4948-aee5-eccb2c155cd7'

// after the appCanReadSecrets role assignment
resource deployerCanWriteSecrets 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  scope: vault
  name: guid(vault.id, deployerPrincipalId, keyVaultSecretsOfficer)
  properties: {
    roleDefinitionId: subscriptionResourceId('Microsoft.Authorization/roleDefinitions', keyVaultSecretsOfficer)
    principalId: deployerPrincipalId
    principalType: 'ServicePrincipal'
  }
}
```

The parameter has no default on purpose: the workflow always supplies it. A local deployment then has to pass it too
(`deployerPrincipalId=<object id>`).

**2. Move the workflow back:** `infra/github-actions/deploy-egnyte-test.yml` to `.github/workflows/`, and remove the
"PARKED" note at its top.

**3. One-time Azure and GitHub setup.** Replace `<OWNER>/<REPO>` with a repository you can push to. This checkout's `origin`
is the upstream `egnyte/python-egnyte`, which you can't, and upstream's own `linter-and-tests.yml` would also run in a
copy of it and fail without upstream's secrets.

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

$SCOPE = "/subscriptions/$SUB/resourceGroups/rg-egnyte-test"
az role assignment create --assignee $CLIENT --role "Contributor" --scope $SCOPE
az role assignment create --assignee $CLIENT --role "Role Based Access Control Administrator" --scope $SCOPE
"AZURE_CLIENT_ID=$CLIENT"; "AZURE_TENANT_ID=$TENANT"; "AZURE_SUBSCRIPTION_ID=$SUB"
```

In GitHub, create the environment **`egnyte-test`** (**Settings, Environments**) with these **variables** (none are secrets):
`AZURE_CLIENT_ID`, `AZURE_TENANT_ID`, `AZURE_SUBSCRIPTION_ID` (from above), `EGNYTE_CLIENT_ID`, `ENTRA_CLIENT_ID`, and
optionally `EGNYTE_DOMAIN` (default `stout`).

**4. First run.** The workflow creates the infrastructure and the two generated secrets, then stops in *deploy* until
`egnyte-client-secret` and `entra-client-secret` are in the vault. Add them (README step 3), then use **Re-run failed jobs**.

## Differences since this was written

- **The web app now only accepts the networks in `infra/allowed-ips.json`, and so does its deployment (Kudu) site.**
  GitHub-hosted runners aren't on that list, so this workflow's *deploy* job would be refused with a 403. Use a
  self-hosted runner on an allowed address, or add the runners' addresses to the list (they change often).

- The shell scripts no longer print GitHub annotations (`::error::`, `::add-mask::`). Errors are plain `ERROR:` lines on
  stderr, so the workflow still fails correctly but without red annotations, and no mask command is needed because the scripts
  never print a secret.
- The workflow's `require-secrets.sh` failure text no longer mentions re-running a workflow.
- The tests for `principal-object-id.sh` (reads the `oid`, hides the token, fails without an `oid`) were removed when it
  was parked. Add them back if you use it again.
- The workflow was validated against GitHub's workflow schema, but it has never run.
