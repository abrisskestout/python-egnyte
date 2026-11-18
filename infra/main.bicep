// Infrastructure for the Egnyte per-user test site (web_app/).
//
// Deploys into an existing resource group:
//   resource group  rg-egnyte-test   (create it first: az group create --name rg-egnyte-test --location northcentralus)
//   app             egnyte-test      -> https://egnyte-test.azurewebsites.net
//   location        North Central US
//
// What it creates: a Linux App Service plan, the web app (system-assigned identity, HTTPS only), a Key Vault
// that uses Azure RBAC, the role assignments that let the app read secrets from it, the app settings (secrets
// are Key Vault references, so no secret value ever appears in this template, its parameters or the logs),
// Microsoft Entra sign-in (App Service Authentication, "Require authentication"), and a Cosmos DB for NoSQL
// account (modules/cosmos-db.bicep) where the app keeps each user's Egnyte tokens. Cosmos DB has local
// authentication switched off: there are no keys or connection strings, the app reaches it only through its
// managed identity, which is given a data role on the one container (modules/cosmos-data-access.bicep).
//
// Secret VALUES are not created here. Put these four in the vault after deploying (see infra/README.md):
//   flask-secret-key, token-encryption-keys   generated once by infra/scripts/ensure-generated-secrets.sh
//   egnyte-client-secret, entra-client-secret  yours to supply
// The identity that deploys needs a role that can create role assignments (Owner, or User Access Administrator /
// Role Based Access Control Administrator) on the resource group, because this template grants the web app access
// to the vault.

targetScope = 'resourceGroup'

@description('Web app name. It becomes <name>.azurewebsites.net, so it must be globally unique.')
@minLength(3)
@maxLength(40)
param appName string = 'egnyte-test'

@description('Azure region.')
param location string = 'northcentralus'

@description('App Service plan size. The app is built for ONE instance (see web_app/README.md, Limits).')
param skuName string = 'B1'

@description('Python version for the Linux web app. Check `az webapp list-runtimes --os linux` for what is offered.')
param pythonVersion string = '3.13'

@description('Your Egnyte domain: stout means stout.egnyte.com.')
param egnyteDomain string = 'stout'

@description('The Egnyte API key (client ID). It is not secret, so it is an ordinary app setting.')
param egnyteClientId string = 'K0eHAXplxpocUex3XX84mddMnMh5PsnHDXbHhPGMVt0U65FQ'

@description('Egnyte permissions the app asks each user for.')
param egnyteScope string = 'Egnyte.filesystem'

@description('The Egnyte folder the Permission test page works in (forward slashes). The same default is in web_app/settings.py.')
param permissionTestFolder string = '/Shared/Teams/IT/Infrastructure/Azure App Test'

@description('Client ID of the Microsoft Entra app registration used for sign-in to the site (not the Egnyte key).')
param entraClientId string = 'dc1b375f-e9eb-42e3-b126-7a2de72e73be'

@description('Azure region for the Cosmos DB account. Defaults to the web app region; change it if that region has no capacity for new Cosmos DB accounts.')
param cosmosLocation string = location

@description('Cosmos DB database that holds the app\'s data. The same default is in web_app/settings.py.')
param cosmosDatabaseName string = 'egnyte-auth'

@description('Cosmos DB container with one encrypted token document per user. The same default is in web_app/settings.py.')
param cosmosContainerName string = 'tokens'

@description('Resource tags.')
param tags object = {
  app: appName
  purpose: 'egnyte-per-user-test'
}

var planName = 'plan-${appName}'
var vaultName = toLower('kv-${take(appName, 12)}-${take(uniqueString(resourceGroup().id), 6)}')
var cosmosAccountName = toLower('cosmos-${take(appName, 20)}-${take(uniqueString(resourceGroup().id), 6)}')
var secretUriBase = '${vault.properties.vaultUri}secrets/'

// Networks allowed to reach the web app: [{ priority, name, ipAddress }], kept in one file so that other resources
// can reuse the same list (see infra/README.md, Network access).
var allowedIps = loadJsonContent('allowed-ips.json')

// Addresses allowed through the Cosmos DB firewall: the same networks as the web app (so people on the VPN can use
// Data Explorer), PLUS every outbound address the web app can use. Without the second part the app would be
// locked out of its own database, because its outbound addresses are not on the list. Cosmos DB takes plain
// addresses, so the "/32" is dropped. App Service picks one outbound address at random per connection and the set
// can change when the plan changes tier, so a redeployment refreshes it (see infra/README.md, Network access).
var webAppOutboundIps = filter(split('${webApp.properties.outboundIpAddresses},${webApp.properties.possibleOutboundIpAddresses}', ','), ip => !empty(ip))
var cosmosAllowedIps = union(map(allowedIps, rule => replace(rule.ipAddress, '/32', '')), webAppOutboundIps)

// Built-in role definition: Key Vault Secrets User
var keyVaultSecretsUser = '4633458b-17de-408a-b874-0445c86b69e6'

resource plan 'Microsoft.Web/serverfarms@2023-12-01' = {
  name: planName
  location: location
  tags: tags
  kind: 'linux'
  sku: {
    name: skuName
  }
  properties: {
    reserved: true // Linux
  }
}

resource vault 'Microsoft.KeyVault/vaults@2023-07-01' = {
  name: vaultName
  location: location
  tags: tags
  properties: {
    tenantId: tenant().tenantId
    sku: {
      family: 'A'
      name: 'standard'
    }
    enableRbacAuthorization: true
    enableSoftDelete: true
    softDeleteRetentionInDays: 7 // the minimum; the name stays reserved this long after a delete
    publicNetworkAccess: 'Enabled'
  }
}

resource webApp 'Microsoft.Web/sites@2023-12-01' = {
  name: appName
  location: location
  tags: tags
  kind: 'app,linux'
  identity: {
    type: 'SystemAssigned'
  }
  properties: {
    serverFarmId: plan.id
    httpsOnly: true
    clientAffinityEnabled: false
    siteConfig: {
      linuxFxVersion: 'PYTHON|${pythonVersion}'
      // One worker with threads: token refresh locks and pending sign-ins live in memory.
      appCommandLine: 'gunicorn --bind=0.0.0.0 --timeout 120 --workers 1 --threads 8 wsgi:app'
      numberOfWorkers: 1
      alwaysOn: true
      http20Enabled: true
      minTlsVersion: '1.2'
      ftpsState: 'Disabled'
      healthCheckPath: '/healthz'
      // Access restrictions: only the listed networks may reach the site, and everything else is refused (403).
      // This covers browsers, so people have to be on the VPN to use the site.
      ipSecurityRestrictions: [for rule in allowedIps: {
        name: rule.name
        priority: rule.priority
        action: 'Allow'
        ipAddress: rule.ipAddress
        description: 'Allowed network (infra/allowed-ips.json)'
      }]
      ipSecurityRestrictionsDefaultAction: 'Deny'
      // The deployment (Kudu/SCM) site follows the same list, so zip deployments must also come from these networks.
      scmIpSecurityRestrictionsUseMain: true
    }
  }
}

// The app's identity may read secrets, and nothing else in the vault.
resource appCanReadSecrets 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  scope: vault
  name: guid(vault.id, webApp.id, keyVaultSecretsUser)
  properties: {
    roleDefinitionId: subscriptionResourceId('Microsoft.Authorization/roleDefinitions', keyVaultSecretsUser)
    principalId: webApp.identity.principalId
    principalType: 'ServicePrincipal'
  }
}

// Where the app keeps each user's Egnyte tokens. Entra-only: no keys, no connection strings.
module cosmos 'modules/cosmos-db.bicep' = {
  name: 'cosmos-db'
  params: {
    accountName: cosmosAccountName
    location: cosmosLocation
    tags: tags
    databaseName: cosmosDatabaseName
    containerName: cosmosContainerName
    allowedIpAddresses: cosmosAllowedIps
  }
}

// The app's managed identity may read and write items in that one container, and nothing else in the account.
module cosmosAccess 'modules/cosmos-data-access.bicep' = {
  name: 'cosmos-data-access'
  params: {
    accountName: cosmos.outputs.accountName
    databaseName: cosmos.outputs.databaseName
    containerName: cosmos.outputs.containerName
    principalId: webApp.identity.principalId
  }
}

// Bicep owns ALL app settings: anything added by hand in the portal is removed by the next deployment.
resource appSettings 'Microsoft.Web/sites/config@2023-12-01' = {
  parent: webApp
  name: 'appsettings'
  properties: {
    EGNYTE_DOMAIN: egnyteDomain
    EGNYTE_CLIENT_ID: egnyteClientId
    EGNYTE_SCOPE: egnyteScope
    PERMISSION_TEST_FOLDER: permissionTestFolder
    EGNYTE_REDIRECT_URI: 'https://${webApp.properties.defaultHostName}/egnyte/callback'
    // Cosmos DB: where to find the token store. These are addresses and names, not credentials: the app signs in to
    // Cosmos DB with its managed identity.
    COSMOS_ENDPOINT: cosmos.outputs.endpoint
    COSMOS_DATABASE: cosmos.outputs.databaseName
    COSMOS_CONTAINER: cosmos.outputs.containerName
    // Key Vault references: App Service reads these with the app's identity and passes the values on as
    // ordinary environment variables. The URIs have no version, so a rotated secret is picked up.
    EGNYTE_CLIENT_SECRET: '@Microsoft.KeyVault(SecretUri=${secretUriBase}egnyte-client-secret/)'
    FLASK_SECRET_KEY: '@Microsoft.KeyVault(SecretUri=${secretUriBase}flask-secret-key/)'
    TOKEN_ENCRYPTION_KEYS: '@Microsoft.KeyVault(SecretUri=${secretUriBase}token-encryption-keys/)'
    MICROSOFT_PROVIDER_AUTHENTICATION_SECRET: '@Microsoft.KeyVault(SecretUri=${secretUriBase}entra-client-secret/)'
    // Install requirements.txt when the zip is deployed.
    SCM_DO_BUILD_DURING_DEPLOYMENT: 'true'
  }
  dependsOn: [
    appCanReadSecrets
    cosmosAccess // the data role exists before the app is pointed at the database
  ]
}

// Application logs to the file system (az webapp log tail). HTTP logs stay off: they record full URLs, and the
// sign-in callback URL carries Egnyte's one-time code.
resource logs 'Microsoft.Web/sites/config@2023-12-01' = {
  parent: webApp
  name: 'logs'
  properties: {
    applicationLogs: {
      fileSystem: {
        level: 'Information'
      }
    }
    httpLogs: {
      fileSystem: {
        enabled: false
      }
    }
  }
}

// Microsoft Entra sign-in. The app trusts the identity headers App Service adds, which is only safe while
// authentication is required for every request, so this is part of the template and not an optional extra.
resource authSettings 'Microsoft.Web/sites/config@2023-12-01' = {
  parent: webApp
  name: 'authsettingsV2'
  properties: {
    platform: {
      enabled: true
      runtimeVersion: '~1'
    }
    globalValidation: {
      requireAuthentication: true
      unauthenticatedClientAction: 'RedirectToLoginPage'
      redirectToProvider: 'azureactivedirectory'
      excludedPaths: [
        '/healthz' // the health check; it returns the text "ok" and nothing else
      ]
    }
    identityProviders: {
      azureActiveDirectory: {
        enabled: true
        registration: {
          openIdIssuer: 'https://sts.windows.net/${tenant().tenantId}/v2.0'
          clientId: entraClientId
          clientSecretSettingName: 'MICROSOFT_PROVIDER_AUTHENTICATION_SECRET'
        }
      }
    }
  }
  dependsOn: [
    appSettings
  ]
}

@description('Name of the web app.')
output webAppName string = webApp.name

@description('Host name of the site.')
output hostName string = webApp.properties.defaultHostName

@description('Key Vault name: put egnyte-client-secret and entra-client-secret here.')
output keyVaultName string = vault.name

@description('Cosmos DB account name: where each user\'s Egnyte tokens are stored.')
output cosmosAccountName string = cosmos.outputs.accountName

@description('Cosmos DB endpoint the app connects to with its managed identity.')
output cosmosEndpoint string = cosmos.outputs.endpoint

@description('Register this redirect URI on your Egnyte API key.')
output egnyteRedirectUri string = 'https://${webApp.properties.defaultHostName}/egnyte/callback'

@description('Register this redirect URI on the Microsoft Entra app registration used for sign-in.')
output entraRedirectUri string = 'https://${webApp.properties.defaultHostName}/.auth/login/aad/callback'
