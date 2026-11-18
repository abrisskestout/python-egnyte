// Azure Cosmos DB for NoSQL: one account, one database, one container.
//
// Sign-in is Microsoft Entra ID only: local (key based) authentication is switched off, so the account has no
// keys or connection strings that could be copied, leaked or used. Callers get access through a data-plane role
// assignment (cosmos-data-access.bicep), normally for a managed identity.
//
// Nothing project-specific is hard-coded here: names, location, tags, partition key and the network allow list
// all come in as parameters.

targetScope = 'resourceGroup'

@description('Account name: 3-44 lowercase letters, digits and hyphens, unique across all of Azure.')
@minLength(3)
@maxLength(44)
param accountName string

@description('Azure region for the account. If it answers "high demand", deploy to another region.')
param location string

@description('Resource tags.')
param tags object = {}

@description('Database name.')
@minLength(1)
param databaseName string

@description('Container name.')
@minLength(1)
param containerName string

@description('Partition key path. "/id" suits one document per user: every read, write and delete is a cheap point operation.')
param partitionKeyPath string = '/id'

@description('Single IPv4 addresses (or CIDR ranges) allowed through the account firewall; everything else is refused. Leave empty for no firewall: the endpoint is then public, but still needs a Microsoft Entra identity with a data role.')
param allowedIpAddresses array = []

@description('Serverless capacity: pay per request, no throughput to size. It cannot be changed after the account is created.')
param serverless bool = true

@description('Autoscale ceiling in RU/s for the container. Only used when serverless is false.')
param autoscaleMaxThroughput int = 1000

resource account 'Microsoft.DocumentDB/databaseAccounts@2024-11-15' = {
  name: accountName
  location: location
  tags: tags
  kind: 'GlobalDocumentDB'
  properties: {
    databaseAccountOfferType: 'Standard'
    locations: [
      {
        locationName: location
        failoverPriority: 0
        isZoneRedundant: false
      }
    ]
    consistencyPolicy: {
      defaultConsistencyLevel: 'Session'
    }
    capabilities: serverless ? [
      {
        name: 'EnableServerless'
      }
    ] : []
    // No keys, no connection strings: data access needs a Microsoft Entra identity with a data-plane role.
    disableLocalAuth: true
    // Also refuse control-plane changes (databases, containers, throughput) made with account keys.
    disableKeyBasedMetadataWriteAccess: true
    minimalTlsVersion: 'Tls12'
    publicNetworkAccess: 'Enabled'
    ipRules: [for address in allowedIpAddresses: {
      ipAddressOrRange: address
    }]
  }
}

resource database 'Microsoft.DocumentDB/databaseAccounts/sqlDatabases@2024-11-15' = {
  parent: account
  name: databaseName
  properties: {
    resource: {
      id: databaseName
    }
  }
}

resource container 'Microsoft.DocumentDB/databaseAccounts/sqlDatabases/containers@2024-11-15' = {
  parent: database
  name: containerName
  properties: {
    resource: {
      id: containerName
      partitionKey: {
        paths: [
          partitionKeyPath
        ]
        kind: 'Hash'
        version: 2
      }
    }
    options: serverless ? {} : {
      autoscaleSettings: {
        maxThroughput: autoscaleMaxThroughput
      }
    }
  }
}

@description('Account name.')
output accountName string = account.name

@description('Endpoint the app connects to (no key or connection string is needed or exists).')
output endpoint string = account.properties.documentEndpoint

@description('Database name.')
output databaseName string = database.name

@description('Container name.')
output containerName string = container.name
