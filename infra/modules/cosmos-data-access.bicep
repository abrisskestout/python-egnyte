// Lets one Microsoft Entra identity (for example a web app's managed identity) read and write the items in ONE
// Cosmos DB container, using Cosmos DB's own data-plane role-based access control.
//
// This is not the same as Azure RBAC: an Azure role such as Owner or Contributor gives no access to the data in
// an account whose local authentication is disabled. Data access only exists through assignments like this one.
//
// The assignment is scoped to the container, not the account or the database, so the identity can touch nothing
// else that is ever added to the account.

targetScope = 'resourceGroup'

@description('Name of the existing Cosmos DB account.')
param accountName string

@description('Database that holds the container.')
param databaseName string

@description('Container the identity gets access to.')
param containerName string

@description('Object (principal) ID of the identity, for example a web app\'s system-assigned managed identity.')
param principalId string

@description('GUID of the Cosmos DB data-plane role definition. Default: the built-in "Cosmos DB Built-in Data Contributor" (...0002), which can read, write and delete items. The built-in "Data Reader" is ...0001.')
param roleDefinitionGuid string = '00000000-0000-0000-0000-000000000002'

resource account 'Microsoft.DocumentDB/databaseAccounts@2024-11-15' existing = {
  name: accountName
}

resource assignment 'Microsoft.DocumentDB/databaseAccounts/sqlRoleAssignments@2024-11-15' = {
  parent: account
  // Must be a GUID. Derived from everything that identifies the assignment, so a re-deployment finds the same one.
  name: guid(account.id, databaseName, containerName, principalId, roleDefinitionGuid)
  properties: {
    roleDefinitionId: '${account.id}/sqlRoleDefinitions/${roleDefinitionGuid}'
    principalId: principalId
    scope: '${account.id}/dbs/${databaseName}/colls/${containerName}'
  }
}
