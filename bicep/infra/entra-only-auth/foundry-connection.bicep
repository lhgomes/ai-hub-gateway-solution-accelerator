targetScope = 'resourceGroup'

// Dedicated, subscription-key-free Foundry connection to an isolated AI Gateway.
// The target gateway must already validate the project's managed identity JWT.
@description('Foundry account resource name')
param foundryAccountName string

@description('Foundry project name')
param foundryProjectName string

@description('Name of the gateway connection created in the Foundry project')
param connectionName string

@description('Gateway URL including the inference API path')
param gatewayApiUrl string

@description('Gateway application ID URI. The Foundry project managed identity requests this token audience.')
param gatewayAudience string

@description('Optional model names for Foundry discovery')
param staticModels array = []

module keylessConnection '../citadel-access-contracts/modules/foundryConnection.bicep' = {
  name: 'keyless-foundry-gateway-connection'
  params: {
    aiFoundryAccountName: foundryAccountName
    aiFoundryProjectName: foundryProjectName
    connectionName: connectionName
    targetUrl: gatewayApiUrl
    authType: 'ProjectManagedIdentity'
    includeSubscriptionKey: false
    managedIdentityAudience: gatewayAudience
    staticModels: staticModels
    customHeaders: {}
  }
}

output targetUrl string = gatewayApiUrl
output authType string = 'ProjectManagedIdentity'
output audience string = gatewayAudience
