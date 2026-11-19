// ==============================================================================
// Enterprise AP Invoice Automation Platform — Production Infrastructure (P14-4)
// Target Region: strictly Azure East US 2 (ADR-001, N2)
// Resources: Container Apps, Azure SQL, Redis Cache, Blob WORM (7-year hold),
// Azure OpenAI (Model Gateway), Key Vault, Virtual Network, and Strict NSG.
// Security: Keyless Entra ID Managed Identities (ADR-007, N1), TLS 1.2+, zero
// static secrets committed or exported (N8, SEC-234).
// ==============================================================================

@description('Target Azure region for all resources. Strictly locked to East US 2.')
@allowed([
  'eastus2'
])
param primaryRegion string = 'eastus2'

@description('Deployment environment tier.')
@allowed([
  'staging',
  'prod'
])
param environment string = 'staging'

@description('Unique application workload prefix for resource naming.')
@minLength(3)
@maxLength(16)
param workloadName string = 'ap-automation'

@description('Microsoft Entra ID Tenant ID for RBAC and authentication.')
param entraTenantId string = tenant().tenantId

@description('Entra ID Administrator object ID for Azure SQL Server.')
param sqlEntraAdminObjectId string = '00000000-0000-0000-0000-000000000000'

@description('Entra ID Administrator principal name/email for Azure SQL Server.')
param sqlEntraAdminLogin string = 'dave.admin@company.com'

// ------------------------------------------------------------------------------
// Variables & Computed Names
// ------------------------------------------------------------------------------
var resourceSuffix = '${workloadName}-${environment}'
var uniqueBase = uniqueString(resourceGroup().id, workloadName, environment)
var storageAccountName = 'st${take(uniqueBase, 17)}${environment}'
var keyVaultName = 'kv-${take(resourceSuffix, 18)}-${take(uniqueBase, 5)}'
var sqlServerName = 'sql-${resourceSuffix}-eastus2'
var sqlDatabaseName = 'sqldb-ap-${environment}'
var redisName = 'redis-${resourceSuffix}'
var openAiName = 'aoai-${resourceSuffix}'
var logAnalyticsName = 'log-${resourceSuffix}'
var vnetName = 'vnet-${resourceSuffix}'
var nsgName = 'nsg-${resourceSuffix}'
var containerAppEnvName = 'cae-${resourceSuffix}'
var apiAppName = 'ca-api'
var uiAppName = 'ca-ui'

// ------------------------------------------------------------------------------
// Regional Confinement Assertion (ADR-001, N2)
// ------------------------------------------------------------------------------
// All resources are provisioned strictly in eastus2
var location = primaryRegion

// ==============================================================================
// 1. Observability: Azure Monitor Log Analytics Workspace
// ==============================================================================
resource logAnalyticsWorkspace 'Microsoft.OperationalInsights/workspaces@2023-09-01' = {
  name: logAnalyticsName
  location: location
  properties: {
    sku: {
      name: 'PerGB2018'
    }
    retentionInDays: 30
    features: {
      searchVersion: 1
      enableLogAccessUsingOnlyResourcePermissions: true
    }
  }
}

// ==============================================================================
// 2. Networking: Virtual Network & Strict Regional NSG (ADR-001, N2, HLD §6)
// ==============================================================================
resource networkSecurityGroup 'Microsoft.Network/networkSecurityGroups@2023-11-01' = {
  name: nsgName
  location: location
  properties: {
    securityRules: [
      // Inbound: HTTPS traffic from WAF / Azure Front Door
      {
        name: 'Allow-HTTPS-Inbound'
        properties: {
          priority: 200
          direction: 'Inbound'
          access: 'Allow'
          protocol: 'Tcp'
          sourceAddressPrefix: 'AzureFrontDoor.Backend'
          sourcePortRange: '*'
          destinationAddressPrefix: '*'
          destinationPortRange: '443'
        }
      }
      // Outbound: Permitted East US 2 regional Azure services
      {
        name: 'Allow-EastUS2-AzureCloud-Outbound'
        properties: {
          priority: 300
          direction: 'Outbound'
          access: 'Allow'
          protocol: '*'
          sourceAddressPrefix: 'VirtualNetwork'
          sourcePortRange: '*'
          destinationAddressPrefix: 'AzureCloud.EastUS2'
          destinationPortRange: '*'
        }
      }
      // Outbound: Intra-VNet traffic between Container Apps and endpoints
      {
        name: 'Allow-VNet-Intra-Outbound'
        properties: {
          priority: 310
          direction: 'Outbound'
          access: 'Allow'
          protocol: '*'
          sourceAddressPrefix: 'VirtualNetwork'
          sourcePortRange: '*'
          destinationAddressPrefix: 'VirtualNetwork'
          destinationPortRange: '*'
        }
      }
      // Outbound: Deny all outbound to Internet (Zero cross-region egress: N2, ADR-001)
      {
        name: 'Deny-Internet-Outbound'
        properties: {
          priority: 900
          direction: 'Outbound'
          access: 'Deny'
          protocol: '*'
          sourceAddressPrefix: '*'
          sourcePortRange: '*'
          destinationAddressPrefix: 'Internet'
          destinationPortRange: '*'
        }
      }
    ]
  }
}

resource virtualNetwork 'Microsoft.Network/virtualNetworks@2023-11-01' = {
  name: vnetName
  location: location
  properties: {
    addressSpace: {
      addressPrefixes: [
        '10.0.0.0/16'
      ]
    }
    subnets: [
      {
        name: 'snet-aca'
        properties: {
          addressPrefix: '10.0.1.0/24'
          networkSecurityGroup: {
            id: networkSecurityGroup.id
          }
          delegations: [
            {
              name: 'aca-delegation'
              properties: {
                serviceName: 'Microsoft.App/environments'
              }
            }
          ]
        }
      }
      {
        name: 'snet-endpoints'
        properties: {
          addressPrefix: '10.0.2.0/24'
          networkSecurityGroup: {
            id: networkSecurityGroup.id
          }
          privateEndpointNetworkPolicies: 'Disabled'
        }
      }
    ]
  }
}

// ==============================================================================
// 3. Storage: Azure Blob Storage with 7-Year WORM Immutability (ADR-005, N6)
// ==============================================================================
resource storageAccount 'Microsoft.Storage/storageAccounts@2023-05-01' = {
  name: storageAccountName
  location: location
  sku: {
    name: 'Standard_LRS'
  }
  kind: 'StorageV2'
  properties: {
    minimumTlsVersion: 'TLS1_2'
    supportsHttpsTrafficOnly: true
    allowBlobPublicAccess: false
    allowSharedKeyAccess: false // Strictly keyless via Entra ID Managed Identity (ADR-007)
    accessTier: 'Hot'
    encryption: {
      services: {
        blob: {
          enabled: true
        }
      }
      keySource: 'Microsoft.Storage'
    }
  }
}

resource blobService 'Microsoft.Storage/storageAccounts/blobServices@2023-05-01' = {
  parent: storageAccount
  name: 'default'
  properties: {
    deleteRetentionPolicy: {
      enabled: true
      days: 30
    }
    containerDeleteRetentionPolicy: {
      enabled: true
      days: 30
    }
  }
}

// 7-year immutable WORM container (2557 days = 7 years including leap days: ADR-005, BR-026)
resource wormContainer 'Microsoft.Storage/storageAccounts/blobServices/containers@2023-05-01' = {
  parent: blobService
  name: 'raw-invoices-immutable'
  properties: {
    publicAccess: 'None'
    immutableStorageWithVersioning: {
      enabled: true
    }
  }
}

resource immutabilityPolicy 'Microsoft.Storage/storageAccounts/blobServices/containers/immutabilityPolicies@2023-05-01' = {
  parent: wormContainer
  name: 'default'
  properties: {
    immutabilityPeriodSinceCreationInDays: 2557
    allowProtectedAppendWrites: true
  }
}

// ==============================================================================
// 4. Secrets & Key Management: Azure Key Vault (ADR-007, N1, N8)
// ==============================================================================
resource keyVault 'Microsoft.KeyVault/vaults@2023-07-01' = {
  name: keyVaultName
  location: location
  properties: {
    sku: {
      family: 'A'
      name: 'standard'
    }
    tenantId: entraTenantId
    enableRbacAuthorization: true
    enableSoftDelete: true
    softDeleteRetentionInDays: 90
    purgeProtection: true
    publicNetworkAccess: 'Disabled'
    networkAcls: {
      bypass: 'AzureServices'
      defaultAction: 'Deny'
    }
  }
}

// ==============================================================================
// 5. Cache: Azure Cache for Redis (Job Queue & Sliding-Window Rate Limiter)
// ==============================================================================
resource redisCache 'Microsoft.Cache/redis@2023-08-01' = {
  name: redisName
  location: location
  properties: {
    sku: {
      name: 'Basic'
      family: 'C'
      capacity: 0 // B0 / C0 basic cache
    }
    enableNonSslPort: false
    minimumTlsVersion: '1.2'
    publicNetworkAccess: 'Disabled'
  }
}

// ==============================================================================
// 6. Database: Azure SQL Logical Server & Database (CLAUDE.md §6)
// ==============================================================================
resource sqlServer 'Microsoft.Sql/servers@2023-08-01-preview' = {
  name: sqlServerName
  location: location
  properties: {
    version: '12.0'
    minimalTlsVersion: '1.2'
    publicNetworkAccess: 'Disabled'
    administrators: {
      administratorType: 'ActiveDirectory'
      principalType: 'User'
      login: sqlEntraAdminLogin
      sid: sqlEntraAdminObjectId
      tenantId: entraTenantId
      azureADOnlyAuthentication: true // Zero SQL server sa/admin passwords (N8, SEC-234)
    }
  }
}

resource sqlDatabase 'Microsoft.Sql/servers/databases@2023-08-01-preview' = {
  parent: sqlServer
  name: sqlDatabaseName
  location: location
  sku: {
    name: 'Standard'
    tier: 'Standard'
    capacity: 20 // S1 / DTU-based for predictable pilot cost
  }
  properties: {
    collation: 'SQL_Latin1_General_CP1_CI_AS'
    maxSizeBytes: 268435456000 // 250 GB
  }
}

// ==============================================================================
// 7. AI Model Gateway: Azure OpenAI East US 2 (ADR-004, Model Gateway)
// ==============================================================================
resource openAiAccount 'Microsoft.CognitiveServices/accounts@2023-05-01' = {
  name: openAiName
  location: location
  kind: 'OpenAI'
  sku: {
    name: 'S0'
  }
  properties: {
    customSubDomainName: toLower('${workloadName}-${environment}-${take(uniqueBase, 6)}')
    publicNetworkAccess: 'Disabled'
    networkAcls: {
      defaultAction: 'Deny'
    }
  }
}

// Deployment 1: GPT-4o-Vision for scans, tables, and images
resource gpt4oVisionDeployment 'Microsoft.CognitiveServices/accounts/deployments@2023-05-01' = {
  parent: openAiAccount
  name: 'gpt-4o-vision'
  sku: {
    name: 'Standard'
    capacity: 30
  }
  properties: {
    model: {
      format: 'OpenAI'
      name: 'gpt-4o'
      version: '2024-05-13'
    }
  }
}

// Deployment 2: GPT-4o-mini for text-dense searchable PDFs (Prompt Caching enabled)
resource gpt4oMiniDeployment 'Microsoft.CognitiveServices/accounts/deployments@2023-05-01' = {
  parent: openAiAccount
  name: 'gpt-4o-mini'
  sku: {
    name: 'Standard'
    capacity: 50
  }
  properties: {
    model: {
      format: 'OpenAI'
      name: 'gpt-4o-mini'
      version: '2024-07-18'
    }
  }
  dependsOn: [
    gpt4oVisionDeployment
  ]
}

// ==============================================================================
// 7b. Networking: Private Endpoints for Isolated Datastores (snet-endpoints)
// ==============================================================================
var endpointSubnetId = '${virtualNetwork.id}/subnets/snet-endpoints'

// Private Endpoint: Azure Key Vault
resource peKeyVault 'Microsoft.Network/privateEndpoints@2023-11-01' = {
  name: 'pe-${keyVaultName}'
  location: location
  properties: {
    subnet: {
      id: endpointSubnetId
    }
    privateLinkServiceConnections: [
      {
        name: 'plsc-keyvault'
        properties: {
          privateLinkServiceId: keyVault.id
          groupIds: [
            'vault'
          ]
        }
      }
    ]
  }
}

// Private Endpoint: Azure SQL Database
resource peSqlServer 'Microsoft.Network/privateEndpoints@2023-11-01' = {
  name: 'pe-${sqlServerName}'
  location: location
  properties: {
    subnet: {
      id: endpointSubnetId
    }
    privateLinkServiceConnections: [
      {
        name: 'plsc-sql'
        properties: {
          privateLinkServiceId: sqlServer.id
          groupIds: [
            'sqlServer'
          ]
        }
      }
    ]
  }
}

// Private Endpoint: Azure Blob Storage
resource peStorageBlob 'Microsoft.Network/privateEndpoints@2023-11-01' = {
  name: 'pe-${storageAccountName}-blob'
  location: location
  properties: {
    subnet: {
      id: endpointSubnetId
    }
    privateLinkServiceConnections: [
      {
        name: 'plsc-blob'
        properties: {
          privateLinkServiceId: storageAccount.id
          groupIds: [
            'blob'
          ]
        }
      }
    ]
  }
}

// Private Endpoint: Azure Cache for Redis
resource peRedis 'Microsoft.Network/privateEndpoints@2023-11-01' = {
  name: 'pe-${redisName}'
  location: location
  properties: {
    subnet: {
      id: endpointSubnetId
    }
    privateLinkServiceConnections: [
      {
        name: 'plsc-redis'
        properties: {
          privateLinkServiceId: redisCache.id
          groupIds: [
            'redisCache'
          ]
        }
      }
    ]
  }
}

// Private Endpoint: Azure OpenAI Model Gateway
resource peOpenAi 'Microsoft.Network/privateEndpoints@2023-11-01' = {
  name: 'pe-${openAiName}'
  location: location
  properties: {
    subnet: {
      id: endpointSubnetId
    }
    privateLinkServiceConnections: [
      {
        name: 'plsc-openai'
        properties: {
          privateLinkServiceId: openAiAccount.id
          groupIds: [
            'account'
          ]
        }
      }
    ]
  }
}

// ==============================================================================
// 8. Compute: Azure Container Apps Environment & Services
// ==============================================================================
resource containerAppEnv 'Microsoft.App/managedEnvironments@2023-05-01' = {
  name: containerAppEnvName
  location: location
  properties: {
    vnetConfiguration: {
      infrastructureSubnetId: '${virtualNetwork.id}/subnets/snet-aca'
      internal: true
    }
    appLogsConfiguration: {
      destination: 'log-analytics'
      logAnalyticsConfiguration: {
        customerId: logAnalyticsWorkspace.properties.customerId
        sharedKey: logAnalyticsWorkspace.listKeys().primarySharedKey
      }
    }
  }
}

// Container App: FastAPI Backend (Internal Ingress :8000)
resource apiContainerApp 'Microsoft.App/containerApps@2023-05-01' = {
  name: apiAppName
  location: location
  identity: {
    type: 'SystemAssigned'
  }
  properties: {
    managedEnvironmentId: containerAppEnv.id
    configuration: {
      ingress: {
        external: false
        targetPort: 8000
        transport: 'auto'
        allowInsecure: false
      }
    }
    template: {
      containers: [
        {
          name: 'api'
          image: 'mcr.microsoft.com/azuredocs/aci-helloworld:latest' // Replaced via CI/CD deploy pipeline
          resources: {
            cpu: json('1.0')
            memory: '2.0Gi'
          }
          env: [
            {
              name: 'APP_ENV'
              value: environment
            }
            {
              name: 'AZURE_REGION'
              value: primaryRegion
            }
            {
              name: 'AZURE_BLOB_ACCOUNT_URL'
              value: storageAccount.properties.primaryEndpoints.blob
            }
            {
              name: 'AZURE_BLOB_WORM_CONTAINER'
              value: 'raw-invoices-immutable'
            }
            {
              name: 'AZURE_SQL_SERVER'
              value: sqlServer.properties.fullyQualifiedDomainName
            }
            {
              name: 'AZURE_SQL_DATABASE'
              value: sqlDatabaseName
            }
            {
              name: 'AZURE_KEY_VAULT_URL'
              value: keyVault.properties.vaultUri
            }
            {
              name: 'REDIS_URL'
              value: 'rediss://${redisCache.properties.hostName}:${redisCache.properties.sslPort}/0'
            }
            {
              name: 'AZURE_OPENAI_ENDPOINT'
              value: openAiAccount.properties.endpoint
            }
            {
              name: 'AZURE_OPENAI_GPT4O_DEPLOYMENT'
              value: 'gpt-4o-vision'
            }
            {
              name: 'AZURE_OPENAI_MINI_DEPLOYMENT'
              value: 'gpt-4o-mini'
            }
            {
              name: 'USE_LOCAL_SQLITE'
              value: 'false'
            }
            {
              name: 'USE_FAKE_REDIS'
              value: 'false'
            }
            {
              name: 'USE_MOCK_AOAI'
              value: 'false'
            }
            {
              name: 'USE_MOCK_BLOB_STORAGE'
              value: 'false'
            }
            {
              name: 'USE_AZURITE_EMULATOR'
              value: 'false'
            }
            {
              name: 'ENABLE_DEMO_AUTH'
              value: 'false'
            }
          ]
          probes: [
            {
              type: 'Liveness'
              httpGet: {
                path: '/health'
                port: 8000
              }
              periodSeconds: 30
              failureThreshold: 3
            }
          ]
        }
      ]
      scale: {
        minReplicas: 1
        maxReplicas: 5
      }
    }
  }
}

// Container App: Streamlit Frontend (External Ingress :8501 via Front Door)
resource uiContainerApp 'Microsoft.App/containerApps@2023-05-01' = {
  name: uiAppName
  location: location
  identity: {
    type: 'SystemAssigned'
  }
  properties: {
    managedEnvironmentId: containerAppEnv.id
    configuration: {
      ingress: {
        external: true
        targetPort: 8501
        transport: 'auto'
        allowInsecure: false
      }
    }
    template: {
      containers: [
        {
          name: 'ui'
          image: 'mcr.microsoft.com/azuredocs/aci-helloworld:latest' // Replaced via CI/CD deploy pipeline
          resources: {
            cpu: json('0.5')
            memory: '1.0Gi'
          }
          env: [
            {
              name: 'AP_API_BASE_URL'
              value: 'http://${apiContainerApp.properties.configuration.ingress.fqdn}:8000'
            }
            {
              name: 'STREAMLIT_SERVER_HEADLESS'
              value: 'true'
            }
            {
              name: 'STREAMLIT_SERVER_ENABLE_XSRF_PROTECTION'
              value: 'true'
            }
            {
              name: 'STREAMLIT_SERVER_ENABLE_CORS'
              value: 'true'
            }
            {
              name: 'STREAMLIT_SERVER_MAX_UPLOAD_SIZE'
              value: '25'
            }
            {
              name: 'STREAMLIT_BROWSER_GATHER_USAGE_STATS'
              value: 'false'
            }
            {
              name: 'STREAMLIT_CLIENT_SHOW_ERROR_DETAILS'
              value: 'false'
            }
          ]
          probes: [
            {
              type: 'Liveness'
              httpGet: {
                path: '/_stcore/health'
                port: 8501
              }
              periodSeconds: 30
              failureThreshold: 3
            }
          ]
        }
      ]
      scale: {
        minReplicas: 1
        maxReplicas: 3
      }
    }
  }
}

// ==============================================================================
// 9. RBAC: Managed Identity Role Assignments (ADR-007, N1, SEC-234)
// ==============================================================================
// Built-in Azure RBAC Role Definition IDs
var roleKeyVaultSecretsUser = '4633458b-17de-408a-b874-0445c86b69e6'
var roleStorageBlobDataContributor = 'ba92f5b4-2d11-453d-a403-e96b0029c9fe'
var roleCognitiveServicesOpenAIUser = '5e0dc982-0038-4745-9372-2f3b90048e9c'

// API -> Key Vault Secrets User
resource kvSecretsUserRole 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  name: guid(keyVault.id, apiContainerApp.id, roleKeyVaultSecretsUser)
  scope: keyVault
  properties: {
    roleDefinitionId: subscriptionResourceId('Microsoft.Authorization/roleDefinitions', roleKeyVaultSecretsUser)
    principalId: apiContainerApp.identity.principalId
    principalType: 'ServicePrincipal'
  }
}

// API -> Storage Blob Data Contributor
resource blobDataContributorRole 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  name: guid(storageAccount.id, apiContainerApp.id, roleStorageBlobDataContributor)
  scope: storageAccount
  properties: {
    roleDefinitionId: subscriptionResourceId('Microsoft.Authorization/roleDefinitions', roleStorageBlobDataContributor)
    principalId: apiContainerApp.identity.principalId
    principalType: 'ServicePrincipal'
  }
}

// API -> Cognitive Services OpenAI User
resource openAiUserRole 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  name: guid(openAiAccount.id, apiContainerApp.id, roleCognitiveServicesOpenAIUser)
  scope: openAiAccount
  properties: {
    roleDefinitionId: subscriptionResourceId('Microsoft.Authorization/roleDefinitions', roleCognitiveServicesOpenAIUser)
    principalId: apiContainerApp.identity.principalId
    principalType: 'ServicePrincipal'
  }
}

// ==============================================================================
// 10. Outputs (Non-Sensitive Endpoint Metadata Only: N8, SEC-234)
// ==============================================================================
output primaryRegion string = primaryRegion
output storageAccountName string = storageAccount.name
output blobWormContainerName string = wormContainer.name
output blobEndpoint string = storageAccount.properties.primaryEndpoints.blob
output keyVaultName string = keyVault.name
output keyVaultUri string = keyVault.properties.vaultUri
output sqlServerFqdn string = sqlServer.properties.fullyQualifiedDomainName
output sqlDatabaseName string = sqlDatabaseName
output openAiEndpoint string = openAiAccount.properties.endpoint
output apiIngressFqdn string = apiContainerApp.properties.configuration.ingress.fqdn
output uiIngressFqdn string = uiContainerApp.properties.configuration.ingress.fqdn

