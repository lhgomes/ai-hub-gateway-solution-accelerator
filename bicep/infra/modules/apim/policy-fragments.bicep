/**
 * @module policy-fragments
 * @description This module creates all policy fragments for the API Management service.
 * It includes configurations for authentication, routing, usage tracking, and PII handling.
 */

// ------------------
//    PARAMETERS
// ------------------

@description('The name of the API Management service')
param apimServiceName string

@description('Complete authorized JWT Access Contracts; used for per-contract quotas in the existing policy pipeline.')
param gatewayAccessContracts array = []

@description('Whether this deployment owns the JWT contract resolver and quota fragments. Set false when updating unrelated fragments on an existing gateway.')
param deployContractFragments bool = true

// Resolve the caller+API to exactly one Access Contract. This is compiled into
// an APIM policy fragment rather than a named value, avoiding its 4096-char limit.
var jwtGrantChecks = [for contract in gatewayAccessContracts: format(
  'if (JArray.Parse(Encoding.UTF8.GetString(Convert.FromBase64String(&quot;{0}&quot;))).Any(x => string.Equals((string)x, oid, StringComparison.OrdinalIgnoreCase)) &amp;&amp; JArray.Parse(Encoding.UTF8.GetString(Convert.FromBase64String(&quot;{1}&quot;))).Any(x => string.Equals((string)x, api, StringComparison.OrdinalIgnoreCase))) matches.Add(Encoding.UTF8.GetString(Convert.FromBase64String(&quot;{2}&quot;)));',
  base64(string(contract.callers)), base64(string(contract.apis)), base64(contract.id)
)]
var jwtGrantSettings = [for contract in gatewayAccessContracts: format(
  '<when condition="@(context.Variables.GetValueOrDefault&lt;string&gt;(&quot;contractId&quot;,&quot;&quot;) == Encoding.UTF8.GetString(Convert.FromBase64String(&quot;{0}&quot;)))"><set-variable name="allowedModels" value="@(Encoding.UTF8.GetString(Convert.FromBase64String(&quot;{1}&quot;)))" /><set-variable name="allowedBackendPools" value="@(Encoding.UTF8.GetString(Convert.FromBase64String(&quot;{2}&quot;)))" /></when>',
  base64(contract.id), base64(join(contract.?allowedModels ?? [], ',')), base64(join(contract.?allowedBackendPools ?? [], ','))
)]
var jwtContractResolutionXml = '<fragment><choose><when condition="@(&quot;{{Gateway-Auth-Mode}}&quot; == &quot;entra&quot;)"><set-variable name="contractId" value="@{ var oid = context.Variables.GetValueOrDefault&lt;string&gt;(&quot;callerOid&quot;, &quot;&quot;); var api = (context.Api.Id ?? &quot;&quot;).ToLowerInvariant(); var matches = new JArray(); ${join(jwtGrantChecks, '')} return matches.Count == 1 ? (string)matches[0] : &quot;&quot;; }" /><choose><when condition="@(string.IsNullOrEmpty(context.Variables.GetValueOrDefault&lt;string&gt;(&quot;contractId&quot;, &quot;&quot;)))"><return-response><set-status code="403" reason="No unique Access Contract grant" /></return-response></when></choose><choose>${join(jwtGrantSettings, '')}</choose><set-variable name="subscription-name" value="@((string)context.Variables[&quot;contractId&quot;])" /></when></choose></fragment>'

// Materialize each contract's static LLM token rate at deployment time: the TPM
// attribute is not dynamically expression-backed in APIM. No runtime registry
// duplication is required; the auth fragment resolves the same contract ID.
var quotaLlmCases = [for contract in gatewayAccessContracts: format(
  '<when condition="@(context.Variables.GetValueOrDefault&lt;string&gt;(&quot;contractId&quot;,&quot;&quot;) == Encoding.UTF8.GetString(Convert.FromBase64String(&quot;{0}&quot;)) &amp;&amp; context.Variables.GetValueOrDefault&lt;string&gt;(&quot;assetKind&quot;,&quot;llm&quot;) == &quot;llm&quot;)"><llm-token-limit counter-key="@((string)context.Variables[&quot;contractId&quot;])" tokens-per-minute="{1}" token-quota="{2}" token-quota-period="{3}" estimate-prompt-tokens="false" /></when>',
  base64(contract.id), int(contract.?tokensPerMinute ?? 1000), int(contract.?tokenQuota ?? 100000),
  contains(['Hourly','Daily','Weekly','Monthly','Yearly'], contract.?tokenQuotaPeriod ?? 'Monthly') ? contract.?tokenQuotaPeriod ?? 'Monthly' : 'INVALID'
)]
var quotaRequestCases = [for contract in gatewayAccessContracts: format(
  '<when condition="@(context.Variables.GetValueOrDefault&lt;string&gt;(&quot;contractId&quot;,&quot;&quot;) == Encoding.UTF8.GetString(Convert.FromBase64String(&quot;{0}&quot;)) &amp;&amp; context.Variables.GetValueOrDefault&lt;string&gt;(&quot;assetKind&quot;,&quot;llm&quot;) != &quot;llm&quot;)"><rate-limit-by-key counter-key="@(context.Variables.GetValueOrDefault&lt;string&gt;(&quot;contractId&quot;,&quot;&quot;) + &quot;:&quot; + context.Variables.GetValueOrDefault&lt;string&gt;(&quot;assetKind&quot;,&quot;&quot;))" calls="{1}" renewal-period="60" /><quota-by-key counter-key="@(context.Variables.GetValueOrDefault&lt;string&gt;(&quot;contractId&quot;,&quot;&quot;) + &quot;:&quot; + context.Variables.GetValueOrDefault&lt;string&gt;(&quot;assetKind&quot;,&quot;&quot;))" calls="{2}" renewal-period="{3}" /></when>',
  base64(contract.id), int(contract.?requestsPerMinute ?? 60), int(contract.?requestQuota ?? 10000), int(contract.?quotaPeriodSeconds ?? 2592000)
)]
var jwtQuotaCases = join(concat(quotaLlmCases, quotaRequestCases), '')
var jwtQuotaPolicy = '<fragment><choose><when condition="@(&quot;{{Gateway-Auth-Mode}}&quot; != &quot;entra&quot;)"></when>${jwtQuotaCases}<otherwise><return-response><set-status code="403" reason="No quota defined for contract" /></return-response></otherwise></choose></fragment>'



@description('Enable PII Anonymization features')
param enablePIIAnonymization bool = true

@description('Enable AI Model Inference features')
// Retained for interface compatibility with callers; not referenced within this module.
#disable-next-line no-unused-params
param enableAIModelInference bool = true

@description('Enable Unified AI API features')
param enableUnifiedAiApi bool = true

// ------------------
//    RESOURCES
// ------------------

resource apimService 'Microsoft.ApiManagement/service@2022-08-01' existing = {
  name: apimServiceName
}

resource resolveAccessContractFragment 'Microsoft.ApiManagement/service/policyFragments@2024-06-01-preview' = if (deployContractFragments) {
  name: 'resolve-access-contract'
  parent: apimService
  properties: {
    description: 'Resolve JWT workload object ID and API into exactly one authorized Access Contract'
    format: 'rawxml'
    value: jwtContractResolutionXml
  }
}

resource jwtContractQuotaFragment 'Microsoft.ApiManagement/service/policyFragments@2024-06-01-preview' = if (deployContractFragments) {
  name: 'enforce-contract-quota'
  parent: apimService
  properties: {
    description: 'Enforce quota resolved from the single JWT Access Contract registry'
    format: 'rawxml'
    value: jwtQuotaPolicy
  }
}

resource aiUsagePolicyFragment 'Microsoft.ApiManagement/service/policyFragments@2022-08-01' = {
  parent: apimService
  name: 'ai-usage'
  properties: {
    description: 'Tracks usage of all AI-related APIs with flexible dimensions for models, features, and more'
    value: loadTextContent('./policies/frag-ai-usage.xml')
    format: 'rawxml'
  }
}

resource raiseThrottlingEventsPolicyFragment 'Microsoft.ApiManagement/service/policyFragments@2022-08-01' = {
  parent: apimService
  name: 'raise-throttling-events'
  properties: {
    description: 'Raises custom events when throttling limits are hit through App Insights metrics, for proactive monitoring and alerting'
    value: loadTextContent('./policies/frag-raise-throttling-events.xml')
    format: 'rawxml'
  }
}

resource raiseAlertEventsPolicyFragment 'Microsoft.ApiManagement/service/policyFragments@2022-08-01' = {
  parent: apimService
  name: 'raise-alert-events'
  properties: {
    description: 'Comprehensive, opt-in alerting: emits App Insights custom metrics for throttling, backend, authorization, content-safety, and PII failures, sliceable per product/model/backend/app'
    value: loadTextContent('./policies/frag-raise-alert-events.xml')
    format: 'rawxml'
  }
}

// Publish Contract usage fragments (Tools/MCP and Agents/A2A). Emit request-count metrics to
// dedicated App Insights namespaces (mcp-usage / a2a-usage) that scheduled Logic Apps aggregate
// into Cosmos. Registered here so a freshly deployed gateway already has them; the
// citadel-publish-contracts deployment also (idempotently) ensures they exist.
resource mcpUsagePolicyFragment 'Microsoft.ApiManagement/service/policyFragments@2022-08-01' = {
  parent: apimService
  name: 'mcp-usage'
  properties: {
    description: 'Tracks usage of published Tools (MCP) as App Insights custom metrics (mcp-usage namespace)'
    value: loadTextContent('./policies/frag-mcp-usage.xml')
    format: 'rawxml'
  }
}

resource a2aUsagePolicyFragment 'Microsoft.ApiManagement/service/policyFragments@2022-08-01' = {
  parent: apimService
  name: 'a2a-usage'
  properties: {
    description: 'Tracks usage of published Agents (A2A) as App Insights custom metrics (a2a-usage namespace)'
    value: loadTextContent('./policies/frag-a2a-usage.xml')
    format: 'rawxml'
  }
}

// Access Contract asset-kind classifier. Lets a single product policy that mixes asset types apply the
// right controls per request (llm / tool / agent). Driven by contractToolApis / contractAgentApis
// variables the product policy sets; defaults to 'llm' so existing LLM-only contracts are unaffected.
resource setAssetKindPolicyFragment 'Microsoft.ApiManagement/service/policyFragments@2022-08-01' = {
  parent: apimService
  name: 'set-asset-kind'
  properties: {
    description: 'Classifies the current request as llm | tool | agent for asset-type-aware access-contract product policies'
    value: loadTextContent('./policies/frag-set-asset-kind.xml')
    format: 'rawxml'
  }
}

resource piiAnonymizationPolicyFragment 'Microsoft.ApiManagement/service/policyFragments@2022-08-01' = {
  parent: apimService
  name: 'pii-anonymization'
  properties: {
    description: 'Anonymizes personally identifiable information (PII) in API requests'
    value: loadTextContent('./policies/frag-pii-anonymization.xml')
    format: 'rawxml'
  }
}

resource piiDenonymizationPolicyFragment 'Microsoft.ApiManagement/service/policyFragments@2022-08-01' = {
  parent: apimService
  name: 'pii-deanonymization'
  properties: {
    description: 'Deanonymizes personally identifiable information (PII) in API responses when needed for backend processing'
    value: loadTextContent('./policies/frag-pii-deanonymization.xml')
    format: 'rawxml'
  }
}

resource piiStateSavingPolicyFragment 'Microsoft.ApiManagement/service/policyFragments@2022-08-01' = if (enablePIIAnonymization) {
  parent: apimService
  name: 'pii-state-saving'
  properties: {
    description: 'Saves the state of personally identifiable information (PII) for testing & validation purposes'
    value: loadTextContent('./policies/frag-pii-state-saving.xml')
    format: 'rawxml'
  }
}

resource aiFoundryCompatibilityPolicyFragment 'Microsoft.ApiManagement/service/policyFragments@2022-08-01' = if (enablePIIAnonymization) {
  parent: apimService
  name: 'ai-foundry-compatibility'
  properties: {
    description: 'Ensures compatibility with Microsoft Foundry CORS requirements'
    value: loadTextContent('./policies/frag-ai-foundry-compatibility.xml')
    format: 'rawxml'
  }
}

// ------------------
//    UNIFIED AI API FRAGMENTS
// ------------------

resource centralCacheManagerFragment 'Microsoft.ApiManagement/service/policyFragments@2024-06-01-preview' = if (enableUnifiedAiApi) {
  parent: apimService
  name: 'central-cache-manager'
  properties: {
    description: 'Caches metadata configuration for Unified AI API performance'
    value: loadTextContent('./policies/frag-central-cache-manager.xml')
    format: 'rawxml'
  }
}

resource requestProcessorFragment 'Microsoft.ApiManagement/service/policyFragments@2024-06-01-preview' = if (enableUnifiedAiApi) {
  parent: apimService
  name: 'request-processor'
  properties: {
    description: 'Analyzes incoming Unified AI requests to extract routing context'
    value: loadTextContent('./policies/frag-request-processor.xml')
    format: 'rawxml'
  }
}

resource pathBuilderFragment 'Microsoft.ApiManagement/service/policyFragments@2024-06-01-preview' = if (enableUnifiedAiApi) {
  parent: apimService
  name: 'path-builder'
  properties: {
    description: 'Reconstructs backend URI paths for Unified AI API routing'
    value: loadTextContent('./policies/frag-path-builder.xml')
    format: 'rawxml'
  }
}

resource securityHandlerFragment 'Microsoft.ApiManagement/service/policyFragments@2024-06-01-preview' = {
  parent: apimService
  name: 'security-handler'
  properties: {
    description: 'Unified authentication handler for all AI Gateway APIs (API Key + optional JWT per-product)'
    value: loadTextContent('./policies/frag-security-handler.xml')
    format: 'rawxml'
  }
}

resource setResponseHeadersFragment 'Microsoft.ApiManagement/service/policyFragments@2024-06-01-preview' = if (enableUnifiedAiApi) {
  parent: apimService
  name: 'set-response-headers'
  properties: {
    description: 'Adds UAIG-* response headers when enableResponseHeaders is true'
    value: loadTextContent('./policies/frag-set-response-headers.xml')
    format: 'rawxml'
  }
}

resource stripBackendHeadersFragment 'Microsoft.ApiManagement/service/policyFragments@2024-06-01-preview' = {
  parent: apimService
  name: 'strip-backend-headers'
  properties: {
    description: 'Removes browser, App Service / ARR, and X-Forwarded-* headers from requests forwarded to AI backends'
    value: loadTextContent('./policies/frag-strip-backend-headers.xml')
    format: 'rawxml'
  }
}

// Resolve Model Alias fragment - shared by all 3 LLM APIs (Azure OpenAI, Universal LLM, Unified AI).
// Initially deployed with an empty inline alias map so policies compile before any aliases are
// onboarded. The llm-backend-onboarding deployment overwrites this fragment with the configured
// modelAliases entries inlined as a static JObject (and also publishes them via metadata-config).
resource resolveModelAliasFragment 'Microsoft.ApiManagement/service/policyFragments@2024-06-01-preview' = {
  parent: apimService
  name: 'resolve-model-alias'
  properties: {
    description: 'Resolves model alias names to actual underlying models with priority/weighted strategy'
    value: replace(loadTextContent('./policies/frag-resolve-model-alias.xml'), '//{inlineAliasesCode}', '')
    format: 'rawxml'
  }
}

// ------------------
//    OUTPUTS
// ------------------

@description('The name of the AI usage policy fragment')
output aiUsagePolicyFragmentName string = aiUsagePolicyFragment.name

@description('The name of the PII anonymization policy fragment')
output piiAnonymizationPolicyFragmentName string = piiAnonymizationPolicyFragment.name

@description('The name of the PII deanonymization policy fragment')
output piiDenonymizationPolicyFragmentName string = piiDenonymizationPolicyFragment.name
@description('The name of the PII state saving policy fragment')
output piiStateSavingPolicyFragmentName string = enablePIIAnonymization ? piiStateSavingPolicyFragment.name : ''
@description('The name of the AI Foundry compatibility policy fragment')
output aiFoundryCompatibilityPolicyFragmentName string = enablePIIAnonymization ? aiFoundryCompatibilityPolicyFragment.name : ''

@description('The name of the central cache manager policy fragment')
output centralCacheManagerFragmentName string = enableUnifiedAiApi ? centralCacheManagerFragment.name : ''
@description('The name of the request processor policy fragment')
output requestProcessorFragmentName string = enableUnifiedAiApi ? requestProcessorFragment.name : ''
@description('The name of the path builder policy fragment')
output pathBuilderFragmentName string = enableUnifiedAiApi ? pathBuilderFragment.name : ''
@description('The name of the security handler policy fragment')
output securityHandlerFragmentName string = enableUnifiedAiApi ? securityHandlerFragment.name : ''
@description('The name of the set response headers policy fragment')
output setResponseHeadersFragmentName string = enableUnifiedAiApi ? setResponseHeadersFragment.name : ''

@description('The name of the resolve model alias policy fragment')
output resolveModelAliasFragmentName string = resolveModelAliasFragment.name
