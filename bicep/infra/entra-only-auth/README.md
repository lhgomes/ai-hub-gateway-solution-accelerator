# Entra ID-only access contracts — isolated AI Gateway

## Overview

This opt-in implementation replaces APIM subscription-key authentication with Microsoft Entra ID JWT authentication for the AI Gateway's LLM inference APIs and published MCP/A2A assets.

The original subscription-key implementation and deployment defaults are untouched. The new mode requires an **isolated APIM deployment**. It uses explicit grants keyed by the managed identity **service principal object ID** (`oid`) and tenant ID (`tid`). It never accepts arbitrary client-supplied contract headers.

The scope is source-code implementation and validation, not a production deployment. ARM/Bicep compilation and generated policy XML validation run in GitHub Actions; genuine APIM policy compilation and runtime inference still require an Azure environment.

## Identity chain

1. A spoke application/agent uses its system-assigned or user-assigned Managed Identity to obtain a Microsoft Entra access token for the **gateway application audience** (for scope-based clients, `api://<gateway-app-id>/.default`).
2. APIM validates the signed token, tenant, audience, issuer, expiry, and expected service principal object ID claim.
3. An exact `tenantId:oid + APIM API ID` mapping selects an Access Contract. Unknown/ambiguous grants fail closed.
4. Inference authorization uses `allowedModels` and `allowedBackendPools`. LLM token limits are keyed to `contractId`. MCP/A2A request limits use `contractId:assetKind`, aggregating all tools or all agents belonging to that contract.
5. Usage metrics retain both caller and contract identities; Responses API ownership requires both to match.
6. Incoming gateway-audience `Authorization` and APIM key headers are removed. The backend uses its own gateway Managed Identity or existing provider authentication. The original caller token is **never** forwarded to a model.
7. A JWT-only MCP-from-API publisher uses a **separate APIM Managed Identity token for the internal source API**. Give that gateway identity a narrowly scoped Access Contract grant at the source, and configure `sourceManagedIdentityAudience`. A missing audience causes a fail-closed 503.

The Azure OpenAI/Foundry model service sees the gateway's backend identity, not the spoke caller. Caller-specific governance is enforced at the gateway and traceability is preserved through trusted telemetry.

## Configuring Access Contracts

Copy [contracts.example.json](./contracts.example.json) to an environment-specific file (do not commit production mappings without appropriate review).

Top-level fields:
- `tenantId`: single allowed Entra tenant ID.
- `audience`: the APIM gateway's Entra application ID URI.
- `assetKinds`: explicit map of *published* APIM API IDs to `tool` or `agent`; the three built-in inference APIs are recognized without mapping.
- `contracts`: a list of grants with unique `id`, `callers` (service principal `oid` values), `apis` (APIM API IDs), and the corresponding allowed models/pools and quotas.

Inference contracts require `allowedModels`, `allowedBackendPools`, `tokensPerMinute`, `tokenQuota`, and `tokenQuotaPeriod`. MCP/A2A contracts require `requestsPerMinute`, `requestQuota`, and `quotaPeriodSeconds`.

The same caller may have grants to multiple APIs, but **one caller/API pair may resolve to only one contract** in this version. Grant configurations are treated as security-critical policy changes. Revocation is implemented by updating this mapping and redeploying the policy fragment.

## Provisioning order

### 1. Deploy an isolated gateway

Provision APIM using the existing accelerator backend infrastructure, routing fragments, metrics, and least-privileged gateway Managed Identity permissions.

For the three inference API resources participating in JWT-only access:
- `subscriptionRequired=false`.
- No APIM Product associations or product policy dependencies.
- Ensure no existing subscription-key users rely on these APIs.
- Restrict public exposure according to your network security design.

The deployer will **not** turn off subscription enforcement on existing APIs or remove Product associations. It checks and rejects unsafe target instances.

### 2. Generate and install contract policies

```bash
python scripts/deploy_entra_only_auth.py \
  --contracts path/to/contracts.json \
  --output /tmp/entra-apim-policies
python -m unittest discover -s validation/tests -p "test_entra_only_auth.py" -v
```

Generation performs no Azure operations. Review the generated policy artifacts, then run:

```bash
python scripts/deploy_entra_only_auth.py \
  --contracts path/to/contracts.json \
  --output /tmp/entra-apim-policies \
  --apim-resource-id "/subscriptions/<sub>/resourceGroups/<rg>/providers/Microsoft.ApiManagement/service/<isolated-apim>" \
  --apply --confirm-isolated-gateway
```

This installs `entra-*` fragments and updates the three inference API policies granted by the registry. It does **not** provision a new APIM instance or create Entra application registrations. An existing accelerator deployment could overwrite this overlay; coordinate infrastructure pipelines accordingly.

### 3. Publish JWT-only MCP and A2A endpoints

In the existing [Citadel Publish Contracts](../citadel-publish-contracts/main.bicep) input, set `authMode: 'entra'` per published asset. The publisher automatically sets APIM `subscriptionRequired=false` and uses `entra-contract-auth`, contract request limits and normalized usage metrics.

For `mcp-from-api`, provide `sourceManagedIdentityAudience` (the audience accepted by the source API) and optionally `sourceManagedIdentityClientId`. Ensure the source API independently enforces JWT authorization for the gateway identity. The publisher does not forward the caller's API key. The JWT-only baseline deliberately takes precedence over user-supplied custom policy XML so that custom policies cannot silently bypass authentication.

For `mcp-existing`, use the publisher's backend Managed Identity or a supported provider-specific authentication configuration. A2A preserves its original Foundry backend identity and agent-card URL rewrite.

The publisher expects the `entra-*` fragments to exist already. Apply the generator/deployer before running Citadel Publish Contracts.

### 4. Create keyless Foundry connections

Deploy [foundry-connection.bicep](./foundry-connection.bicep) at the Foundry project's resource group, supplying `foundryAccountName`, `foundryProjectName`, `connectionName`, `gatewayApiUrl`, and `gatewayAudience`. It reuses the existing Foundry connection module with `ProjectManagedIdentity` and `includeSubscriptionKey: false`.

Grant the Foundry project's service principal object ID in the contract registry for the target inference API. Verify that the Foundry connection requests a token for the gateway audience and does not inject an `api-key` header. Existing key-based Foundry connection deployments are unchanged.

## Tests and production acceptance

CI checks Python policy generation, fail-closed grants, published asset configuration, Bicep compilation, and non-secret Foundry connection definitions.

An actual Azure integration deployment is still required to check:
- APIM runtime policy compilation (not just XML well-formedness) and policy execution order.
- JWT acquired via spoke Managed Identity: correct/incorrect tenant, issuer, audience, expired, missing and unknown caller.
- Independent contract model grants, pool restrictions during alias/fallback hops, and quota aggregation.
- Response ownership across callers and contracts, including chained Responses calls and cache eviction.
- MCP/A2A published endpoint calls, streaming behavior, and MCP internal Managed Identity source authentication.
- Foundry ProjectManagedIdentity connection behavior with zero subscription-key headers.
- Logs, alerts and usage dashboards for the correct caller and contract dimensions.
- Recovery from partial APIM deployment, configuration rollback, and quota/reset semantics.

**Do not merge this PR into a production deployment until those integration checks pass.** Switching quota keys starts independent counter windows. Legacy response-ID cache values cannot be shared with JWT-only ownership semantics. Unrelated third-party providers may still require provider-specific API keys for downstream authentication.

## Design boundary

This is JWT-only enforcement with an APIM gateway-owned backend identity; it is not end-to-end caller delegation. The backend sees the gateway's Managed Identity. Authorization decisions and traceability for the initiating caller are handled by the gateway. In a zero-trust architecture, do not permit bypass routes that evade gateway policy enforcement.
