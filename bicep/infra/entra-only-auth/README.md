# Entra ID-only authentication — isolated inference gateway

This implementation generates an optional JWT-only policy overlay for the three inference APIs (Azure OpenAI, Universal LLM and Unified AI). The normal APIM subscription-key flow remains unchanged.

## Identity and governance

- Spoke workloads obtain a Microsoft Entra access token using Managed Identity for the gateway's configured application audience.
- APIM validates token issuer, audience, tenant, signature and expiration, then extracts the managed-identity service principal object ID (oid).
- The normalized identity is tenant ID plus object ID. A caller is authorized only when its identity and requested API match an explicit Access Contract grant in the JSON registry.
- Model grants, backend pool grants and token quotas are resolved from that contract. Backend authorization is checked before every inference hop and retry.
- Token quotas are keyed to the contract. Usage attribution includes normalized caller and contract identifiers.
- Responses API ownership is checked using caller and contract identity in an isolated cache.
- The incoming gateway-audience bearer token and subscription-key headers are stripped. Backend authentication remains independent, using gateway Managed Identity or the existing provider-specific mechanism.

Unknown or ambiguous grants fail closed. The generator rejects duplicate identity/API combinations, unrestricted model/pool grants, and invalid limits.

## Generate and validate

Copy contracts.example.json to a private environment-specific configuration file. Replace the placeholders with the Entra tenant GUID, the gateway application audience, the caller managed identity's SERVICE PRINCIPAL OBJECT ID (not client ID), and the exact backend pool IDs. Protect the mapping through code review.

Run:

    python scripts/deploy_entra_only_auth.py --contracts path/to/contracts.json --output /tmp/entra-apim-policies

    python -m unittest discover -s validation/tests -p "test_entra_only_auth.py" -v

Generating files does not modify Azure resources.

## Optional isolated-gateway deployment

This overlay MUST NOT be applied to an existing shared APIM instance that has legacy consumers. Prepare a dedicated APIM environment with the upstream accelerator APIs, backend routing fragments, pools, managed identities and telemetry infrastructure already provisioned.

Every API selected in the grants must have subscriptionRequired=false AND no APIM Product associations. The deployment preflight validates these conditions, and refuses to change API subscription settings itself.

After logging into Azure CLI and reviewing the generated policies, use:

    python scripts/deploy_entra_only_auth.py --contracts path/to/contracts.json --output /tmp/entra-apim-policies --apim-resource-id "/subscriptions/<subscription-id>/resourceGroups/<rg>/providers/Microsoft.ApiManagement/service/<dedicated-apim>" --apply --confirm-isolated-gateway

The command installs the generated policy fragments before updating the selected API policies. It does not provision a new gateway or modify legacy deployments. A normal accelerator redeployment could overwrite the overlay; do not mix the deployment pipelines.

## Required Azure integration validation

- A valid Managed Identity token with a matching identity/API grant succeeds.
- Missing, invalid, expired, wrong-audience or wrong-tenant token fails with 401.
- A valid but ungranted caller or model fails with 403.
- Callers on the same contract share limits; distinct contracts have distinct counters.
- Attempts to select or retry an ungranted backend pool fail with 403.
- Responses API GET/DELETE/chained calls enforce caller and contract ownership.
- APIM never forwards the original caller JWT to the backend; Foundry validates the gateway's own Managed Identity and resource RBAC.
- Usage telemetry preserves caller and contract attribution.

## Limitations and remaining work

This is an isolated inference-only implementation. It is not yet a general replacement for the existing Access Contract provisioning pipeline. JWT-only support for published MCP and A2A APIs, automated contract lifecycle provisioning, Foundry connection provisioning without API-key injection, and all legacy alert/reporting dimensions remain to be integrated and tested.

The current cache format is not migration-compatible with legacy subscription IDs: never point both modes at the same Responses API ownership cache. Switching quota counter identity also starts new windows. No Azure integration/deployment test has been performed. Keep this feature in a draft PR until the remaining work and runtime validation are complete.
