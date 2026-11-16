# Entra Access Contracts — Azure acceptance checklist

This is a **deployment-time acceptance plan**, not evidence that a gateway was tested.
Use an isolated APIM instance and test workload identities with representative backend routes.
Do not run stress/quota tests against production or use real customer data.

## Prerequisites

- The gateway is deployed with `entraAuth=true`, the correct tenant and gateway Entra application audience.
- The complete, validated `gatewayAccessContracts` desired state is deployed.
- The caller's **service principal object ID** (`oid`), not its client/application ID, is explicitly granted.
- At least two test Managed Identities exist: one granted on a test API and another deliberately **not** granted.
- Each test API has a safe, idempotent read-only operation and a reachable backend.
- APIM diagnostics, ingestion, and downstream reporting are available for review.

## Initial identity boundary

From the Azure workload running each Managed Identity, acquire a token for the gateway
application ID URI (the audience must match the APIM JWT validation policy):

```bash
az login --identity
export AUTHORIZED_TOKEN="$(az account get-access-token --resource 'api://<gateway-app-id>' --query accessToken -o tsv)"
# Acquire DENIED_TOKEN from a DIFFERENT, ungranted managed identity.
```

Do not print tokens, write them to files, or commit them. For the same safe read-only operation,
run the smoke harness from the repository root:

```bash
python scripts/smoke_test_entra_gateway.py \
  --url 'https://<isolated-apim>.azure-api.net/<read-only-operation>' \
  --authorized-token-env AUTHORIZED_TOKEN \
  --denied-token-env DENIED_TOKEN \
  --authorized-status 200
unset AUTHORIZED_TOKEN DENIED_TOKEN
```

The harness verifies missing token → 401, malformed token → 401, valid ungranted caller → 403,
and (when supplied) an explicitly chosen success status for the authorized caller. It disables
redirects and never prints bearer values. A single 2xx/401/403 smoke test does **not** certify
policy completeness, quota correctness, or downstream RBAC.

## Mandatory test matrix

| Case | Expected evidence | Result |
| --- | --- | --- |
| Valid managed identity and granted API | Only contracted operations can reach backend; normalized caller and contract logged | Unverified |
| Incorrect tenant, audience, expired or tampered JWT | 401 before any backend identity/token acquisition | Unverified |
| Valid but unlisted caller/API grant | 403, no backend call | Unverified |
| Duplicate grants / invalid configuration | Manifest validator or ARM deployment fails; no registry loss | Source checks only |
| Multiple contracts with shared caller but distinct APIs | Each API maps to the correct contract and quota | Unverified |
| Model disallowed; backend pool disallowed | 403 including explicit backend selection and alias retry | Unverified |
| LLM token TPM/quota, MCP, A2A, auxiliary service quotas | Intended counters enforced independently; concurrent limits understood | Unverified |
| Responses GET/DELETE/chaining | Different caller or contract cannot access cached response | Unverified |
| AI Search, Document Intelligence, Realtime, other enabled APIs | JWT enforced on every operation, including WebSocket and streaming paths | Unverified |
| MCP internal source API | Gateway MI acquires a distinct source-audience token; caller token never forwarded | Unverified |
| Foundry ProjectManagedIdentity connection | Correct gateway audience, no subscription-key header; successful inference | Unverified |
| Legacy `entraAuth=false` | Product/subscription key, Product policies, rotation and Foundry API-key mode still work | Unverified |
| Usage ingestion and cost reports | `productName` is logical contract, `appId` caller; no incorrect joins or charges | Unverified |
| Optional built-in MCP examples | Keyless mode must reject the unsecured sample resources until explicitly hardened | Source checks only |
| Backend routing metadata API | Public /version works, /version/backend-contract requires a granted JWT caller in Entra mode | Unverified |
| Custom Product policies | Every required custom control explicitly migrated or deployment intentionally stays in subscription mode | Requires review |
| Contract grant added, modified, revoked | Full-state redeployment converges, revocations denied; no accidental grant loss | Unverified |
| Upgrade / backend onboarding / rollback | No overwrites of contract resolver or auth mode; rollback confirmed | Unverified |

For each scenario, capture the test identity/contract (not tokens), API and operation, UTC time,
request correlation ID, APIM effective policy, resulting status, backend/metric evidence, and
links to the relevant logs. Re-run after subsequent policy or Bicep changes.

## Release gate

Keep the PR in **Draft** until: (1) Bicep/CI passes, (2) APIM accepts and executes the
effective policies for all enabled APIs, (3) this full matrix passes in a representative
Azure deployment, (4) Product/catalog/reporting differences are either remediated or
explicitly accepted, and (5) an independent security review signs off.

See [AUTH_COMPATIBILITY_AUDIT.md](./AUTH_COMPATIBILITY_AUDIT.md) for the source-level assessment.
