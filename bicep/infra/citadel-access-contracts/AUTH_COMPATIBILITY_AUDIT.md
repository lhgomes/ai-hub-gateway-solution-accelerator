# Entra authentication compatibility audit

Status: **code-level remediation, NOT production validation**. This record belongs to PR #2. The existing `entraAuth` switch is gateway-wide. The new Access Contract registry is the authoritative desired-state `gatewayAccessContracts` parameter on the normal gateway deployment; it is not the APIM subscription catalog.

## Controls and effect of setting entraAuth=true

| Surface or process | Existing subscription behavior | Entra behavior / evidence | Remaining risk |
| --- | --- | --- | --- |
| Azure OpenAI / Universal LLM / Unified AI | Native APIM subscription gate, Product policy | Shared `security-handler`, `resolve-access-contract`, model/pool checks, contract quotas | Must validate policy compilation, aliases/retries, quota and response-ID runtime |
| AI Search index + service API | Subscription gate; gateway authenticates to Search | Caller JWT and contract grant enforced **before** Search Managed Identity acquisition | Must validate actual API IDs, streaming/operations, and source endpoint reachability |
| Document Intelligence (legacy + modern) | Subscription gate; gateway authenticates to Cognitive Services | Caller JWT and contract grant enforced **before** backend Managed Identity | Existing outbound policy includes legacy expressions; APIM XML compilation still required |
| Realtime websocket | Subscription gate; Product-dependent example routing | Caller JWT and contract grant enforced before backend identity; null-safe Product references | Realtime routing has upstream `REPLACE` placeholders; actual URL routing and APIM websocket policy support unverified |
| Other generic AI inference policy | Backend MI without explicit caller identity | Caller JWT, contract grant and request-based quota added | Confirm which API resources actually use the policy |
| Published MCP/A2A | Product/subscription policy and publisher-specific defaults | Shared JWT, grant, request quota and existing telemetry | Runtime protocol, streaming, and source Managed Identity hop must be tested |
| Optional built-in MCP examples | Samples can publish without subscription/auth and are not production assets | Entra mode now rejects enabling the insecure samples with a deployment-time error | Harden each sample separately before enabling it in JWT deployments |
| Release metadata API | /version public; /version/backend-contract contains backend routing information | Entra mode requires JWT and an explicit grant to `release-version-api` for backend-contract; /version remains public | Live policy evaluation and metadata exposure test required |
| Custom Product policy XML | Runs in Product scope for valid Product subscription | **Not migrated automatically.** Entra grants resolve at API scope; Product policy is not a substitute | Customized policies, response headers, transformations, safety and per-product alerts require individual migration |
| Product catalog / developer portal | Product resources and subscriptions exist | Access Contract onboarding skips Product/subscription creation in Entra mode | Portal, catalog, approval flows, custom reports and other Product-centric functions may change |
| Contract onboarding | Access Contract deployment provisions APIM Products/subscription keys | Separate contract deployment can create endpoints and Foundry connections; validated manifest aggregation generates the root gateway's complete desired-state registry | Deployment pipeline must apply the complete registry; contract and Foundry updates are not atomic |
| Token quotas / request quotas | Product-scoped policies, subscription counters | LLM token counters keyed by contract; MCP/agent/service request counters keyed by contract and kind | Quota windows reset across mode migration; rate and quota measurements require runtime testing |
| Responses API ownership | Cached subscription+Product ID | Cached normalized caller+contract ID | Existing cache records not migration compatible; fail/deny across old and new modes |
| LLM/MCP/A2A metrics | `productName` = Product name, `appId` = app/subscription identity | Same metric fields, now contract ID and normalized caller | Downstream queries using Product identity semantics require review |
| Legacy usage fragments | Product/subscription dimensions | Fallback to normalized caller+contract while preserving field names | Actual event consumers and dashboards not exhaustively proven |
| LLM backend onboarding | Redeploys pools and shared fragments | Uses canonical authorization, model-access, usage and Responses fragments instead of stale copies | Live backend routing tests needed |
| APIM gateway upgrade | Can update JWT values, API subscriptions and shared fragments | Defaults to `authMode='preserve'` and skips authentication-sensitive API/policy updates unless mode explicitly selected | Existing upgrade automation must opt in to intentional API/auth changes |
| Key Vault / key rotation | APIM subscription keys stored/rotated | Key creation and rotation skipped in Entra mode | Existing secret-dependent consumers need migration |
| Legacy key-only deployment | Products and subscriptions required | `entraAuth=false` + `authMode=subscription` keeps legacy path | Must regression test real subscription key flows |

## Security conditions that must be verified in Azure

1. Wrong, expired, tampered, cross-tenant or wrong-audience JWT: HTTP 401; no backend attempt.
2. Valid but unlisted managed identity or wrong API: HTTP 403; no backend attempt.
3. Missing/multiple matching contracts: deny; no backend attempt. Contract replacement and revocation must work promptly.
4. Model and pool unauthorized: deny before any provider call, including alias fallback and retry.
5. Main inference, AI Search, Document Intelligence, Realtime, MCP and A2A all obey the same original-caller boundary.
6. Gateway uses its own narrowly scoped backend Managed Identity, never forwards the gateway-audience bearer token.
7. Token/rate quotas: enforce contract-wide caps, distinct contracts independently, not bypassable through alternate APIs.
8. Responses API: cross-caller and cross-contract read/delete/chaining denied.
9. Usage data: verify metrics and every downstream Logic App, Cosmos, dashboard and export retains meaningful attribution.
10. Both deployment modes: a real key-only scenario continues to work after the change.

## Configuration risks

`gatewayAccessContracts` is compiled into a policy fragment using C# and XML snippets. Grant identifiers, caller/API lists, model grants and backend grants are base64-encoded before embedding in XML/C#; numeric quota attributes are converted to integers, and unknown token quota periods become a deployment-invalid literal. This prevents raw configuration strings from directly escaping into policy syntax. The root gateway now uses a sealed Bicep contract type, and the build-time `scripts/validate_gateway_access_contracts.py` validator additionally checks GUID-shaped caller IDs, duplicate identity/API grants, unsafe model/pool identifiers, unsupported fields and quota values. **The validator is only enforced when deployment goes through the documented manifest workflow**; unrestricted direct parameter submissions bypass its Python checks. Actual service-principal ownership and permission still require tenant-level verification.

`allowedModels` and `allowedBackendPools` are per-contract restrictions. An empty model allowlist currently denies JWT model requests. A missing pool allowance is rejected at the backend authorization fragment for JWT calls. Non-inference APIs use the `service` kind to avoid borrowing the MCP `tool` request counter.


## Product policy equivalence gate

The normal default LLM and mixed-asset Product policies use model allowlists, LLM token quotas, MCP/A2A request quotas and response-header settings. These are mapped to the API-level contract resolver and quota fragments. The resolver now also populates the opt-in alert switches and static custom dimensions consumed by existing telemetry. Custom `services[].policyXml` is **rejected** by keyless contract onboarding with a deployment-time `fail()` expression rather than discarded; subscription mode retains the Product XML path.

This does not establish equivalent behavior for dynamic custom expressions, transformations, per-contract content-safety or PII decisions. Those still require explicit migration and runtime verification.

## Full desired-state grant lifecycle

The supported net-new workflow is to review a manifest for each use case, validate and combine all active manifests, and pass the resulting ARM parameter file to the **existing gateway deployment** (not to a separate APIM policy generator). Removing a manifest and redeploying updates/revokes its caller/API grants. The separate Citadel Access Contract module does not mutate the registry or manage revocation automatically. See the lifecycle section of README.md. Prevent ad-hoc gateway deployments from overwriting the authoritative registry with a partial or empty list.

## Decision

**PR #2 must remain draft.** Passing Bicep compilation and source-level invariant tests is not equivalent to a security review or a successful APIM runtime test. Do not promise complete functional/reporting equivalence until customized Product policies, consumer dependencies, configuration safety, and live integration tests are addressed.
