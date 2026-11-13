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
| Custom Product policy XML | Runs in Product scope for valid Product subscription | **Not migrated automatically.** Entra grants resolve at API scope; Product policy is not a substitute | Customized policies, response headers, transformations, safety and per-product alerts require individual migration |
| Product catalog / developer portal | Product resources and subscriptions exist | Access Contract onboarding skips Product/subscription creation in Entra mode | Portal, catalog, approval flows, custom reports and other Product-centric functions may change |
| Contract onboarding | Access Contract deployment provisions APIM Products/subscription keys | Contract deployment can create endpoints and keyless Foundry connections; **it does not update gatewayAccessContracts** | Operators must update and redeploy complete gateway desired state for new grants and revocations |
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

`gatewayAccessContracts` is compiled into a policy fragment using C# and XML snippets. Grant identifiers, caller/API lists, model grants and backend grants are base64-encoded before embedding in XML/C#; numeric quota attributes are converted to integers, and unknown token quota periods become a deployment-invalid literal. This prevents raw configuration strings from directly escaping into policy syntax. **This is not full input validation.** A validated grant schema is still a preproduction requirement, and callers must be actual Entra service-principal object GUIDs. Duplicate identity/API grants fail closed at runtime, but should also be rejected during deployment.

`allowedModels` and `allowedBackendPools` are per-contract restrictions. An empty model allowlist currently denies JWT model requests. A missing pool allowance is rejected at the backend authorization fragment for JWT calls. Non-inference APIs use the `service` kind to avoid borrowing the MCP `tool` request counter.

## Decision

**PR #2 must remain draft.** Passing Bicep compilation and source-level invariant tests is not equivalent to a security review or a successful APIM runtime test. Do not promise complete functional/reporting equivalence until customized Product policies, consumer dependencies, configuration safety, and live integration tests are addressed.
