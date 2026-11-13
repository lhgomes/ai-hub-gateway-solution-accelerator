"""Source-level checks for native Entra authentication. Azure runtime tests remain separate."""
from pathlib import Path
import re
import unittest
import xml.etree.ElementTree as ET

ROOT = Path(__file__).resolve().parents[2]
BICEP = ROOT / "bicep/infra"
POLICY = BICEP / "modules/apim/policies"


def read(path):
    return path.read_text(encoding="utf-8")


class NativeEntraAuthTests(unittest.TestCase):
    def test_single_inference_policy_path(self):
        for name in ("azure-open-ai-api-policy.xml", "universal-llm-api-policy-v2.xml",
                     "unified-ai-api-policy.xml"):
            with self.subTest(name=name):
                xml = read(POLICY / name)
                self.assertEqual(xml.count('fragment-id="security-handler"'), 1)
                self.assertEqual(xml.count('fragment-id="resolve-access-contract"'), 1)
                self.assertEqual(xml.count('fragment-id="enforce-contract-quota"'), 1)
                self.assertIn('fragment-id="validate-model-access"', xml)
                self.assertNotIn('<set-variable name="allowedBackendPools" value=""', xml)

    def test_authentication_must_precede_request_processing(self):
        xml = read(POLICY / "unified-ai-api-policy.xml")
        self.assertLess(xml.index('fragment-id="security-handler"'),
                        xml.index('fragment-id="request-processor"'))
        self.assertIn('auth-type", "") != "jwt"', xml)

    def test_jwt_grants_are_resolved_before_backend_use(self):
        auth = read(POLICY / "frag-security-handler.xml")
        self.assertIn('name="validated-jwt"', auth)
        self.assertIn('name="callerId"', auth)
        self.assertIn('name="callerOid"', auth)
        policy = read(BICEP / 'modules/apim/policy-fragments.bicep')
        self.assertIn('jwtContractResolutionXml', policy)
        self.assertIn('matches.Count == 1', policy)
        self.assertIn('name="contractId"', policy)
        self.assertIn('name="Authorization" exists-action="delete"', auth)
        self.assertIn('name="api-key" exists-action="delete"', auth)
        self.assertNotIn('x-access-contract', auth)

    def test_governance_reuses_one_contract_identity(self):
        quota = read(BICEP / "modules/apim/policy-fragments.bicep")
        self.assertIn("var jwtQuotaCases", quota)
        self.assertIn("contract.id", quota)
        self.assertIn("context.Variables[&quot;contractId&quot;]", quota)
        model = read(POLICY / "frag-validate-model-access.xml")
        self.assertIn('auth-type', model)
        backend = read(POLICY / "frag-set-backend-authorization.xml")
        self.assertIn("allowedBackendPools", backend)
        self.assertIn("Backend pool not granted", backend)

    def test_same_bicep_deployment_provisions_auth_and_contracts(self):
        for f in (BICEP / "main.bicep", BICEP / "resources.bicep",
                  BICEP / "modules/apim/apim.bicep"):
            self.assertIn("gatewayAccessContracts", read(f))
        apim = read(BICEP / "modules/apim/apim.bicep")
        self.assertIn("Gateway-Auth-Mode", apim)
        self.assertNotIn("Gateway-Access-Contracts", apim)
        self.assertIn("resolveAccessContractFragment", read(BICEP / "modules/apim/policy-fragments.bicep"))


    def test_published_assets_use_gateway_jwt_and_shared_governance(self):
        folder = BICEP / 'citadel-publish-contracts'
        for filename in ('baseline-mcp-policy.xml', 'baseline-a2a-policy.xml'):
            xml = read(folder / 'policies' / filename)
            self.assertIn('fragment-id="resolve-access-contract"', xml)
            self.assertIn('fragment-id="enforce-contract-quota"', xml)
        a2a = read(folder / 'policies/baseline-a2a-policy.xml')
        self.assertIn('fragment-id="security-handler"', a2a)
        pub = read(folder / 'main.bicep')
        self.assertIn("param authMode string = 'entra'", pub)
        self.assertIn('sourceManagedIdentityAudience', pub)
        src = read(folder / 'modules/publishMcpFromApi.bicep')
        self.assertIn('authentication-managed-identity', src)
        self.assertIn('sourceTokenPolicy', src)

    def test_keyless_foundry_onboarding(self):
        main = read(BICEP / 'citadel-access-contracts/main.bicep')
        module = read(BICEP / 'citadel-access-contracts/modules/foundryConnection.bicep')
        self.assertIn("param authMode string = 'entra'", main)
        self.assertIn('includeSubscriptionKey: authMode ==', main)
        self.assertIn("authMode == 'entra' ? gatewayAudience", main)
        self.assertIn('includeSubscriptionKey bool = false', module)

    def test_v1_and_v2_issuers_for_managed_identity(self):
        xml = read(POLICY / 'frag-security-handler.xml')
        self.assertIn('JWT-IssuerV1', xml)
        self.assertIn('JWT-OpenIdConfigUrlV1', xml)

    def test_managed_identity_gateway_audience(self):
        policy = read(POLICY / "frag-security-handler.xml")
        self.assertIn("<audience>{{audience}}</audience>", policy)
        self.assertIn("<audience>{{JWT-AppRegistrationId}}</audience>", policy)
        self.assertIn("name=\"callerId\"", policy)
        self.assertIn('name="Authorization" exists-action="delete"', policy)

    def test_subscription_free_secondary_apis_require_early_authorization(self):
        # These gateway APIs can be subscription-free with entraAuth=true.
        # The original caller must be checked before APIM acquires backend credentials.
        for filename in (
            "ai-search-index-api-policy.xml",
            "ai-search-service-api-policy.xml",
            "doc-intelligence-api-policy.xml",
            "openai-realtime-policy.xml",
            "ai-model-inference-api-policy.xml",
        ):
            with self.subTest(api=filename):
                xml = read(POLICY / filename)
                self.assertEqual(xml.count('fragment-id="security-handler"'), 1)
                self.assertEqual(xml.count('fragment-id="resolve-access-contract"'), 1)
                self.assertEqual(xml.count('fragment-id="enforce-contract-quota"'), 1)
                self.assertLess(xml.index('fragment-id="security-handler"'),
                                xml.index('fragment-id="resolve-access-contract"'))
                self.assertLess(xml.index('fragment-id="resolve-access-contract"'),
                                xml.index('authentication-managed-identity'))
                self.assertIn('<set-variable name="assetKind" value="service" />', xml)

    def test_missing_jwt_model_grant_is_denied(self):
        xml = read(POLICY / "frag-validate-model-access.xml")
        self.assertIn('== "jwt"; // fail closed for JWT contracts', xml)

    def test_realtime_policy_never_dereferences_missing_apim_product(self):
        xml = read(POLICY / "openai-realtime-policy.xml")
        self.assertNotIn("context.Product.Name", xml)
        self.assertIn("context.Product?.Name", xml)

    def test_legacy_usage_metrics_keep_existing_field_names(self):
        # Existing ingestion workflows still read productName/appId/subscriptionId.
        for name in (
            "frag-ai-usage.xml",
            "frag-openai-usage.xml",
            "frag-openai-usage-streaming.xml",
            "frag-llm-usage.xml",
            "frag-set-llm-usage.xml",
            "frag-mcp-usage.xml",
            "frag-a2a-usage.xml",
        ):
            with self.subTest(fragment=name):
                xml = read(POLICY / name)
                self.assertIn("contractId", xml)
                self.assertTrue("callerId" in xml or "appId" in xml)
        for name in ("llm", "mcp", "agent"):
            workflow = read(ROOT / "src/usage-ingestion-logicapp" /
                            f"{name}-usage-ingestion/workflow.json")
            self.assertIn("productName", workflow)
            self.assertIn("appId", workflow)

    def test_gateway_auth_mode_selection_is_backwards_compatible(self):
        apim = read(BICEP / "modules/apim/apim.bicep")
        self.assertIn("value: entraAuth ? 'entra' : 'subscription'", apim)
        self.assertIn("allowSubscriptionKey: entraAuth ? false:true", apim)
        access = read(BICEP / "citadel-access-contracts/modules/apimOnboardService.bicep")
        self.assertIn("if (authMode == 'subscription')", access)

    def test_grant_values_are_safe_in_policy_xml(self):
        source = read(BICEP / "modules/apim/policy-fragments.bicep")
        self.assertIn("base64(string(contract.callers))", source)
        self.assertIn("base64(string(contract.apis))", source)
        self.assertIn("base64(contract.id)", source)
        self.assertIn("base64(join(contract.?allowedModels", source)
        self.assertIn("base64(join(contract.?allowedBackendPools", source)
        self.assertIn("int(contract.?tokensPerMinute", source)
        self.assertIn("int(contract.?requestQuota", source)
        self.assertIn("'INVALID'", source)

    def test_backend_onboarding_cannot_overwrite_canonical_auth(self):
        content = read(BICEP / "llm-backend-onboarding/modules/llm-policy-fragments.bicep")
        for name in (
            "frag-set-backend-authorization.xml", "frag-set-llm-usage.xml",
            "frag-validate-model-access.xml", "frag-responses-id-security.xml",
            "frag-responses-id-cache-store.xml",
        ):
            self.assertIn("../../modules/apim/policies/" + name, content)
            self.assertNotIn("'./policies/" + name + "'", content)

    def test_upgrade_preserves_existing_auth_settings_unless_explicitly_selected(self):
        source = read(BICEP / "apim-gateway-upgrade/main.bicep")
        self.assertIn("param authMode string = 'preserve'", source)
        self.assertIn("= if (updatePolicyFragments && authMode != 'preserve')", source)
        self.assertIn("deployContractFragments: authMode != 'preserve'", source)
        self.assertIn("allowSubscriptionKey: authMode != 'entra'", source)
        self.assertIn("entraAuth: authMode == 'entra'", source)
        self.assertIn("JWT-OpenIdConfigUrlV1", source)
        self.assertIn("JWT-IssuerV1", source)
        self.assertIn("authMode != 'preserve'", source)
        fragments = read(BICEP / "modules/apim/policy-fragments.bicep")
        self.assertIn("if (deployContractFragments)", fragments)

    def test_response_ownership_keeps_caller_and_contract(self):
        for name in ("frag-responses-id-security.xml",
                     "frag-responses-id-cache-store.xml"):
            xml = read(POLICY / name)
            self.assertIn('GetValueOrDefault<string>("callerId"', xml)
            self.assertIn('GetValueOrDefault<string>("contractId"', xml)


if __name__ == "__main__":
    unittest.main()
