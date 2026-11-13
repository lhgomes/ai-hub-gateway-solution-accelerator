"""Pure local checks for the JWT-only policy overlay (no Azure resources required)."""
import copy
import importlib.util
from pathlib import Path
import tempfile
import sys
import unittest
import xml.etree.ElementTree as ET

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts"))
SPEC = importlib.util.spec_from_file_location("entra_only_auth", ROOT / "scripts/entra_only_auth.py")
auth = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(auth)

TENANT = "11111111-1111-1111-1111-111111111111"
OID1 = "22222222-2222-2222-2222-222222222222"
OID2 = "33333333-3333-3333-3333-333333333333"


def sample():
    return {
        "tenantId": TENANT,
        "audience": "api://11111111-4444-4444-4444-111111111111",
        "contracts": [{
            "id": "LLM-HR-DEV", "callers": [OID1],
            "apis": ["azure-openai-api", "universal-llm-api", "unified-ai-api"],
            "allowedModels": ["gpt-4.1"], "allowedBackendPools": ["foundry-eu"],
            "tokensPerMinute": 1000, "tokenQuota": 100000,
            "tokenQuotaPeriod": "Monthly"
        }]
    }


class EntraOnlyGenerationTests(unittest.TestCase):
    def test_generation_and_fragment_integrity(self):
        with tempfile.TemporaryDirectory() as d:
            paths = auth.generate(sample(), Path(d))
            self.assertEqual(len(paths), 14)
            for name in paths:
                ET.parse(Path(d) / name)
            fragment = (Path(d) / "frag-entra-contract-auth.xml").read_text()
            self.assertIn("<validate-jwt", fragment)
            self.assertIn('name="callerId"', fragment)
            self.assertIn('name="contractId"', fragment)
            self.assertIn('code="403"', fragment)
            for api in auth.API_FILES:
                policy = (Path(d) / f"api-{api}-policy.xml").read_text()
                self.assertIn('fragment-id="entra-contract-auth"', policy)
                self.assertIn('fragment-id="entra-contract-limits"', policy)
                self.assertIn('fragment-id="entra-validate-model-access"', policy)
                self.assertIn('fragment-id="entra-raise-alert-events"', policy)
                self.assertIn('fragment-id="entra-authorize-target-pool"', policy)
                self.assertIn('fragment-id="entra-responses-id-security"', policy)
                self.assertNotIn('fragment-id="security-handler"', policy)
                self.assertNotIn('<set-variable name="allowedBackendPools" value=""', policy)
            unified = (Path(d) / "api-unified-ai-api-policy.xml").read_text()
            self.assertNotIn("product_required", unified)
            self.assertLess(unified.index('fragment-id="entra-contract-auth"'),
                            unified.index('fragment-id="request-processor"'))

    def test_duplicate_grant_fails_closed(self):
        cfg = sample()
        other = copy.deepcopy(cfg["contracts"][0])
        other["id"] = "SECOND-CONTRACT"
        cfg["contracts"].append(other)
        with self.assertRaisesRegex(ValueError, "Ambiguous"):
            auth.validate(cfg)

    def test_undeclared_apis_rejected(self):
        cfg = sample()
        cfg["contracts"][0]["apis"] = ["unknown-api"]
        with self.assertRaisesRegex(ValueError, "declared published asset"):
            auth.validate(cfg)

    def test_empty_grants_and_unrestricted_models_rejected(self):
        for field in ("callers", "apis", "allowedModels", "allowedBackendPools"):
            with self.subTest(field=field):
                cfg = sample()
                cfg["contracts"][0][field] = []
                with self.assertRaises(ValueError):
                    auth.validate(cfg)

    def test_values_must_be_valid(self):
        for field, value in (("tokensPerMinute", 0), ("tokenQuota", True),
                             ("tokenQuotaPeriod", "EveryMinute")):
            with self.subTest(field=field):
                cfg = sample()
                cfg["contracts"][0][field] = value
                with self.assertRaises(ValueError):
                    auth.validate(cfg)

    def test_distinct_callers_can_share_one_contract(self):
        cfg = sample()
        cfg["contracts"][0]["callers"].append(OID2)
        auth.validate(cfg)
        xml = auth.auth_fragment(cfg)
        ET.fromstring(xml)
        self.assertIn(OID1, xml)
        self.assertIn(OID2, xml)


    def test_deployment_preflight_never_relaxes_subscription_settings(self):
        import deploy_entra_only_auth as deployment
        rid = ("/subscriptions/aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa/"
               "resourceGroups/test/providers/Microsoft.ApiManagement/service/test-isolated")
        calls = []
        def safe_rest(method, url, body=None):
            calls.append((method, url))
            if url.endswith("/products?api-version=2024-05-01"):
                return {"value": []}
            return {"properties": {"subscriptionRequired": False}}
        self.assertTrue(deployment.preflight(rid, ["unified-ai-api"], safe_rest))
        self.assertTrue(all(method == "GET" for method, _ in calls))
        def legacy_rest(method, url, body=None):
            return {"properties": {"subscriptionRequired": True}}
        with self.assertRaisesRegex(ValueError, "subscriptionRequired=false"):
            deployment.preflight(rid, ["unified-ai-api"], legacy_rest)
        def product_rest(method, url, body=None):
            return {"value": [{"id": "legacy-product"}]} if "/products?" in url else {
                "properties": {"subscriptionRequired": False}}
        with self.assertRaisesRegex(ValueError, "APIM Products"):
            deployment.preflight(rid, ["unified-ai-api"], product_rest)


    def test_mcp_a2a_contract_governance(self):
        cfg = sample()
        cfg["assetKinds"] = {"weather-tool": "tool", "hr-agent": "agent"}
        cfg["contracts"][0]["apis"] += ["weather-tool", "hr-agent"]
        cfg["contracts"][0].update({
            "requestsPerMinute": 60, "requestQuota": 10000,
            "quotaPeriodSeconds": 2592000,
        })
        with tempfile.TemporaryDirectory() as d:
            files = auth.generate(cfg, Path(d))
            self.assertEqual(len(files), 14)
            for item in files:
                ET.parse(Path(d) / item)
            quota = (Path(d) / "frag-entra-contract-request-limits.xml").read_text()
            self.assertIn("rate-limit-by-key", quota)
            self.assertIn("quota-by-key", quota)
            self.assertIn("assetKind", quota)
            for name in ("mcp", "a2a"):
                usage = (Path(d) / f"frag-entra-{name}-usage.xml").read_text()
                self.assertIn("contractId", usage)
                self.assertIn("callerId", usage)

    def test_asset_kind_and_quota_validation(self):
        cfg = sample()
        cfg["assetKinds"] = {"weather-tool": "tool"}
        cfg["contracts"][0]["apis"] += ["weather-tool"]
        with self.assertRaisesRegex(ValueError, "requestsPerMinute"):
            auth.validate(cfg)
        cfg["contracts"][0].update({
            "requestsPerMinute": 30, "requestQuota": 500,
            "quotaPeriodSeconds": 300,
        })
        auth.validate(cfg)
        cfg["assetKinds"]["weather-tool"] = "unexpected"
        with self.assertRaisesRegex(ValueError, "assetKinds"):
            auth.validate(cfg)

    def test_publisher_modules_use_jwt_mode(self):
        base = ROOT / "bicep/infra/citadel-publish-contracts"
        main = (base / "main.bicep").read_text()
        self.assertIn("authMode?", main)
        for module in ("publishMcpExisting.bicep", "publishMcpFromApi.bicep",
                       "publishA2aAgent.bicep"):
            source = (base / "modules" / module).read_text()
            self.assertIn("param entraOnly bool = false", source)
            self.assertIn("entra-contract-auth", source)
            self.assertIn("entra-contract-request-limits", source)
            self.assertIn("subscriptionRequired: entraOnly ? false :", source)

    def test_foundry_keyless_connection(self):
        bicep = (ROOT / "bicep/infra/entra-only-auth/foundry-connection.bicep").read_text()
        self.assertIn("includeSubscriptionKey: false", bicep)
        self.assertIn("ProjectManagedIdentity", bicep)

    def test_caller_token_does_not_become_backend_key(self):
        xml = auth.auth_fragment(sample())
        self.assertIn('name="Authorization" exists-action="delete"', xml)
        self.assertIn('name="api-key" exists-action="delete"', xml)
        self.assertIn('name="Ocp-Apim-Subscription-Key" exists-action="delete"', xml)
        self.assertIn('output-token-variable-name="validated-jwt"', xml)


if __name__ == "__main__":
    unittest.main()
