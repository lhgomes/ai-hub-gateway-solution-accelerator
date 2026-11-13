"""Pure local checks for the JWT-only policy overlay (no Azure resources required)."""
import copy
import importlib.util
from pathlib import Path
import tempfile
import unittest
import xml.etree.ElementTree as ET

ROOT = Path(__file__).resolve().parents[2]
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
            self.assertEqual(len(paths), 8)
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
        with self.assertRaisesRegex(ValueError, "verified inference APIs"):
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

    def test_caller_token_does_not_become_backend_key(self):
        xml = auth.auth_fragment(sample())
        self.assertIn('name="api-key" exists-action="delete"', xml)
        self.assertIn('name="Ocp-Apim-Subscription-Key" exists-action="delete"', xml)
        self.assertIn('output-token-variable-name="validated-jwt"', xml)


if __name__ == "__main__":
    unittest.main()
