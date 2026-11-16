"""Contract schema, lifecycle, and security regression tests (no Azure deployment required)."""
import importlib.util
import json
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
MODULE = ROOT / "scripts/validate_gateway_access_contracts.py"
spec = importlib.util.spec_from_file_location("gateway_contracts", MODULE)
contracts = importlib.util.module_from_spec(spec)
spec.loader.exec_module(contracts)

OID_A = "11111111-2222-3333-4444-555555555555"
OID_B = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"


def sample(id="LLM-HR-DEV", caller=OID_A, apis=None):
    return {
        "id": id,
        "callers": [caller],
        "apis": apis or ["universal-llm-api", "weather-tool"],
        "allowedModels": ["gpt-4.1"],
        "allowedBackendPools": ["foundry-pool"],
        "tokensPerMinute": 1000,
        "tokenQuota": 100000,
        "tokenQuotaPeriod": "Monthly",
        "requestsPerMinute": 60,
        "requestQuota": 10000,
        "quotaPeriodSeconds": 2592000,
    }


class GatewayContractTests(unittest.TestCase):
    def test_accepts_known_good_contract(self):
        self.assertEqual(contracts.validate_contracts([sample()]), [sample()])

    def test_rejects_ambiguous_caller_and_api_across_contracts(self):
        for caller, api in [(OID_A.upper(), "UNIVERSAL-LLM-API"), (OID_A, "weather-tool")]:
            with self.subTest(caller=caller, api=api):
                other = sample("another-contract", caller, [api])
                with self.assertRaisesRegex(ValueError, "ambiguous"):
                    contracts.validate_contracts([sample(), other])

    def test_different_callers_or_different_apis_are_permitted(self):
        contracts.validate_contracts([sample(), sample("second", OID_B)])
        contracts.validate_contracts([sample(), sample("second", OID_A, ["hr-agent"])])

    def test_duplicate_contract_id_or_entries_fail(self):
        with self.assertRaisesRegex(ValueError, "Duplicate contract id"):
            contracts.validate_contracts([sample(), sample("llm-hr-dev", OID_B)])
        for key in ("callers", "apis", "allowedModels"):
            bad = sample()
            bad[key] = bad[key] * 2
            with self.subTest(key=key), self.assertRaisesRegex(ValueError, "duplicate"):
                contracts.validate_contracts([bad])

    def test_invalid_and_missing_grants_fail(self):
        for key, value in [
            ("callers", []), ("callers", ["not-a-guid"]),
            ("callers", ["00000000-0000-0000-0000-000000000000"]),
            ("apis", []), ("apis", ["bad\"name"]),
            ("allowedModels", []), ("allowedBackendPools", []),
        ]:
            bad = sample()
            bad[key] = value
            with self.subTest(key=key, value=value), self.assertRaises(ValueError):
                contracts.validate_contracts([bad])

    def test_injection_and_unknown_fields_fail(self):
        for value in ('x\" ); return true; //', '<when condition="true">', 'pool,other'):
            bad = sample()
            bad["allowedModels"] = [value]
            with self.subTest(value=value), self.assertRaises(ValueError):
                contracts.validate_contracts([bad])
        bad = sample()
        bad["legacyPolicyXml"] = "<policies/>"
        with self.assertRaisesRegex(ValueError, "Unexpected"):
            contracts.validate_contracts([bad])

    def test_invalid_quotas_rejected_not_silently_defaulted(self):
        for key, value in [
            ("tokensPerMinute", 0), ("tokenQuota", -1), ("tokenQuota", True),
            ("requestsPerMinute", "60"), ("requestQuota", 0),
            ("quotaPeriodSeconds", 299), ("tokenQuotaPeriod", "Forever"),
        ]:
            bad = sample()
            bad[key] = value
            with self.subTest(key=key), self.assertRaises(ValueError):
                contracts.validate_contracts([bad])

    def test_llm_only_requires_llm_limits_and_secondary_requires_request_limits(self):
        a = sample(apis=["universal-llm-api"])
        for key in ("requestsPerMinute", "requestQuota", "quotaPeriodSeconds"):
            a.pop(key)
        contracts.validate_contracts([a])
        b = {"id": "secondary", "callers": [OID_B], "apis": ["search-api"]}
        with self.assertRaisesRegex(ValueError, "requestsPerMinute"):
            contracts.validate_contracts([b])
        b.update(requestsPerMinute=60, requestQuota=1000, quotaPeriodSeconds=300)
        contracts.validate_contracts([b])

    def test_declarative_observability_controls(self):
        item = sample()
        item.update({
            "customDimension1": "cost-center-4711",
            "customDimension2": "HR-service",
            "alertOnAuthFailure": True,
            "alertOnThrottling": False,
            "alertsEnabled": True,
            "enableResponseHeaders": False,
        })
        contracts.validate_contracts([item])
        for key, value in [
            ("alertOnAuthFailure", "true"),
            ("alertsEnabled", 1),
            ("customDimension1", "bad\" />"),
            ("customDimension2", ""),
        ]:
            bad = dict(item)
            bad[key] = value
            with self.subTest(field=key), self.assertRaises(ValueError):
                contracts.validate_contracts([bad])

    def test_full_reconciliation_and_revocation(self):
        with tempfile.TemporaryDirectory() as temp:
            folder = Path(temp)
            a = folder / "a.json"
            b = folder / "b.json"
            output = folder / "gateway-parameters.json"
            a.write_text(json.dumps({"contracts": [sample()]}), encoding="utf-8")
            b.write_text(json.dumps({"contracts": [sample("second", OID_B)]}), encoding="utf-8")
            all_contracts = contracts.load_manifests([a, b])
            contracts.write_parameters(all_contracts, output)
            current = json.loads(output.read_text())["parameters"]["gatewayAccessContracts"]["value"]
            self.assertEqual({x["id"] for x in current}, {"LLM-HR-DEV", "second"})
            # Removing a manifest and regenerating represents revocation.
            contracts.write_parameters(contracts.load_manifests([a]), output)
            current = json.loads(output.read_text())["parameters"]["gatewayAccessContracts"]["value"]
            self.assertEqual([x["id"] for x in current], ["LLM-HR-DEV"])

    def test_conflicting_manifests_do_not_change_existing_output(self):
        with tempfile.TemporaryDirectory() as temp:
            folder = Path(temp)
            output = folder / "gateway.json"
            a = folder / "a.json"
            b = folder / "b.json"
            contracts.write_parameters([sample()], output)
            before = output.read_text()
            a.write_text(json.dumps([sample()]))
            b.write_text(json.dumps([sample("conflict")]))
            with self.assertRaisesRegex(ValueError, "ambiguous"):
                contracts.load_manifests([a, b])
            self.assertEqual(output.read_text(), before)


if __name__ == "__main__":
    unittest.main()
