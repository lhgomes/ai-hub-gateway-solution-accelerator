#!/usr/bin/env python3
"""Validate and aggregate declarative Entra Access Contracts into one gateway parameter.

This is a build-time input validator, NOT a second runtime registry or APIM policy generator.
One invocation must include every active contract; removed entries are revoked on full gateway
redeployment. Never concatenate this output with the current APIM state.
"""
import argparse
import json
import os
import re
import tempfile
from pathlib import Path

GUID = re.compile(r"^[0-9a-fA-F]{8}-(?:[0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}$")
IDENTIFIER = re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9._-]{0,79}$")
MODEL = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/+-]{0,127}$")
DIMENSION = re.compile(r"^[A-Za-z0-9][A-Za-z0-9 ._:/+-]{0,127}$")
ALERT_FIELDS = {"alertsEnabled", "alertOnThrottling", "alertOnQuotaExceeded", "alertOnBackendFailure", "alertOnAuthFailure", "alertOnContentSafety", "alertOnPiiFailure", "enableResponseHeaders"}
PERIODS = {"Hourly", "Daily", "Weekly", "Monthly", "Yearly"}
INFERENCE_APIS = {"universal-llm-api", "azure-openai-api", "unified-ai-api"}
FIELDS = {
    "id", "callers", "apis", "allowedModels", "allowedBackendPools",
    "tokensPerMinute", "tokenQuota", "tokenQuotaPeriod",
    "requestsPerMinute", "requestQuota", "quotaPeriodSeconds",
    "customDimension1", "customDimension2", *ALERT_FIELDS,
}


def _nonempty_strings(item, key, pattern):
    values = item.get(key)
    if not isinstance(values, list) or not values:
        raise ValueError(f"{item.get('id', 'contract')}: {key} must be a nonempty array")
    if any(not isinstance(v, str) or not pattern.fullmatch(v) for v in values):
        raise ValueError(f"{item.get('id', 'contract')}: invalid {key} value")
    if len({v.lower() for v in values}) != len(values):
        raise ValueError(f"{item.get('id', 'contract')}: duplicate {key} value")
    return values


def _positive(item, key, required):
    value = item.get(key)
    if value is None and not required:
        return
    if type(value) is not int or value <= 0 or value > 2_147_483_647:
        raise ValueError(f"{item['id']}: {key} must be a positive 32-bit integer")


def validate_contracts(contracts):
    if not isinstance(contracts, list):
        raise ValueError("Access Contracts must be an array")
    seen_ids = set()
    seen_grants = set()
    result = []
    for item in contracts:
        if not isinstance(item, dict):
            raise ValueError("Each Access Contract must be an object")
        extra = set(item) - FIELDS
        if extra:
            raise ValueError(f"Unexpected Access Contract fields: {', '.join(sorted(extra))}")
        cid = item.get("id")
        if not isinstance(cid, str) or not IDENTIFIER.fullmatch(cid):
            raise ValueError("Contract id must be a safe nonempty identifier (max 80 characters)")
        if cid.lower() in seen_ids:
            raise ValueError(f"Duplicate contract id: {cid}")
        seen_ids.add(cid.lower())
        callers = _nonempty_strings(item, "callers", GUID)
        apis = _nonempty_strings(item, "apis", IDENTIFIER)
        if any(c.lower() == "00000000-0000-0000-0000-000000000000" for c in callers):
            raise ValueError(f"{cid}: the all-zero caller object ID is invalid")
        for caller in callers:
            for api in apis:
                pair = (caller.lower(), api.lower())
                if pair in seen_grants:
                    raise ValueError(f"{cid}: ambiguous caller/API grant: {caller}, {api}")
                seen_grants.add(pair)

        is_llm = bool(INFERENCE_APIS.intersection({a.lower() for a in apis}))
        is_other = bool({a.lower() for a in apis} - INFERENCE_APIS)
        if is_llm:
            _nonempty_strings(item, "allowedModels", MODEL)
            _nonempty_strings(item, "allowedBackendPools", IDENTIFIER)
            for key in ("tokensPerMinute", "tokenQuota"):
                _positive(item, key, required=True)
            if item.get("tokenQuotaPeriod") not in PERIODS:
                raise ValueError(f"{cid}: invalid tokenQuotaPeriod")
        if is_other:
            for key in ("requestsPerMinute", "requestQuota", "quotaPeriodSeconds"):
                _positive(item, key, required=True)
            if item["quotaPeriodSeconds"] < 300:
                raise ValueError(f"{cid}: quotaPeriodSeconds must be at least 300")
        # Reject inconsistent optional values rather than silently ignoring them.
        for key in ("tokensPerMinute", "tokenQuota", "requestsPerMinute",
                    "requestQuota", "quotaPeriodSeconds"):
            if key in item:
                _positive(item, key, required=True)
        if "tokenQuotaPeriod" in item and item["tokenQuotaPeriod"] not in PERIODS:
            raise ValueError(f"{cid}: invalid tokenQuotaPeriod")
        for field, pattern in (("allowedModels", MODEL), ("allowedBackendPools", IDENTIFIER)):
            if field in item:
                _nonempty_strings(item, field, pattern)
        for dim in ("customDimension1", "customDimension2"):
            if dim in item and (not isinstance(item[dim], str) or
                                not DIMENSION.fullmatch(item[dim])):
                raise ValueError(f"{cid}: invalid {dim}")
        for alert in ALERT_FIELDS:
            if alert in item and type(item[alert]) is not bool:
                raise ValueError(f"{cid}: {alert} must be boolean")
        result.append(item)
    return sorted(result, key=lambda c: c["id"].lower())


def load_manifests(paths):
    all_contracts = []
    if not paths:
        raise ValueError("Supply one or more complete Access Contract manifests")
    for path in paths:
        contents = json.loads(Path(path).read_text(encoding="utf-8"))
        if isinstance(contents, dict):
            if set(contents) != {"contracts"}:
                raise ValueError(f"{path}: expected a 'contracts' array only")
            contents = contents["contracts"]
        if not isinstance(contents, list):
            raise ValueError(f"{path}: expected an array")
        all_contracts.extend(contents)
    return validate_contracts(all_contracts)


def write_parameters(contracts, path):
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    data = json.dumps({
        "$schema": "https://schema.management.azure.com/schemas/2019-04-01/deploymentParameters.json#",
        "contentVersion": "1.0.0.0",
        "parameters": {"gatewayAccessContracts": {"value": contracts}},
    }, indent=2) + "\n"
    fd, temp = tempfile.mkstemp(prefix=".gateway-contracts-", dir=str(target.parent), text=True)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as out:
            out.write(data)
        os.replace(temp, target)
    finally:
        if os.path.exists(temp):
            os.unlink(temp)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", action="append", required=True,
                        help="Complete desired-state manifest (repeat for multiple teams)")
    parser.add_argument("--output", required=True,
                        help="Azure CLI parameter override file for gatewayAccessContracts")
    args = parser.parse_args()
    contracts = load_manifests(args.manifest)
    write_parameters(contracts, args.output)
    print(f"Validated {len(contracts)} Access Contracts; wrote {args.output}")


if __name__ == "__main__":
    main()
