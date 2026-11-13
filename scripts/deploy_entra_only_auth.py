#!/usr/bin/env python3
"""Deploy the generated JWT-only API overlay to an ISOLATED, preconfigured APIM.

The target must already contain the upstream accelerator's APIs, backend pools,
routing fragments, monitoring, and Managed Identity permissions. This tool
never creates APIs or turns off subscription checks. It refuses endpoints that
still require subscriptions or are associated with APIM products.
"""
from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
import tempfile
from pathlib import Path

from entra_only_auth import API_FILES, generate, validate

API_VERSION = "2024-05-01"
RESOURCE_RE = re.compile(
    r"^/subscriptions/([0-9a-fA-F-]{36})/resourceGroups/([^/]+)/providers/Microsoft.ApiManagement/service/([^/]+)$",
    re.I,
)

FRAGMENTS = {
    "entra-contract-auth": "frag-entra-contract-auth.xml",
    "entra-contract-limits": "frag-entra-contract-limits.xml",
    "entra-authorize-target-pool": "frag-entra-authorize-target-pool.xml",
    "entra-responses-id-security": "frag-entra-responses-id-security.xml",
    "entra-responses-id-cache-store": "frag-entra-responses-id-cache-store.xml",
    "entra-set-llm-usage": "frag-entra-set-llm-usage.xml",
}


def az_rest(method, url, body=None):
    cmd = ["az", "rest", "--method", method, "--url", url, "--output", "json"]
    if body is None:
        result = subprocess.run(cmd, check=True, capture_output=True, text=True)
    else:
        with tempfile.TemporaryDirectory() as d:
            path = Path(d) / "body.json"
            path.write_text(json.dumps(body), encoding="utf-8")
            result = subprocess.run(
                cmd + ["--headers", "Content-Type=application/json", "If-Match=*", "--body", "@" + str(path)],
                check=True, capture_output=True, text=True,
            )
    return json.loads(result.stdout) if result.stdout.strip() else {}


def preflight(apim_id, api_names, rest=az_rest):
    if not RESOURCE_RE.fullmatch(apim_id):
        raise ValueError("Invalid APIM resource ID")
    api_base = "https://management.azure.com" + apim_id + "/apis/"
    for api in api_names:
        details = rest("GET", api_base + api + "?api-version=" + API_VERSION)
        if details.get("properties", {}).get("subscriptionRequired") is not False:
            raise ValueError(f"{api}: API must already have subscriptionRequired=false")
        products = rest("GET", api_base + api + "/products?api-version=" + API_VERSION)
        if products.get("value"):
            raise ValueError(f"{api}: API belongs to APIM Products; use a dedicated keyless gateway/API copy")
    return True


def deploy(apim_id, generated_dir, api_names, rest=az_rest):
    base = "https://management.azure.com" + apim_id
    # All fragments must exist before any API policy is replaced.
    for frag_id, filename in FRAGMENTS.items():
        policy = (generated_dir / filename).read_text(encoding="utf-8")
        rest("PUT", base + "/policyFragments/" + frag_id + "?api-version=" + API_VERSION, {
            "properties": {"format": "rawxml", "value": policy,
                           "description": "Generated isolated JWT-only APIM policy"}
        })
    for api in api_names:
        policy = (generated_dir / f"api-{api}-policy.xml").read_text(encoding="utf-8")
        rest("PUT", base + "/apis/" + api + "/policies/policy?api-version=" + API_VERSION, {
            "properties": {"format": "rawxml", "value": policy}
        })


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--contracts", type=Path, required=True, help="Non-secret, exact identity-to-contract grant JSON")
    p.add_argument("--output", type=Path, required=True, help="Directory for generated XML")
    p.add_argument("--apim-resource-id", help="Exact existing APIM ARM resource ID (required with --apply)")
    p.add_argument("--apply", action="store_true", help="Explicitly deploy after a safety preflight")
    p.add_argument("--confirm-isolated-gateway", action="store_true",
                   help="Acknowledge this targets a dedicated, non-legacy gateway")
    args = p.parse_args()
    config = validate(json.loads(args.contracts.read_text(encoding="utf-8")))
    files = generate(config, args.output)
    print(f"Generated and XML-validated {len(files)} files in {args.output}")
    if not args.apply:
        print("Dry run only: no Azure resource was modified.")
        return
    if not args.confirm_isolated_gateway or not args.apim_resource_id:
        p.error("--apply requires --confirm-isolated-gateway and --apim-resource-id")
    selected = sorted({api for c in config["contracts"] for api in c["apis"]})
    preflight(args.apim_resource_id, selected)
    deploy(args.apim_resource_id, args.output, selected)
    print("Deployed JWT-only overlay. Validate APIM policy compilation and runtime tests before production.")


if __name__ == "__main__":
    main()
