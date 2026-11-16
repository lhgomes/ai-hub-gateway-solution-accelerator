#!/usr/bin/env python3
"""Opt-in Azure APIM Entra authorization smoke test; does not deploy resources.

Tokens come exclusively from operator environment variables. No token or body is printed,
and HTTP redirects are disabled to prevent credentials crossing hosts.
"""
import argparse
import os
import sys
import urllib.error
import urllib.request
from urllib.parse import urlsplit


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def endpoint(url):
    u = urlsplit(url)
    if u.scheme != "https" or not u.netloc or u.username or u.password or u.fragment:
        raise ValueError("Endpoint must be an explicit HTTPS URL without credentials or fragment")
    if u.query:
        raise ValueError("Do not put credentials or query parameters in the endpoint URL")
    return url


def invoke(url, token, timeout=20):
    headers = {"Accept": "application/json"}
    if token is not None:
        headers["Authorization"] = "Bearer " + token
    req = urllib.request.Request(endpoint(url), headers=headers, method="GET")
    opener = urllib.request.build_opener(NoRedirect())
    try:
        with opener.open(req, timeout=timeout) as response:
            return response.status
    except urllib.error.HTTPError as exc:
        return exc.code


def run(url, authorized_token=None, denied_token=None, authorized_status=200):
    """Verify negative cases and, when supplied, a positive authorized case."""
    tests = [
        ("no bearer token", None, 401),
        ("malformed bearer token", "not.a.jwt", 401),
    ]
    if denied_token:
        tests.append(("valid-but-ungranted caller", denied_token, 403))
    if authorized_token:
        tests.append(("authorized caller", authorized_token, authorized_status))
    failures = []
    for name, token, expected in tests:
        observed = invoke(url, token)
        outcome = "PASS" if observed == expected else "FAIL"
        print(f"{outcome}: {name}: HTTP {observed} (expected {expected})")
        if observed != expected:
            failures.append(name)
    return len(failures)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--url", required=True, help="Full HTTPS URL to a safe, read-only APIM operation")
    parser.add_argument("--authorized-token-env", help="Environment variable containing an authorized MI token")
    parser.add_argument("--denied-token-env", help="Environment variable containing a valid but ungranted MI token")
    parser.add_argument("--authorized-status", type=int, default=200)
    args = parser.parse_args()
    try:
        endpoint(args.url)
        if args.denied_token_env and not os.environ.get(args.denied_token_env):
            raise ValueError("Denied caller token environment variable is unset")
        if args.authorized_token_env and not os.environ.get(args.authorized_token_env):
            raise ValueError("Authorized caller token environment variable is unset")
        failures = run(
            args.url,
            authorized_token=os.environ.get(args.authorized_token_env) if args.authorized_token_env else None,
            denied_token=os.environ.get(args.denied_token_env) if args.denied_token_env else None,
            authorized_status=args.authorized_status,
        )
    except (ValueError, urllib.error.URLError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
