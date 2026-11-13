#!/usr/bin/env python3
"""Generate an isolated JWT-only APIM inference policy overlay.

This does NOT deploy or modify the existing APIM gateway. Apply only to a
separate gateway / deliberately isolated API copies after reviewing output.
Contracts are an explicit allowlist; validation rejects ambiguous grants.
"""
from __future__ import annotations

import argparse
import html
import json
import re
from pathlib import Path
from xml.sax.saxutils import escape, quoteattr
import xml.etree.ElementTree as ET

API_FILES = {
    "azure-openai-api": "azure-open-ai-api-policy.xml",
    "universal-llm-api": "universal-llm-api-policy-v2.xml",
    "unified-ai-api": "unified-ai-api-policy.xml",
}
PERIODS = {"Hourly", "Daily", "Weekly", "Monthly", "Yearly"}
ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "bicep/infra/modules/apim/policies"


def normalize_upstream_policy_xml(content):
    """Escape C# quote/angle characters in upstream APIM expression attributes.

    Some original policy sources contain literal nested double quotes inside
    XML attributes. Preserve the APIM expression while producing valid XML.
    """
    def fix(match):
        raw = html.unescape(match.group("body"))
        safe = escape(raw, {'"': "&quot;"})
        return match.group("prefix") + safe + match.group("suffix")

    pattern = re.compile(
        r'(?P<prefix>\b[\w:-]+=")(?P<body>@[\s\S]*?)(?P<suffix>[})]"(?=\s*(?:/?>|[a-zA-Z][\w:-]*=)))'
    )
    content = pattern.sub(fix, content)
    # Trace messages contain C# generics in XML text (e.g. GetValueOrDefault<string>).
    # They are not XML markup and must be escaped as text.
    def fix_message(match):
        return match.group(1) + escape(html.unescape(match.group(2))) + match.group(3)
    return re.sub(r'(<(message|set-body)>)([\s\S]*?)(</\2>)',
                  lambda m: m.group(1) + escape(html.unescape(m.group(3))) + m.group(4), content)


def validate(config):
    if not isinstance(config, dict) or not re.fullmatch(r"[0-9a-fA-F-]{36}", str(config.get("tenantId", ""))):
        raise ValueError("An Entra tenant GUID is required")
    if not isinstance(config.get("audience"), str) or not config["audience"].startswith("api://"):
        raise ValueError("A gateway application ID URI (api://...) is required")
    contracts = config.get("contracts")
    if not isinstance(contracts, list) or not contracts:
        raise ValueError("At least one contract is required; no anonymous fallback exists")
    grants = set()
    ids = set()
    for c in contracts:
        cid = c.get("id")
        if not isinstance(cid, str) or not re.fullmatch(r"[a-zA-Z0-9_.-]{1,100}", cid) or cid in ids:
            raise ValueError("Contract IDs must be unique and nonempty")
        ids.add(cid)
        for prop in ("callers", "apis", "allowedModels", "allowedBackendPools"):
            if not isinstance(c.get(prop), list) or not c[prop] or any(not isinstance(x, str) or not x.strip() for x in c[prop]):
                raise ValueError(f"{cid}: {prop} must contain explicit nonempty strings")
        if any(x not in API_FILES for x in c["apis"]):
            raise ValueError(f"{cid}: only the three verified inference APIs are supported")
        if any(not re.fullmatch(r"[0-9a-fA-F-]{36}", oid) for oid in c["callers"]):
            raise ValueError(f"{cid}: caller IDs must be service principal object GUIDs (oid), not app IDs")
        for key in ("tokensPerMinute", "tokenQuota"):
            if type(c.get(key)) is not int or c[key] <= 0:
                raise ValueError(f"{cid}: {key} must be a positive integer")
        if c.get("tokenQuotaPeriod") not in PERIODS:
            raise ValueError(f"{cid}: invalid tokenQuotaPeriod")
        if any("," in x or "|" in x for x in c["allowedModels"] + c["allowedBackendPools"]):
            raise ValueError(f"{cid}: model/pool IDs cannot include comma or pipe")
        for oid in c["callers"]:
            for api in c["apis"]:
                grant = (oid.lower(), api)
                if grant in grants:
                    raise ValueError(f"Ambiguous grant for oid={oid} API={api}; split workloads or merge contracts")
                grants.add(grant)
    return config


def expr(value):
    return quoteattr(value)


def choose_contracts(config):
    clauses = []
    for c in config["contracts"]:
        apps = " || ".join(
            '(caller == ' + json.dumps(config["tenantId"].lower() + ":" + oid.lower()) + ')'
            for oid in c["callers"]
        )
        apis = " || ".join('(api == ' + json.dumps(api) + ')' for api in c["apis"])
        condition = f"@{{ var caller = context.Variables.GetValueOrDefault<string>(\"callerId\", \"\"); var api = context.Api.Id; return ({apps}) && ({apis}); }}"
        clauses.append(f"""<when condition={expr(condition)}>
  <set-variable name="contractId" value={expr(c["id"])} />
  <set-variable name="allowedModels" value={expr(",".join(c["allowedModels"]))} />
  <set-variable name="allowedBackendPools" value={expr(",".join(c["allowedBackendPools"]))} />
  <set-variable name="consumerId" value="@((string)context.Variables[&quot;callerId&quot;])" />
  <set-variable name="appId" value="@((string)context.Variables[&quot;callerId&quot;])" />
</when>""")
    return "\n".join(clauses)


def auth_fragment(config):
    tenant = config["tenantId"].lower()
    openid = f"https://login.microsoftonline.com/{tenant}/v2.0/.well-known/openid-configuration"
    issuer = f"https://login.microsoftonline.com/{tenant}/v2.0"
    return f"""<fragment>
  <!-- JWT-only: application identity is explicitly mapped to ONE Access Contract per API.
       Unauthenticated requests and unmatched identities fail closed. -->
  <validate-jwt header-name="Authorization" require-scheme="Bearer"
       output-token-variable-name="validated-jwt"
       failed-validation-httpcode="401" failed-validation-error-message="Invalid or missing gateway JWT">
    <openid-config url={expr(openid)} />
    <audiences><audience>{escape(config["audience"])}</audience></audiences>
    <issuers><issuer>{escape(issuer)}</issuer><issuer>https://sts.windows.net/{escape(tenant)}/</issuer></issuers>
    <required-claims><claim name="tid" match="all"><value>{escape(tenant)}</value></claim></required-claims>
  </validate-jwt>
  <!-- oid identifies the managed-identity service principal. Never trust caller-supplied headers. -->
  <set-variable name="callerId" value="@{{
    var token = (Jwt)context.Variables[&quot;validated-jwt&quot;];
    var oid = token.Claims.GetValueOrDefault(&quot;oid&quot;, &quot;&quot;);
    var tid = token.Claims.GetValueOrDefault(&quot;tid&quot;, &quot;&quot;);
    if (string.IsNullOrWhiteSpace(oid) || string.IsNullOrWhiteSpace(tid)) return &quot;&quot;;
    return tid.ToLowerInvariant() + &quot;:&quot; + oid.ToLowerInvariant();
  }}" />
  <choose>
    <when condition="@(string.IsNullOrEmpty(context.Variables.GetValueOrDefault&lt;string&gt;(&quot;callerId&quot;, &quot;&quot;)))">
      <return-response><set-status code="403" reason="Missing application identity" /></return-response>
    </when>
  </choose>
  <choose>
{choose_contracts(config)}
    <otherwise>
      <return-response><set-status code="403" reason="Caller not granted access to this API" /></return-response>
    </otherwise>
  </choose>
  <set-variable name="user-id" value="@((string)context.Variables[&quot;callerId&quot;])" />
  <set-variable name="subscription-name" value="@((string)context.Variables[&quot;contractId&quot;])" />
  <!-- Do not forward a gateway-audience caller JWT to any backend. -->
  <set-header name="Authorization" exists-action="delete" />
  <set-header name="api-key" exists-action="delete" />
  <set-header name="Ocp-Apim-Subscription-Key" exists-action="delete" />
</fragment>
"""


def pool_authorization_fragment():
    """Fail closed even on explicit API-type routes and retry / alias fallback."""
    return """<fragment>
      <choose>
        <when condition="@{
          var selected = context.Variables.GetValueOrDefault&lt;string&gt;(&quot;targetBackendPool&quot;, &quot;&quot;);
          var allowed = context.Variables.GetValueOrDefault&lt;string&gt;(&quot;allowedBackendPools&quot;, &quot;&quot;);
          if (string.IsNullOrWhiteSpace(selected) || string.IsNullOrWhiteSpace(allowed)) return true;
          return !allowed.Split(',').Any(p => p.Trim().Equals(selected, StringComparison.OrdinalIgnoreCase));
        }">
          <return-response>
            <set-status code="403" reason="Backend pool not granted by Access Contract" />
          </return-response>
        </when>
      </choose>
    </fragment>
    """


def limits_fragment(config):
    clauses = []
    for c in config["contracts"]:
        clause = f"""<when condition={expr('@(context.Variables.GetValueOrDefault<string>("contractId", "") == ' + json.dumps(c["id"]) + ')')}>
  <llm-token-limit counter-key="@((string)context.Variables[&quot;contractId&quot;])"
       tokens-per-minute="{c["tokensPerMinute"]}" token-quota="{c["tokenQuota"]}"
       token-quota-period="{c["tokenQuotaPeriod"]}" estimate-prompt-tokens="false" />
</when>"""
        clauses.append(clause)
    return "<fragment><choose>\n" + "\n".join(clauses) + "\n</choose></fragment>\n"


def rewrite_policy(api, content):
    # API-level policies are deployed to isolated, subscription-free API instances.
    # Keep the entire upstream routing / retry / backend chain intact.
    auth = '<include-fragment fragment-id="security-handler" />'
    if content.count(auth) != 1:
        raise ValueError(f"{api}: unexpected authentication insertion count")
    content = content.replace(auth, '<include-fragment fragment-id="entra-contract-auth" />')
    if api == "unified-ai-api":
        # Validate identity before metadata reads or request processing.
        content = content.replace('<include-fragment fragment-id="entra-contract-auth" />', '', 1)
        content = content.replace('<inbound>\n        <base />', '<inbound>\n        <base />\n        <include-fragment fragment-id="entra-contract-auth" />', 1)
    if api == "unified-ai-api":
        # With keyless API access there is no APIM context.Product; the registry is authoritative.
        content, count = re.subn(
            r'\s*<!-- Validate product context -->\s*<choose>.*?</choose>',
            '', content, count=1, flags=re.S
        )
        if count != 1:
            raise ValueError("Unified AI: product precheck not found")
    # All three upstream policies may overwrite this variable with an empty (allow-all) value.
    # Retain only the authorization-derived grant.
    content = content.replace('<set-variable name="allowedBackendPools" value="" />',
                              '<!-- allowedBackendPools is set by entra-contract-auth -->')
    # Authorization must precede response ownership, then quota enforcement.
    owner = '<include-fragment fragment-id="responses-id-security" />'
    if content.count(owner) != 1:
        raise ValueError(f"{api}: response security insertion not found")
    content = content.replace(owner, '<include-fragment fragment-id="entra-responses-id-security" />\n'
                       '        <include-fragment fragment-id="entra-contract-limits" />', 1)
    content = content.replace('<include-fragment fragment-id="responses-id-cache-store" />',
                              '<include-fragment fragment-id="entra-responses-id-cache-store" />')
    content = content.replace('<include-fragment fragment-id="set-llm-usage" />',
                              '<include-fragment fragment-id="entra-set-llm-usage" />')
    # Every backend authentication call (initial and retry) is preceded by an
    # explicit pool-grant check. Never rely solely on the router to enforce RBAC.
    backend_auth = '<include-fragment fragment-id="set-backend-authorization" />'
    if backend_auth not in content:
        raise ValueError(f"{api}: backend authorization call not found")
    content = content.replace(backend_auth,
                              '<include-fragment fragment-id="entra-authorize-target-pool" />\n'
                              '        ' + backend_auth)
    if '<include-fragment fragment-id="entra-contract-auth" />' not in content:
        raise ValueError("JWT authentication was not installed")
    content = normalize_upstream_policy_xml(content)
    ET.fromstring(content)
    return content


def response_fragment(name):
    content = (SOURCE / name).read_text(encoding="utf-8")
    # Preserve the existing 4-field cache representation, substituting the trusted
    # caller and contract for subscription and product. This is for an ISOLATED gateway;
    # sharing response caches with legacy policies is not supported.
    content = content.replace('context.Subscription?.Id ?? string.Empty',
                              'context.Variables.GetValueOrDefault<string>("callerId", string.Empty)')
    content = content.replace('context.Subscription?.Id ?? "NA"',
                              'context.Variables.GetValueOrDefault<string>("callerId", "NA")')
    content = content.replace('context.Product?.Id ?? "NA"',
                              'context.Variables.GetValueOrDefault<string>("contractId", "NA")')
    content = content.replace('context.Product?.Id', 'context.Variables.GetValueOrDefault<string>("contractId", "NA")')
    content = content.replace('context.Subscription?.Id', 'context.Variables.GetValueOrDefault<string>("callerId", "NA")')
    content = normalize_upstream_policy_xml(content)
    ET.fromstring(content)
    return content


def usage_fragment():
    content = (SOURCE / "frag-set-llm-usage.xml").read_text(encoding="utf-8")
    content = content.replace('context.Product?.Name?.ToString() ?? "Portal-Admin"',
                              'context.Variables.GetValueOrDefault<string>("contractId", "Unassigned")')
    content = content.replace('context.Subscription?.Id ?? "Portal-Admin-Sub"',
                              'context.Variables.GetValueOrDefault<string>("callerId", "Unassigned")')
    content = normalize_upstream_policy_xml(content)
    ET.fromstring(content)
    return content


def generate(config, output):
    config = validate(config)
    output.mkdir(parents=True, exist_ok=True)
    generated = {
        "frag-entra-contract-auth.xml": auth_fragment(config),
        "frag-entra-contract-limits.xml": limits_fragment(config),
        "frag-entra-authorize-target-pool.xml": pool_authorization_fragment(),
        "frag-entra-responses-id-security.xml": response_fragment("frag-responses-id-security.xml"),
        "frag-entra-responses-id-cache-store.xml": response_fragment("frag-responses-id-cache-store.xml"),
        "frag-entra-set-llm-usage.xml": usage_fragment(),
    }
    for api, filename in API_FILES.items():
        generated[f"api-{api}-policy.xml"] = rewrite_policy(api, (SOURCE / filename).read_text(encoding="utf-8"))
    for name, content in generated.items():
        ET.fromstring(content)
        (output / name).write_text(content, encoding="utf-8")
    return list(generated)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--contracts", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    names = generate(json.loads(args.contracts.read_text(encoding="utf-8")), args.output)
    print(f"Generated {len(names)} validated XML files in {args.output}; deployment NOT performed")


if __name__ == "__main__":
    main()
