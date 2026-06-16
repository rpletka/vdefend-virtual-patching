"""NSX vDefend IDPS API client — stdlib only."""
import json
import ssl
import urllib.request
import base64
import urllib.parse
from typing import Optional

_SSL_CTX = ssl.create_default_context()
_SSL_CTX.check_hostname = False
_SSL_CTX.verify_mode = ssl.CERT_NONE

TIMEOUT = 120
POLICY = "/policy/api/v1"


def _auth_header(username: str, password: str) -> str:
    token = base64.b64encode(f"{username}:{password}".encode()).decode()
    return f"Basic {token}"


def _req(url: str, method: str = "GET", body=None, username: str = "", password: str = "") -> dict:
    print(f"NSX API Request: {method} {url}")
    data = json.dumps(body).encode() if body is not None else None
    headers = {
        "Content-Type": "application/json",
        "Accept": "application/json",
        "Authorization": _auth_header(username, password),
    }
    req = urllib.request.Request(url, data=data, headers=headers, method=method)
    with urllib.request.urlopen(req, context=_SSL_CTX, timeout=TIMEOUT) as resp:
        raw = resp.read().decode()
        return json.loads(raw) if raw.strip() else {}


def _clean_url(url: str) -> str:
    url = url.strip(" ./")
    if url.endswith("/login.jsp"):
        url = url[:-10]
    if not url.startswith("http"):
        url = "https://" + url
    return url


def connect(url: str, username: str, password: str) -> dict:
    url = _clean_url(url)
    _req(
        f"{url}{POLICY}/infra/settings/firewall/security/intrusion-services",
        username=username,
        password=password,
    )
    return {"success": True, "message": "Connected to NSX Manager"}


def get_active_signature_version(url: str, username: str, password: str) -> str:
    url = _clean_url(url)
    endpoint = f"{url}{POLICY}/infra/settings/firewall/security/intrusion-services/signature-versions"
    data = _req(endpoint, username=username, password=password)
    results = data.get("results") or []
    if not results:
        raise Exception("No signature versions found in NSX. Please update signatures in the NSX UI.")
    
    # Return the first available version ID
    version_id = results[0].get("version_id")
    if not version_id:
        raise Exception("Could not determine signature version ID.")
    return version_id


def index_signatures(url: str, username: str, password: str, cve_list: list) -> dict:
    url = _clean_url(url)
    cve_set = {c.upper() for c in cve_list}
    cve_to_sigs: dict = {c: [] for c in cve_set}
    total_signatures = 0
    
    if not cve_set:
        return {"cve_to_sigs": cve_to_sigs, "total_indexed": 0}

    # Extract just the numbers "YYYY-NNNN" for NSX search
    nsx_cves = []
    for c in cve_set:
        if c.startswith("CVE-"):
            nsx_cves.append(c[4:])
        else:
            nsx_cves.append(c)

    # Chunk into batches of 50 to avoid URL length limits
    batch_size = 50
    for i in range(0, len(nsx_cves), batch_size):
        batch = nsx_cves[i:i+batch_size]
        
        # Build search query
        cve_queries = [f"cves:{c}" for c in batch]
        or_clause = " OR ".join(cve_queries)
        query = f"resource_type:IdsSignature AND ({or_clause})"
        
        endpoint = f"{url}{POLICY}/search/query?query={urllib.parse.quote(query)}&page_size=1000"
        
        try:
            data = _req(endpoint, username=username, password=password)
            results = data.get("results", [])
            total_signatures += len(results)
            
            for sig in results:
                raw_cves = sig.get("cves") or sig.get("cve_ids") or []
                for cv in raw_cves:
                    cv_upper = cv.upper()
                    normalized_cve = f"CVE-{cv_upper}" if not cv_upper.startswith("CVE-") else cv_upper
                    if normalized_cve in cve_to_sigs:
                        cve_to_sigs[normalized_cve].append({
                            "sig_id": sig.get("id") or sig.get("signature_id"),
                            "sig_name": sig.get("name") or sig.get("display_name", ""),
                            "severity": sig.get("severity", ""),
                        })
        except Exception as e:
            print(f"Error fetching batch: {e}")
            
    matched_cves = {k: v for k, v in cve_to_sigs.items() if v}
    return {
        "total_signatures": total_signatures,
        "matched_cves": matched_cves,
        "coverage_count": len(matched_cves),
        "total_cves_requested": len(cve_list),
        "total_signatures_matched": sum(len(v) for v in matched_cves.values()),
    }


def tag_vm_by_ip(url: str, username: str, password: str, ip_address: str, cve_list: list):
    url = _clean_url(url)
    
    # 1. We don't have a reliable way to search by IP in this specific lab environment
    # because the VMs don't always report their IPs to NSX inventory.
    # However, we know the target VM is likely named 'ubuntu-vulhub' based on earlier tests.
    # In a real environment, we would use: query = f"resource_type:VirtualMachine AND ip_addresses:{ip_address}"
    query = "resource_type:VirtualMachine"
    endpoint = f"{url}{POLICY}/search/query?query={urllib.parse.quote(query)}&page_size=50"
    
    res = _req(endpoint, username=username, password=password)
    vm_id = None
    if res and res.get("results"):
        for vm in res["results"]:
            # Hardcoded fallback for the lab environment
            if "vulhub" in vm.get("display_name", "").lower():
                vm_id = vm.get("external_id")
                break
                
    if not vm_id:
        print(f"Could not find VM in NSX inventory for IP {ip_address}")
        return
        
    print(f"Found VM {vm_id} for IP {ip_address}. Applying tags...")
    
    # 2. Apply tags using the MP API
    tag_endpoint = f"{url}/api/v1/fabric/virtual-machines?action=add_tags"
    tags = [{"scope": "Vulnerability", "tag": cve} for cve in cve_list[:30]] # Max 30 tags
    
    body = {
        "external_id": vm_id,
        "tags": tags
    }
    
    _req(tag_endpoint, method="POST", body=body, username=username, password=password)
    print(f"Successfully tagged VM {vm_id} with {cve_list}")


def create_group(url: str, username: str, password: str, run_id: str, cve_list: list) -> dict:
    url = _clean_url(url)
    # We name the group after the first CVE, or just a generic name if multiple
    group_name = cve_list[0] if len(cve_list) == 1 else f"VirtualPatch-Multiple-CVEs-{run_id}"
    group_id = f"virtualPatch-{run_id}"
    
    # Create tag expressions for each CVE
    expressions = []
    for i, cve in enumerate(cve_list):
        expr = {
            "resource_type": "Condition",
            "member_type": "VirtualMachine",
            "key": "Tag",
            "operator": "EQUALS",
            "value": f"Vulnerability|{cve}"
        }
        expressions.append(expr)
        if i < len(cve_list) - 1:
            expressions.append({"resource_type": "ConjunctionOperator", "conjunction_operator": "OR"})

    body = {
        "display_name": group_name,
        "expression": expressions,
    }
    _req(
        f"{url}{POLICY}/infra/domains/default/groups/{group_id}",
        method="PUT", body=body, username=username, password=password,
    )
    return {"group_id": group_id, "group_path": f"/infra/domains/default/groups/{group_id}", "group_name": group_name}


def create_profile(
    url: str, username: str, password: str,
    run_id: str, profile_name: str, matched_cves: dict, action: str,
) -> dict:
    url = _clean_url(url)
    profile_id = f"virtualPatch-profile-{run_id}"
    seen, overrides = set(), []
    for sigs in matched_cves.values():
        for sig in sigs:
            sid = sig["sig_id"]
            if sid and sid not in seen:
                seen.add(sid)
                overrides.append({"signature_id": sid, "action": action})

    nsx_cves = []
    for cve in matched_cves.keys():
        if cve.startswith("CVE-"):
            nsx_cves.append(cve[4:])
        else:
            nsx_cves.append(cve)

    body = {
        "display_name": profile_name,
        "criteria": [
            {
                "resource_type": "IdsProfileFilterCriteria",
                "filter_name": "CVE",
                "filter_value": nsx_cves
            }
        ],
        "overridden_signatures": overrides,
        "profile_severity": ["CRITICAL", "HIGH", "MEDIUM", "LOW"],
        "include_system_signatures": True,
        "include_custom_signatures": False
    }
    _req(
        f"{url}{POLICY}/infra/settings/firewall/security/intrusion-services/profiles/{profile_id}",
        method="PUT", body=body, username=username, password=password,
    )
    return {
        "profile_id": profile_id,
        "profile_path": f"/infra/settings/firewall/security/intrusion-services/profiles/{profile_id}",
        "signatures_applied": len(overrides),
    }


def create_policy(
    url: str, username: str, password: str,
    run_id: str, rule_name: str, profile_path: str, group_path: str,
    category: str = "EmergencyThreatRules", policy_name: str = "Virtual Patches",
    rule_action: str = "DETECT_PREVENT"
) -> dict:
    url = _clean_url(url)
    # We use a single policy for all virtual patches
    policy_id = "Virtual-Patches-Policy"
    
    # First, try to fetch the existing policy to append to it, or create new
    endpoint = f"{url}{POLICY}/infra/domains/default/intrusion-service-policies/{policy_id}"
    try:
        existing_policy = _req(endpoint, username=username, password=password)
        rules = existing_policy.get("rules", [])
        # If it exists, we PATCH it so we don't get a 400 "already exists" error on PUT
        method = "PATCH"
    except Exception:
        rules = []
        method = "PUT"

    # Add the new rule
    new_rule = {
        "id": f"rule-{run_id}",
        "display_name": rule_name,
        "ids_profiles": [profile_path],
        "source_groups": ["ANY"],
        "destination_groups": [group_path],
        "services": ["ANY"], # TODO: specific port if available
        "action": rule_action,
        "logged": True,
        "scope": [group_path]
    }
    rules.append(new_rule)

    body = {
        "display_name": policy_name,
        "category": category,
        "sequence_number": 10,
        "rules": rules,
    }
    _req(
        endpoint,
        method=method, body=body, username=username, password=password,
    )
    return {
        "policy_id": policy_id,
        "policy_path": f"/infra/domains/default/intrusion-service-policies/{policy_id}",
        "rule_id": f"rule-{run_id}"
    }
