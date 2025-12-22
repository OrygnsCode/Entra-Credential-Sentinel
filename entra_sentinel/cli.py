import os
import sys
import argparse
import logging
import datetime
from dotenv import load_dotenv

from entra_sentinel.auth import get_access_token, get_tenant_info
from entra_sentinel.graph import paginate_graph_results, GRAPH_BASE_URL
import json
from entra_sentinel.audit import audit_entity, RISKY_PERMISSIONS_MAP
from entra_sentinel.report import write_csv_report, write_json_report, aggregate_stats, print_summary, TOOL_VERSION

logger = logging.getLogger("EntraSentinel")

def parse_args():
    parser = argparse.ArgumentParser(description="Entra Credential Sentinel V3")
    
    parser.add_argument("--expiry-window-days", type=int, default=30, help="Days threshold for expiring credentials (default 30)")
    parser.add_argument("--output-dir", type=str, default="out", help="Directory for output files")
    parser.add_argument("--format", type=str, default="both", choices=["csv", "json", "both"], help="Output format")
    parser.add_argument("--scope", type=str, default="both", choices=["apps", "sps", "both"], help="Audit scope")
    
    # Validation / Logic Overrides
    parser.add_argument("--tenant-org-id", type=str, help="Override auto-detected Tenant Organization ID")
    parser.add_argument("--risk-map-json", type=str, help="Path to JSON file with custom risk map (overrides built-in)")
    
    # Filters
    parser.add_argument("--only-risky", action="store_true", help="Only output entities with risky permissions, expired/expiring creds, or orphaned")
    
    # Exit Codes
    parser.add_argument("--fail-on-risk", action="store_true", help="Exit code 2 if risky permissions found")
    parser.add_argument("--fail-on-expired", action="store_true", help="Exit code 2 if expired credentials found")
    parser.add_argument("--fail-on-orphaned", action="store_true", help="Exit code 2 if orphaned found")
    
    return parser.parse_args()

def should_emit(finding):
    """
    Determines if finding should be in output based on --only-risky
    """
    has_risk_perm = len(finding["riskyPermissions"]) > 0
    is_orphaned = (finding["isOrphaned"] is True)
    
    has_expired = False
    has_expiring = False
    for c in finding["credentials"]:
        if c["status"] == "EXPIRED": has_expired = True
        if c["status"] == "EXPIRING": has_expiring = True
            
    is_risky_state = has_risk_perm or is_orphaned or has_expired or has_expiring
    return is_risky_state

def main():
    # Logging Configuration (Centralized)
    logging.basicConfig(
        level=os.getenv("LOG_LEVEL", "INFO").upper(),
        format="%(levelname)s: %(message)s"
    )

    args = parse_args()
    
    # Init Env
    if os.path.exists(".env"):
        load_dotenv()
        
    TENANT_ID = os.getenv("TENANT_ID")
    CLIENT_ID = os.getenv("CLIENT_ID")
    CLIENT_SECRET = os.getenv("CLIENT_SECRET")
    
    # Check Required
    if not TENANT_ID:
        print("Error: Missing required environment variable: TENANT_ID")
        sys.exit(3)
    if not CLIENT_ID:
        print("Error: Missing required environment variable: CLIENT_ID")
        sys.exit(3)
    if not CLIENT_SECRET:
        print("Error: Missing required environment variable: CLIENT_SECRET")
        sys.exit(3)
        
    # Load Risk Map Override
    if args.risk_map_json:
        try:
            with open(args.risk_map_json, "r", encoding="utf-8") as f:
                custom_map = json.load(f)
                if isinstance(custom_map, dict):
                    RISKY_PERMISSIONS_MAP.update(custom_map)
                    print(f"Loaded {len(custom_map)} custom risk definitions.")
                else:
                    print("Warning: Risk map JSON must be a dictionary.")
        except Exception as e:
            print(f"Error loading risk map: {e}")
            sys.exit(1)
        
    # Setup Output
    os.makedirs(args.output_dir, exist_ok=True)
    
    # Auth
    print("Authenticating...")
    token = get_access_token(TENANT_ID, CLIENT_ID, CLIENT_SECRET)
    
    # Tenant Discovery
    print("Discovering Tenant Info...")
    tenant_info = get_tenant_info(token)
    
    # Override if provided
    if args.tenant_org_id:
        print(f"  > Using configured Tenant Org ID: {args.tenant_org_id}")
        tenant_info["id"] = args.tenant_org_id
    else:
        print(f"  > Detected Tenant Org: {tenant_info.get('displayName')} ({tenant_info.get('id')})")

    # Optimization: Pre-fetch Microsoft Graph SP
    print("Resolving Microsoft Graph Service Principal...")
    graph_filter = "appId eq '00000003-0000-0000-c000-000000000000'"
    graph_url = f"{GRAPH_BASE_URL}/servicePrincipals?$filter={graph_filter}&$select=id,appId,displayName,appRoles"
    graph_res, _ = paginate_graph_results(token, graph_url)
    
    graph_sp = None
    if graph_res:
        raw_sp = graph_res[0]
        roles_map = {}
        for r in raw_sp.get("appRoles", []):
            rid = r.get("id")
            val = r.get("value") or r.get("displayName")
            roles_map[rid] = val
        
        graph_sp = {
            "id": raw_sp.get("id"),
            "appId": raw_sp.get("appId"),
            "displayName": raw_sp.get("displayName"),
            "appRoles": roles_map
        }
        print(f"  > Found MS Graph SP: {graph_sp['id']}")
    else:
        print("  > Warning: MS Graph SP not found. Optimization disabled.")

    all_findings = []
    global_errors = []
    
    # App Index for linking SPs to Apps (False positive reduction)
    app_index = {}
    
    # Audit Apps
    if args.scope in ["apps", "both"]:
        print("Auditing App Registrations...")
        url = f"{GRAPH_BASE_URL}/applications?$select=id,appId,displayName,passwordCredentials,keyCredentials"
        apps, err = paginate_graph_results(token, url)
        
        if err:
            logger.error(f"Failed to list applications: {err}")
            global_errors.append(f"Failed to list applications: {err}")
            print(f"Critical Error: Failed to list applications. {err}")
            # Non-fatal if we are checking SPs too, but traditionally we exit. Let's keep exit for consistency.
            sys.exit(3)
        else:
            print(f"  > Found {len(apps)} apps.")
            for app in apps:
                finding = audit_entity(token, app, "Application", args, tenant_info)
                
                # Index for SP lookup
                app_index[finding["appId"]] = finding
                
                if args.only_risky:
                    if should_emit(finding):
                        all_findings.append(finding)
                else:
                    all_findings.append(finding)

    # Audit SPs
    if args.scope in ["sps", "both"]:
        print("Auditing Service Principals...")
        # Get necessary fields for MS Managed logic
        url = f"{GRAPH_BASE_URL}/servicePrincipals?$select=id,appId,displayName,passwordCredentials,keyCredentials,servicePrincipalType,tags,appOwnerOrganizationId,publisherName"
        sps, err = paginate_graph_results(token, url)
        
        if err:
            logger.error(f"Failed to list service principals: {err}")
            global_errors.append(f"Failed to list service principals: {err}")
            print(f"Critical Error: Failed to list service principals. {err}")
            sys.exit(3)
        else:
            print(f"  > Found {len(sps)} service principals.")
            for sp in sps:
                # Pass app_index and graph_sp
                finding = audit_entity(token, sp, "ServicePrincipal", args, tenant_info, app_index, graph_sp=graph_sp)
                if args.only_risky:
                    if should_emit(finding):
                        all_findings.append(finding)
                else:
                    all_findings.append(finding)
                    
    # Generate Reports
    print("Generating reports...")
    stats = aggregate_stats(all_findings, global_errors)
    
    json_data = {
        "metadata": {
            "runAtUtc": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "tenantOrgId": tenant_info["id"],
            "tenantDisplayName": tenant_info["displayName"],
            "expiryWindowDays": args.expiry_window_days,
            "graphBaseUrl": GRAPH_BASE_URL,
            "toolVersion": TOOL_VERSION
        },
        "summary": stats,
        "findings": all_findings,
        "errors": global_errors
    }
    
    # Ensure entity sort for JSON
    json_data["findings"].sort(key=lambda x: (x.get("displayName") or "", x.get("appId") or ""))
    
    if args.format in ["json", "both"]:
        write_json_report(json_data, os.path.join(args.output_dir, "entra_credential_sentinel.json"))
        
    if args.format in ["csv", "both"]:
        write_csv_report(all_findings, os.path.join(args.output_dir, "entra_credential_sentinel.csv"))
        
    print_summary(stats)
    
    # Exit Codes
    exit_code = 0
    if args.fail_on_risk and stats["risky_entities"] > 0:
        exit_code = 2
    if args.fail_on_expired and stats["expired_creds"] > 0:
        exit_code = 2
    if args.fail_on_orphaned and stats["orphaned"] > 0:
        exit_code = 2
        
    sys.exit(exit_code)

if __name__ == "__main__":
    main()
