import json
import csv
import os
import datetime

# Package version (manual or from init)
TOOL_VERSION = "3.0.0"

def write_json_report(data, output_path):
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, sort_keys=True)

def write_csv_report(findings, output_path):
    # Sort findings: DisplayName -> AppId
    sorted_findings = sorted(findings, key=lambda x: (x.get("displayName") or "", x.get("appId") or ""))
    
    headers = [
        "EntityType", "DisplayName", "AppId", "ObjectId", 
        "Owners", "IsOrphaned", "OwnerStatus", "OwnerSource", "OwnersCount", "HasLocalOwners",
        "ServicePrincipalType", "AppOwnerOrganizationId", "PublisherName",
        "CredentialTotalCount", "HasAnyCredentials", "HasExpired", "HasExpiring",
        "SecretCount", "CertCount", "FederatedCount", "ExpiredCount", "ExpiringCount", 
        "NextExpiryDate", "NextExpiryInDays",
        "RiskyPermCount", "RiskyPermDetails"
    ]
    
    rows = []
    for f in sorted_findings:
        creds = f.get("credentials", [])
        secrets = [c for c in creds if c["type"] == "Secret"]
        certs = [c for c in creds if c["type"] == "Certificate"]
        federated = [c for c in creds if c["type"] == "Federated"]
        expired = [c for c in creds if c["status"] == "EXPIRED"]
        expiring = [c for c in creds if c["status"] == "EXPIRING"]
        
        # Calculate next expiry
        valid_dates_dt = []
        valid_days = []
        
        for c in creds:
             if c["status"] in ["ACTIVE", "EXPIRING"] and c["endDateTime"]:
                 try:
                     dt = datetime.datetime.fromisoformat(c["endDateTime"].replace('Z', '+00:00'))
                     valid_dates_dt.append(dt)
                     if c["daysUntilExpiry"] is not None:
                         valid_days.append(c["daysUntilExpiry"])
                 except ValueError:
                     pass
                     
        if valid_dates_dt:
            next_expiry_iso = min(valid_dates_dt).isoformat()
            next_expiry_days = min(valid_days) if valid_days else ""
        else:
            next_expiry_iso = ""
            next_expiry_days = ""
        
        risky = f.get("riskyPermissions", [])
        # Deterministic sort of permissions
        risky_sorted = sorted(risky, key=lambda x: (x['resourceDisplayName'], x['permission']))
        risky_details = "; ".join([f"{p['resourceDisplayName']}: {p['permission']} ({p['risk']})" for p in risky_sorted])
        
        # Safe owners join
        owners_str = "; ".join(f.get("owners") or [])
        
        row = {
            "EntityType": f["entityType"],
            "DisplayName": f["displayName"],
            "AppId": f["appId"],
            "ObjectId": f["objectId"],
            "Owners": owners_str,
            "IsOrphaned": f["isOrphaned"],
            "OwnerStatus": f.get("ownerStatus"),
            "OwnerSource": f.get("ownerSource", "N/A"),
            "OwnersCount": f.get("ownersCount", 0),
            "HasLocalOwners": f.get("hasLocalOwners"),
            "ServicePrincipalType": f.get("servicePrincipalType") or "",
            "AppOwnerOrganizationId": f.get("appOwnerOrganizationId") or "",
            "PublisherName": f.get("publisherName") or "",
            "CredentialTotalCount": len(creds),
            "HasAnyCredentials": len(creds) > 0,
            "HasExpired": len(expired) > 0,
            "HasExpiring": len(expiring) > 0,
            "SecretCount": len(secrets),
            "CertCount": len(certs),
            "FederatedCount": len(federated),
            "ExpiredCount": len(expired),
            "ExpiringCount": len(expiring),
            "NextExpiryDate": next_expiry_iso,
            "NextExpiryInDays": next_expiry_days,
            "RiskyPermCount": len(risky),
            "RiskyPermDetails": risky_details
        }
        rows.append(row)
        
    with open(output_path, "w", newline='', encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=headers)
        writer.writeheader()
        writer.writerows(rows)

def print_summary(stats):
    print("-" * 50)
    print(f"Apps scanned: {stats['apps_scanned']}")
    print(f"Service Principals scanned: {stats['sps_scanned']}")
    print(f"Total Credentials found: {stats['total_creds']}")
    print(f"  - Secrets: {stats['type_counts']['Secret']}")
    print(f"  - Certificates: {stats['type_counts']['Certificate']}")
    print(f"  - Federated: {stats['type_counts']['Federated']}")
    print(f"Expired Credentials: {stats['expired_creds']}")
    print(f"Expiring Credentials: {stats['expiring_creds']}")
    print(f"Orphaned Entities: {stats['orphaned']}")
    print(f"  - External Managed: {stats['external_managed_count']}")
    print(f"  - Unknown Owner Org: {stats['unknown_owner_org_count']}")
    print(f"  - Lookup Failed: {stats['owner_lookup_failed_count']}")
    print(f"Entities with Risky Perms: {stats['risky_entities']}")
    print(f"Global Errors: {len(stats['errors'])}")
    print("-" * 50)

def aggregate_stats(findings, global_errors):
    stats = {
        "apps_scanned": sum(1 for f in findings if f["entityType"] == "Application"),
        "sps_scanned": sum(1 for f in findings if f["entityType"] == "ServicePrincipal"),
        "total_creds": 0,
        "expired_creds": 0,
        "expiring_creds": 0,
        "orphaned": 0,
        "risky_entities": 0,
        "type_counts": {"Secret": 0, "Certificate": 0, "Federated": 0},
        "external_managed_count": 0,
        "unknown_owner_org_count": 0,
        "owner_lookup_failed_count": 0,
        "errors": global_errors
    }
    
    for f in findings:
        creds = f.get("credentials", [])
        stats["total_creds"] += len(creds)
        stats["expired_creds"] += sum(1 for c in creds if c["status"] == "EXPIRED")
        stats["expiring_creds"] += sum(1 for c in creds if c["status"] == "EXPIRING")
        
        for c in creds:
             if c["type"] in stats["type_counts"]:
                 stats["type_counts"][c["type"]] += 1
        
        if f.get("isOrphaned") is True:
            stats["orphaned"] += 1
            
        status = f.get("ownerStatus")
        if status == "EXTERNAL_MANAGED":
            stats["external_managed_count"] += 1
        elif status == "UNKNOWN_OWNER_ORG":
            stats["unknown_owner_org_count"] += 1
        elif status == "OWNER_LOOKUP_FAILED":
            stats["owner_lookup_failed_count"] += 1
            
        if len(f.get("riskyPermissions", [])) > 0:
            stats["risky_entities"] += 1
            
    return stats
