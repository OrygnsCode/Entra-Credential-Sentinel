import datetime
import math
import logging
from .graph import paginate_graph_results, resolve_service_principal, GRAPH_BASE_URL

logger = logging.getLogger("EntraSentinel")

# Risky Permissions Curated List
RISKY_PERMISSIONS_MAP = {
    # Application Permissions
    "Directory.ReadWrite.All": "CRITICAL",
    "Application.ReadWrite.All": "CRITICAL",
    "AppRoleAssignment.ReadWrite.All": "CRITICAL",
    "RoleManagement.ReadWrite.Directory": "CRITICAL",
    "PrivilegedAccess.ReadWrite.AzureAD": "CRITICAL",
    "Policy.ReadWrite.ConditionalAccess": "CRITICAL",
    "User.ReadWrite.All": "HIGH",
    "Group.ReadWrite.All": "HIGH",
    "IdentityProvider.ReadWrite.All": "HIGH",
    "AuditLog.Read.All": "MEDIUM",
    
    # Delegated Permissions
    "Directory.AccessAsUser.All": "CRITICAL",
    "RoleManagement.ReadWrite.Directory": "CRITICAL",
    "offline_access": "MEDIUM",
}

def calculate_expiry_status(end_date_str, expiry_window_days):
    if not end_date_str:
        return None, "UNKNOWN"
    try:
        expiry_dt = datetime.datetime.fromisoformat(end_date_str.replace('Z', '+00:00'))
        now_dt = datetime.datetime.now(datetime.timezone.utc)
        
        delta_seconds = (expiry_dt - now_dt).total_seconds()
        
        if delta_seconds < 0:
            return 0, "EXPIRED"
            
        # Ceiling for days remaining (0 means < 24h)
        days_remaining = math.ceil(delta_seconds / 86400)
        
        status = "ACTIVE"
        if days_remaining <= expiry_window_days:
            status = "EXPIRING"
            
        return days_remaining, status
    except ValueError:
        return None, "UNKNOWN"

def analyze_credentials(creds, cred_type, expiry_window_days):
    findings = []
    for c in creds:
        days, status = calculate_expiry_status(c.get("endDateTime"), expiry_window_days)
        findings.append({
            "type": cred_type,
            "id": c.get("keyId"),
            "displayName": c.get("displayName") or "No Name",
            "startDateTime": c.get("startDateTime"),
            "endDateTime": c.get("endDateTime"),
            "daysUntilExpiry": days,
            "status": status,
            "usage": c.get("usage", "N/A") if cred_type == "Certificate" else "Password"
        })
    return findings

def analyze_federated_credentials(token, app_object_id):
    """
    Fetches and normalizes federated identity credentials for an Application.
    """
    url = f"{GRAPH_BASE_URL}/applications/{app_object_id}/federatedIdentityCredentials"
    creds, error = paginate_graph_results(token, url)
    
    findings = []
    if error:
        logger.warning(f"Failed to fetch federated creds for {app_object_id}: {error}")
        return findings, error

    if not creds:
        return findings, None

    for c in creds:
        findings.append({
            "type": "Federated",
            "id": c.get("id"),
            "displayName": c.get("name"),
            "issuer": c.get("issuer"),
            "subject": c.get("subject"),
            "audiences": c.get("audiences", []),
            "startDateTime": None,
            "endDateTime": None,
            "daysUntilExpiry": None,
            "status": "NO_EXPIRY",
            "usage": "Federated"
        })
    return findings, None

def get_owners(token, resource_url):
    """
    Returns (owners_list, error_message).
    owners_list is None if error occurred.
    """
    owners_data, error = paginate_graph_results(token, resource_url)
    if error:
        return None, error
    
    owners = [o.get('userPrincipalName') or o.get('id') for o in owners_data]
    return owners, None

def assess_sp_metadata_ownership(entity_props, tenant_org_id, app_index):
    """
    Checks if SP ownership can be determined via metadata alone.
    Returns: (status, is_orphaned, source, owners) or None
    """
    # 1. Managed Identity
    if entity_props.get("servicePrincipalType") == "ManagedIdentity":
        return "MANAGED_IDENTITY", False, "N/A", []
        
    # 2. External Managed
    app_owner_org = entity_props.get("appOwnerOrganizationId")
    if app_owner_org and app_owner_org != tenant_org_id:
        return "EXTERNAL_MANAGED", None, "N/A", []
        
    # 3. Tenant App Link
    app_id = entity_props.get("appId")
    if app_index and app_id in app_index:
        app_finding = app_index[app_id]
        app_status = app_finding.get("ownerStatus")
        app_owners = app_finding.get("owners", [])
        
        if app_status in ["OWNED", "ORPHANED", "OWNER_LOOKUP_FAILED"]:
            return app_status, app_finding.get("isOrphaned"), "APPLICATION", app_owners
        # Fallback for other statuses
        return app_status, app_finding.get("isOrphaned"), "APPLICATION", app_owners
        
    return None

def determine_owner_status(entity_type, owners_list, owners_error, entity_props, tenant_org_id, app_index=None):
    """
    Fallback logic if metadata check didn't return a result (or for Applications).
    """
    local_owners = owners_list if owners_list else []
    has_local_owners = (len(local_owners) > 0)
    app_owner_org = entity_props.get("appOwnerOrganizationId")
    
    # Application Logic
    if entity_type == "Application":
        if owners_error:
            return "OWNER_LOOKUP_FAILED", None, "N/A", []
        if has_local_owners:
            return "OWNED", False, "APPLICATION", local_owners
        else:
            return "ORPHANED", True, "APPLICATION", []
            
    # SP Logic Checks (Re-check metadata just in case, but usually called after)
    # The caller manages the optimization skip. This is for when we HAVE local owners/error.
    
    # 4. Check Owner Lookup Error
    if owners_error:
        return "OWNER_LOOKUP_FAILED", None, "SERVICE_PRINCIPAL", []

    # 5. Local Owners (Prioritize over Unknown Org)
    if has_local_owners:
        return "OWNED", False, "SERVICE_PRINCIPAL", local_owners

    # 6. Unknown Owner Org (Only if no owners)
    if not app_owner_org:
        return "UNKNOWN_OWNER_ORG", None, "N/A", local_owners
        
    # 7. Default to Orphaned
    return "ORPHANED", True, "SERVICE_PRINCIPAL", []

def audit_entity(token, entity, entity_type, config, tenant_info, app_index=None, graph_sp=None):
    """
    Audits a single entity.
    graph_sp: {id, appRoles} for optimization
    """
    entity_id = entity.get("id")
    app_id = entity.get("appId")
    display_name = entity.get("displayName")
    
    errors = []
    
    # 1. Credentials
    pw_creds = analyze_credentials(entity.get("passwordCredentials", []), "Secret", config.expiry_window_days)
    key_creds = analyze_credentials(entity.get("keyCredentials", []), "Certificate", config.expiry_window_days)
    all_creds = pw_creds + key_creds
    
    if entity_type == "Application":
        fed_creds, fed_err = analyze_federated_credentials(token, entity_id)
        if fed_err:
            errors.append(f"Federated Creds Error: {fed_err}")
        all_creds.extend(fed_creds)
    
    # 2. Owners (Optimized)
    owners_list = None
    owners_err = None
    has_local_owners = None
    status, is_orphaned, source, effective_owners = (None, None, None, [])
    
    # Try metadata check first for SPs
    if entity_type == "ServicePrincipal":
        meta_result = assess_sp_metadata_ownership(entity, tenant_info["id"], app_index)
        if meta_result:
            status, is_orphaned, source, effective_owners = meta_result
            # Skipped lookup, so we don't know local owners
            has_local_owners = None 
    
    # If not determined by metadata, fetch owners
    if not status:
        if entity_type == "Application":
            owners_url = f"{GRAPH_BASE_URL}/applications/{entity_id}/owners?$select=id,userPrincipalName"
        else:
            owners_url = f"{GRAPH_BASE_URL}/servicePrincipals/{entity_id}/owners?$select=id,userPrincipalName"
            
        owners_list, owners_err = get_owners(token, owners_url)
        if owners_err:
            errors.append(f"Owners Error: {owners_err}")
            has_local_owners = None
        else:
            has_local_owners = (len(owners_list) > 0)
            
        status, is_orphaned, source, effective_owners = determine_owner_status(
            entity_type, 
            owners_list, 
            owners_err, 
            entity, 
            tenant_info["id"],
            app_index
        )
    
    # 3. Permissions
    app_perms = []
    delegated_perms = []
    risky_perms = []
    if entity_type == "ServicePrincipal":
        # App Role Assignments
        assign_url = f"{GRAPH_BASE_URL}/servicePrincipals/{entity_id}/appRoleAssignments?$select=resourceId,appRoleId"
        assignments, assign_err = paginate_graph_results(token, assign_url)
        
        if assign_err:
            errors.append(f"AppRoleAssignment Error: {assign_err}")
        else:
            for asm in assignments:
                resource_id = asm.get("resourceId")
                role_id = asm.get("appRoleId")
                
                # OPTIMIZATION: Check against Graph SP first
                if graph_sp and resource_id == graph_sp["id"]:
                     res_name = "Microsoft Graph" # or graph_sp displayName
                     role_name = graph_sp["appRoles"].get(role_id, "Unknown-Role")
                     is_graph_res = True
                     res_app_id = graph_sp.get("appId")
                else:
                    res_info = resolve_service_principal(token, resource_id)
                    res_name = res_info["displayName"]
                    role_name = res_info["appRoles"].get(role_id, "Unknown-Role")
                    is_graph_res = res_info.get("isGraph")
                    res_app_id = res_info.get("appId")
                
                risk = RISKY_PERMISSIONS_MAP.get(role_name) if is_graph_res else None
                    
                perm_obj = {
                    "type": "Application",
                    "resourceDisplayName": res_name,
                    "resourceAppId": res_app_id,
                    "permission": role_name,
                    "risk": risk
                }
                app_perms.append(perm_obj)
                if risk:
                    risky_perms.append(perm_obj)

        # Delegated Grants ($select optimized)
        grants_url = f"{GRAPH_BASE_URL}/oauth2PermissionGrants?$filter=clientId eq '{entity_id}'&$select=clientId,resourceId,scope"
        grants, grants_err = paginate_graph_results(token, grants_url)
        
        if grants_err:
            errors.append(f"DelegatedGrant Error: {grants_err}")
        else:
            for g in grants:
                resource_id = g.get("resourceId")
                scope = g.get("scope", "")
                
                if graph_sp and resource_id == graph_sp["id"]:
                    res_name = "Microsoft Graph"
                    is_graph_res = True
                    res_app_id = graph_sp.get("appId")
                else:
                    res_info = resolve_service_principal(token, resource_id)
                    res_name = res_info["displayName"]
                    is_graph_res = res_info.get("isGraph", False)
                    res_app_id = res_info.get("appId")
                
                for s in scope.split(" "):
                    if not s: continue
                    risk = RISKY_PERMISSIONS_MAP.get(s) if is_graph_res else None
                    
                    perm_obj = {
                        "type": "Delegated",
                        "resourceDisplayName": res_name,
                        "resourceAppId": res_app_id,
                        "permission": s,
                        "risk": risk
                    }
                    delegated_perms.append(perm_obj)
                    if risk:
                        risky_perms.append(perm_obj)

    return {
        "entityType": entity_type,
        "displayName": display_name,
        "appId": app_id,
        "objectId": entity_id,
        "servicePrincipalType": entity.get("servicePrincipalType"),
        "appOwnerOrganizationId": entity.get("appOwnerOrganizationId"),
        "publisherName": entity.get("publisherName"),
        "owners": effective_owners,
        "ownersCount": len(effective_owners),
        "localOwners": owners_list if owners_list is not None else [],
        "localOwnersCount": len(owners_list) if owners_list is not None else 0,
        "hasLocalOwners": has_local_owners,
        "ownerStatus": status,
        "ownerSource": source,
        "isOrphaned": is_orphaned,
        "credentials": all_creds,
        "permissions": {
            "application": app_perms,
            "delegated": delegated_perms
        },
        "riskyPermissions": risky_perms,
        "errors": errors
    }
