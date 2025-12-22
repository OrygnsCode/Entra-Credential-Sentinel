import time
import requests
import logging
import random
import math

logger = logging.getLogger("EntraSentinel")
GRAPH_BASE_URL = "https://graph.microsoft.com/v1.0"
MAX_RETRIES = 3
TIMEOUT_SECONDS = 30 # Increased timeout

# Cache for resource resolution: { resourceId: { "displayName": str, "appRoles": {id: val} } }
_RESOURCE_CACHE = {}

def graph_request(method, url, token, params=None):
    """
    Executes a Graph API request with retries and error handling.
    Returns: (json_data, error_message)
    """
    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json"
    }
    
    for attempt in range(MAX_RETRIES):
        try:
            response = requests.request(
                method, 
                url, 
                headers=headers, 
                params=params, 
                timeout=TIMEOUT_SECONDS
            )
            
            if response.status_code in [200, 201, 202, 204]:
                if response.status_code == 204 or not response.content:
                    return None, None
                return response.json(), None
            
            # Critical Application Errors
            if response.status_code in [400, 401, 403]:
                error_msg = f"Graph API Error {response.status_code} at {url}: {response.text}"
                logger.error(error_msg)
                return None, error_msg

            # Rate limiting / Transient
            if response.status_code in [429, 503, 504]:
                retry_after = int(response.headers.get("Retry-After", 0))
                # Add 20% jitter
                jitter = random.uniform(0.8, 1.2)
                
                if retry_after > 0:
                    sleep_time = retry_after * jitter
                else:
                    sleep_time = (2 ** attempt) * jitter
                
                sleep_time = min(sleep_time, 60)
                
                logger.warning(f"Rate limited or server error ({response.status_code}). Retrying in {sleep_time:.2f}s...")
                time.sleep(sleep_time)
                continue
            
            # Other errors
            msg = f"Graph API Error {response.status_code}: {response.text}"
            logger.error(msg)
            return None, msg
            
        except requests.exceptions.RequestException as e:
            sleep_time = (2 ** attempt) * random.uniform(0.8, 1.2)
            logger.warning(f"Network error: {e}. Retrying in {sleep_time:.2f}s...")
            time.sleep(sleep_time)
            
    return None, f"Max retries exceeded for {url}"

def paginate_graph_results(token, url, result_key="value"):
    """
    Fully paginates a Graph API list endpoint.
    Returns: (list_of_items, error_message)
    Always returns a list (empty if error) to prevent iteration crashes.
    """
    items = []
    
    # First Page
    data, error = graph_request("GET", url, token)
    if error:
        return items, error  # Return empty list + Error
        
    if not data:
        return items, None
        
    if result_key in data:
        items.extend(data[result_key])
    
    current_resp = data
    while "@odata.nextLink" in current_resp:
        next_link = current_resp["@odata.nextLink"]
        resp, err = graph_request("GET", next_link, token)
        if err:
            return items, err # Return partial list + Error
            
        if not resp:
            break
            
        current_resp = resp
        if result_key in current_resp:
            items.extend(current_resp[result_key])
            
    return items, None

def resolve_service_principal(token, sp_id):
    """
    Resolves Service Principal details with caching.
    Fetches expanded properties for accurate classification.
    Returns dict or None if lookup fails.
    """
    if sp_id in _RESOURCE_CACHE:
        return _RESOURCE_CACHE[sp_id]
    
    # Updated query to include fields needed for Microsoft First Party detection
    url = f"{GRAPH_BASE_URL}/servicePrincipals/{sp_id}?$select=id,appId,displayName,appRoles,servicePrincipalType,tags,appOwnerOrganizationId,publisherName"
    data, error = graph_request("GET", url, token)
    
    if error or not data:
        logger.warning(f"Could not resolve resource SP {sp_id}: {error}")
        return {
            "displayName": "Unknown Resource",
            "appId": None,
            "appRoles": {},
            "isGraph": False,
            "publisherName": None,
            "tags": [],
            "servicePrincipalType": None,
            "appOwnerOrganizationId": None
        }
    
    # Process appRoles into id -> value map
    roles_map = {}
    for r in data.get("appRoles", []):
        rid = r.get("id")
        val = r.get("value") or r.get("displayName")
        roles_map[rid] = val
       
    # Microsoft Graph App ID is consistently this GUID
    is_graph = (data.get("appId") == "00000003-0000-0000-c000-000000000000")
        
    info = {
        "displayName": data.get("displayName", "Unknown"),
        "appId": data.get("appId"),
        "appRoles": roles_map,
        "isGraph": is_graph,
        "servicePrincipalType": data.get("servicePrincipalType"),
        "tags": data.get("tags", []),
        "appOwnerOrganizationId": data.get("appOwnerOrganizationId"),
        "publisherName": data.get("publisherName")
    }
    
    _RESOURCE_CACHE[sp_id] = info
    return info
