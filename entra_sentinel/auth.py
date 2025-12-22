import sys
import logging
import msal
import requests

logger = logging.getLogger("EntraSentinel")

def get_access_token(tenant_id, client_id, client_secret):
    """
    Acquires a client credential token for Microsoft Graph.
    Returns: token (str)
    Exits if token cannot be acquired.
    """
    authority = f"https://login.microsoftonline.com/{tenant_id}"
    app = msal.ConfidentialClientApplication(
        client_id,
        authority=authority,
        client_credential=client_secret
    )
    result = app.acquire_token_for_client(scopes=["https://graph.microsoft.com/.default"])
    
    if "access_token" in result:
        return result["access_token"]
    else:
        logger.error(f"Failed to acquire token: {result.get('error_description')}")
        print(f"Error: Failed to acquire access token. Check credentials. MSAL Error: {result.get('error_description')}")
        sys.exit(3)

def get_tenant_info(token):
    """
    Retrieves tenant organization details.
    Returns: { "id": str, "displayName": str } or exits if fails.
    """
    url = "https://graph.microsoft.com/v1.0/organization?$select=id,displayName"
    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json"
    }
    
    try:
        resp = requests.get(url, headers=headers, timeout=20)
        if resp.status_code == 200:
            data = resp.json()
            if "value" in data and len(data["value"]) > 0:
                return data["value"][0]
    except Exception as e:
        logger.error(f"Failed to fetch organization info: {e}")
        
    print("Error: Failed to retrieve Tenant Organization Info. Check permissions (Directory.Read.All required).")
    sys.exit(3)
