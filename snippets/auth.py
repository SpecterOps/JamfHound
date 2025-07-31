import requests
from requests.auth import HTTPBasicAuth

def get_jamf_token(base_url, username, password):
    """
    Obtain a bearer token from the Jamf Pro API.

    Args:
        base_url (str): The base URL of the Jamf Pro server (e.g., 'https://your-jamf-pro-server.com').
        username (str): Jamf Pro username with API access.
        password (str): Password for the Jamf Pro user.

    Returns:
        str: Bearer token for authenticating API requests.

    Raises:
        requests.HTTPError: If the request to obtain the token fails.
    """
    token_url = f"{base_url}/api/v1/auth/token"
    response = requests.post(token_url, auth=HTTPBasicAuth(username, password))
    response.raise_for_status()

    token_data = response.json()
    return token_data['token']