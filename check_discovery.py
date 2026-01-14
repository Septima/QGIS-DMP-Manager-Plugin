import requests
import json

# OIDC Discovery endpoint
authority = "https://log-in.test.miljoeportal.dk/runtime/oauth2"
discovery_url = f"{authority}/.well-known/openid-configuration"

print("=== OIDC DISCOVERY ENDPOINT ===")
print(f"URL: {discovery_url}\n")

try:
    response = requests.get(discovery_url)
    print(f"Status: {response.status_code}")
    
    if response.status_code == 200:
        config = response.json()
        print("\n=== DISCOVERY CONFIGURATION ===")
        print(json.dumps(config, indent=2))
        
        print("\n=== ENDPOINTS ===")
        print(f"Authorization: {config.get('authorization_endpoint')}")
        print(f"Token: {config.get('token_endpoint')}")
        print(f"UserInfo: {config.get('userinfo_endpoint')}")
        
        print("\n=== SUPPORTED FEATURES ===")
        print(f"PKCE methods: {config.get('code_challenge_methods_supported')}")
        print(f"Grant types: {config.get('grant_types_supported')}")
        print(f"Response types: {config.get('response_types_supported')}")
        
    else:
        print(f"ERROR: {response.text}")
        
except Exception as e:
    print(f"EXCEPTION: {e}")
