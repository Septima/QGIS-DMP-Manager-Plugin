"""
Simpel OAuth2 login flow for Miljøportalen DEMO med PKCE

"""

import json
import webbrowser
import secrets
import urllib.parse
import hashlib
import base64
from http.server import HTTPServer, BaseHTTPRequestHandler
from pathlib import Path
import requests
from datetime import datetime


# Load configuration
config_path = Path(__file__).parent / "dmp_manager" / "configuration.json"
with open(config_path, 'r', encoding='utf-8') as f:
    config = json.load(f)

# Get mp_demo configuration
mp_demo = config["Access"]["mp_demo"]

CLIENT_ID = mp_demo["clientId"]
CLIENT_SECRET = mp_demo.get("clientSecret")  # None hvis ikke sat
REDIRECT_URI = mp_demo["redirectUri"]
AUTHORITY = mp_demo["authority"]
SCOPE = mp_demo["scope"]
PORT = mp_demo["port"]

AUTH_URL = f"{AUTHORITY}/authorize.idp"
TOKEN_URL = f"{AUTHORITY}/token"

# Generate state for CSRF protection
STATE = secrets.token_urlsafe(32)

# Generate PKCE code verifier and challenge
CODE_VERIFIER = base64.urlsafe_b64encode(secrets.token_bytes(32)).decode('utf-8').rstrip('=')
CODE_CHALLENGE = base64.urlsafe_b64encode(
    hashlib.sha256(CODE_VERIFIER.encode('utf-8')).digest()
).decode('utf-8').rstrip('=')

# Global variable to store the authorization code
auth_code = None


class CallbackHandler(BaseHTTPRequestHandler):
    """Handles the OAuth callback"""
    
    def log_message(self, format, *args):
        """Suppress default logging"""
        pass
    
    def do_GET(self):
        global auth_code
        
        # Parse the callback URL
        parsed_path = urllib.parse.urlparse(self.path)
        params = urllib.parse.parse_qs(parsed_path.query)
        
        if 'code' in params:
            auth_code = params['code'][0]
            
            # Send success response to browser
            self.send_response(200)
            self.send_header('Content-type', 'text/html')
            self.end_headers()
            
            html = """
            <html>
            <head><title>Login OK</title></head>
            <body style="font-family: Arial; text-align: center; padding: 50px;">
                <h1>✅ Login gennemført!</h1>
                <p>Du kan nu lukke dette vindue.</p>
            </body>
            </html>
            """
            self.wfile.write(html.encode())
        else:
            # Handle error
            self.send_response(400)
            self.send_header('Content-type', 'text/html')
            self.end_headers()
            
            error = params.get('error', ['Unknown error'])[0]
            html = f"""
            <html>
            <head><title>Login fejl</title></head>
            <body style="font-family: Arial; text-align: center; padding: 50px;">
                <h1>❌ Login fejlede</h1>
                <p>Fejl: {error}</p>
            </body>
            </html>
            """
            self.wfile.write(html.encode())


def start_login_flow():
    """Start OAuth2 login flow"""
    
    print("=" * 60)
    print("🔐 MILJØPORTALEN LOGIN")
    print("=" * 60)
    print(f"Client ID: {CLIENT_ID}")
    print(f"Redirect URI: {REDIRECT_URI}")
    print(f"Scopes: {SCOPE}")
    print(f"PKCE: ✅ Aktiveret (S256)")
    print()
    
    # Build authorization URL
    params = {
        'response_type': 'code',
        'client_id': CLIENT_ID,
        'redirect_uri': REDIRECT_URI,
        'scope': SCOPE, 
        'state': STATE,
        'code_challenge': CODE_CHALLENGE,
        'code_challenge_method': 'S256',
        'response_mode': 'query'
    }
    
    auth_url = f"{AUTH_URL}?{urllib.parse.urlencode(params)}"
    
    print("📱 Åbner browser til login...")
    print()
    
    # Open browser
    webbrowser.open(auth_url)
    
    # Start local server to receive callback
    print(f"🌐 Starter lokal server på port {PORT}...")
    server = HTTPServer(('localhost', PORT), CallbackHandler)
    
    print("⏳ Venter på login callback...")
    print()
    
    # Wait for one request (the callback)
    server.handle_request()
    
    return auth_code


def exchange_code_for_token(code):
    """Exchange authorization code for access token"""
    
    print("=" * 60)
    print("🔄 UDVEKSLER CODE TIL TOKEN")
    print("=" * 60)
    
    data = {
        'grant_type': 'authorization_code',
        'code': code,
        'redirect_uri': REDIRECT_URI,
        'client_id': CLIENT_ID,
        'code_verifier': CODE_VERIFIER  # PKCE parameter
    }
    
    # Tilføj client_secret hvis den findes (men den gør den ikke)
    if CLIENT_SECRET:
        data['client_secret'] = CLIENT_SECRET
        print("🔑 Bruger client_secret")
    else:
        print("ℹ️  Public client (ingen client_secret)")
    
    print("✅ Bruger PKCE code_verifier")
    
    headers = {
        'Content-Type': 'application/x-www-form-urlencoded',
        'Accept': 'application/json'
    }
    
    print()
    print("📋 Token request detaljer:")
    print(f"   URL: {TOKEN_URL}")
    print(f"   Method: POST")
    print(f"   Data: {list(data.keys())}")
    print()
    
    try:
        print("📤 Sender token request...")
        response = requests.post(TOKEN_URL, data=data, headers=headers, timeout=10)
        
        print(f"📥 Response status: {response.status_code}")
        print(f"   Content-Type: {response.headers.get('Content-Type', 'N/A')}")
        print()
        
        # Check content type
        content_type = response.headers.get('Content-Type', '')
        
        if 'application/json' not in content_type:
            print(f"❌ FEJL: Server returnerede {content_type} i stedet for JSON")
            print()
            print("=" * 60)
            print("FULD SERVER RESPONSE:")
            print("=" * 60)
            print(response.text)
            print("=" * 60)
            print()
            
            # Prøv at finde error i HTML
            if '<title>' in response.text:
                import re
                title_match = re.search(r'<title>(.*?)</title>', response.text, re.IGNORECASE | re.DOTALL)
                if title_match:
                    print(f"📄 HTML Title: {title_match.group(1).strip()}")
            
            return None
        
        response.raise_for_status()
        token_data = response.json()
        
        print("✅ TOKEN MODTAGET!")
        print()
        return token_data
        
    except requests.exceptions.RequestException as e:
        print(f"❌ REQUEST FEJL: {e}")
        if hasattr(e, 'response') and e.response is not None:
            print()
            print("Response body:")
            print(e.response.text[:1000])
        return None


def main():
    """Main login flow"""
    
    # Step 1: Get authorization code
    code = start_login_flow()
    
    if not code:
        print("❌ Ingen authorization code modtaget")
        return
    
    print(f"✅ Authorization code modtaget ({len(code)} tegn)")
    print()
    
    # Step 2: Exchange code for token
    token_data = exchange_code_for_token(code)
    
    if not token_data:
        print("❌ Kunne ikke få token")
        return
    
    # Display token info
    access_token = token_data.get('access_token', '')
    expires_in = token_data.get('expires_in', 0)
    token_type = token_data.get('token_type', '')
    
    print("=" * 60)
    print("📋 TOKEN INFORMATION")
    print("=" * 60)
    print(f"Token type: {token_type}")
    print(f"Expires in: {expires_in} sekunder ({expires_in // 60} minutter)")
    print(f"Token længde: {len(access_token)} tegn")
    print()
    print("Access Token (første 100 tegn):")
    print(access_token[:100] + "...")
    print()
    
    # Save to configuration
    config["Values"]["Token value"] = access_token
    config["Values"]["Token time"] = datetime.now().strftime("%Y-%m-%dT%H:%M:%S")
    
    with open(config_path, 'w', encoding='utf-8') as f:
        json.dump(config, f, indent=4, ensure_ascii=False)
    
    print("💾 Token gemt i configuration.json")
    print()
    print("=" * 60)
    print("🎉 LOGIN GENNEMFØRT!")
    print("=" * 60)


if __name__ == "__main__":
    main()
