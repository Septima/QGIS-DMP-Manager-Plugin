import threading
import webbrowser
import requests
import base64
import hashlib
import os
import time
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlencode, urlparse, parse_qs

# =========================
# KONFIGURATION
# =========================

AUTHORITY = "https://log-in.test.miljoeportal.dk/runtime/oauth2"

AUTH_URL = f"{AUTHORITY}/authorize.idp"
TOKEN_URL = f"{AUTHORITY}/token"

CLIENT_ID = "qgisplugin-integration-daiedittest"
REDIRECT_URI = "http://localhost:5001/login"
PORT = 5001

SCOPES = [
    "openid",
    "http://www.miljoeportal.dk/roles"
]

# =========================
# HJÆLPEFUNKTIONER
# =========================

def log(msg, debug=True):
    if debug:
        print(f"[MP-OAuth2] {msg}")

def generate_pkce():
    code_verifier = base64.urlsafe_b64encode(os.urandom(40)).decode("utf-8").rstrip("=")
    challenge = hashlib.sha256(code_verifier.encode("utf-8")).digest()
    code_challenge = base64.urlsafe_b64encode(challenge).decode("utf-8").rstrip("=")
    return code_verifier, code_challenge

# =========================
# OAUTH2 LOGIN FUNKTION
# =========================

def oauth2_login_qgis_mp_demo(debug=True):
    log("Starter Miljøportalen OAuth2 login (Authorization Code + PKCE)", debug)

    code_verifier, code_challenge = generate_pkce()
    log("PKCE code_verifier og code_challenge genereret", debug)

    auth_params = {
        "response_type": "code",
        "client_id": CLIENT_ID,
        "redirect_uri": REDIRECT_URI,
        "scope": " ".join(SCOPES),
        "code_challenge": code_challenge,
        "code_challenge_method": "S256"
    }

    auth_request_url = f"{AUTH_URL}?{urlencode(auth_params)}"

    log("Åbner browser til:", debug)
    log(auth_request_url, debug)

    auth_code_container = {}

    class RedirectHandler(BaseHTTPRequestHandler):
        def do_GET(self):
            parsed = urlparse(self.path)
            if parsed.path == "/login":
                qs = parse_qs(parsed.query)
                if "code" in qs:
                    auth_code_container["code"] = qs["code"][0]

                self.send_response(200)
                self.send_header("Content-Type", "text/html")
                self.end_headers()
                self.wfile.write(b"""
                    <html>
                        <body>
                            <h2>Login gennemf\u00f8rt</h2>
                            <p>Du kan lukke dette vindue.</p>
                        </body>
                    </html>
                """)

        def log_message(self, format, *args):
            return

    httpd = HTTPServer(("localhost", PORT), RedirectHandler)
    server_thread = threading.Thread(target=httpd.serve_forever)
    server_thread.daemon = True
    server_thread.start()

    log(f"Redirect-server lytter p\u00e5 {REDIRECT_URI}", debug)

    webbrowser.open(auth_request_url)

    log("Venter p\u00e5 authorization code …", debug)

    while "code" not in auth_code_container:
        time.sleep(0.2)

    httpd.shutdown()

    auth_code = auth_code_container["code"]
    log(f"Authorization code modtaget ({len(auth_code)} tegn)", debug)

    # =========================
    # TOKEN EXCHANGE (VIGTIG DEL)
    # =========================

    headers = {
        "Accept": "application/json",
        "Content-Type": "application/x-www-form-urlencoded",
        "X-Requested-With": "XMLHttpRequest"
    }

    token_payload = {
        "grant_type": "authorization_code",
        "client_id": CLIENT_ID,
        "code": auth_code,
        "redirect_uri": REDIRECT_URI,
        "code_verifier": code_verifier
    }

    log("Kalder token endpoint", debug)

    r = requests.post(
        TOKEN_URL,
        data=token_payload,
        headers=headers
    )

    log(f"Token HTTP status: {r.status_code}", debug)
    log(f"Token Content-Type: {r.headers.get('Content-Type')}", debug)
    log(f"Token raw response:\n{r.text}", debug)

    if "application/json" not in r.headers.get("Content-Type", ""):
        raise RuntimeError("Token endpoint returnerede ikke JSON – login fejlede")

    token_response = r.json()

    log("OAuth2 token modtaget korrekt", debug)

    return token_response

# =========================
# EKSEMPEL
# =========================
# token = oauth2_login_qgis_mp_demo(debug=True)
