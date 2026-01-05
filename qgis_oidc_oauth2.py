from PyQt5.QtCore import QUrl, QObject
from PyQt5.QtGui import QDesktopServices
from PyQt5.QtNetwork import QTcpServer, QTcpSocket
from qgis.core import QgsMessageLog

import urllib.parse
import requests
import secrets
import hashlib
import base64

# Miljøportalen DEMO konfiguration
AUTHORITY = "https://log-in.miljoeportal.dk/runtime/oauth2"
AUTH_URL = f"{AUTHORITY}/authorize.idp"
TOKEN_URL = f"{AUTHORITY}/token"

CLIENT_ID = "qgisplugin-integration-daiedit"
REDIRECT_URI = "http://localhost:5001/"
PORT = 5001

SCOPES = [
    "openid",
    "http://www.miljoeportal.dk/roles"
]


class RedirectListener(QTcpServer):

    def __init__(self, parent=None):
        super().__init__(parent)

    def incomingConnection(self, socketDescriptor):
        socket = QTcpSocket(self)
        socket.setSocketDescriptor(socketDescriptor)
        socket.readyRead.connect(lambda: self.handle(socket))

    def handle(self, socket):
        data = socket.readAll().data().decode()
        
        first_line = data.splitlines()[0]
        path = first_line.split(" ")[1]
        
        # Ignorer favicon requests
        if path == '/favicon.ico':
            socket.write("HTTP/1.1 404 Not Found\r\n\r\n".encode('utf-8'))
            socket.disconnectFromHost()
            return
        
        print("\n=== CALLBACK MODTAGET ===")
        print(f"Raw data:\n{data}")
        print(f"\nFirst line: {first_line}")
        print(f"Path: {path}")
        
        # Parse query parameters
        query = urllib.parse.urlparse(path).query
        print(f"Query string: {query}")
        
        params = urllib.parse.parse_qs(query)
        print(f"Parsed params: {params}")
        
        if 'code' in params:
            code = params['code'][0]
            print(f"\nAuthorization code modtaget: {code[:20]}...")
            self.parent().exchange_code_for_token(code)
        else:
            print("\nFEJL: Ingen authorization code i callback!")
            if 'error' in params:
                print(f"OAuth error: {params['error']}")
        
        socket.write("HTTP/1.1 200 OK\r\n\r\nLogin OK - du kan lukke browseren".encode('utf-8'))
        socket.disconnectFromHost()


class OidcPoC(QObject):

    def __init__(self):
        super().__init__()
        
        # PKCE setup
        self.code_verifier = base64.urlsafe_b64encode(secrets.token_bytes(32)).decode('utf-8').rstrip('=')
        challenge = hashlib.sha256(self.code_verifier.encode('utf-8')).digest()
        self.code_challenge = base64.urlsafe_b64encode(challenge).decode('utf-8').rstrip('=')
        
        self.state = secrets.token_urlsafe(32)

    def _start_listener(self):
        self.listener = RedirectListener(self)
        success = self.listener.listen(port=PORT)
        if success:
            print(f"\n✓ Lytter på port {PORT}")
            QgsMessageLog.logMessage(f"Lytter på port {PORT}", "OIDC")
        else:
            print(f"\n✗ FEJL: Kunne ikke lytte på port {PORT}")
            QgsMessageLog.logMessage(f"FEJL: Kunne ikke lytte på port {PORT}", "OIDC")

    def start(self):
        print("\n=== STARTER OIDC LOGIN ===")
        QgsMessageLog.logMessage("Starter OIDC login", "OIDC")
        
        # Start listener
        self._start_listener()
        
        # Build authorization URL
        params = {
            'response_type': 'code',
            'client_id': CLIENT_ID,
            'redirect_uri': REDIRECT_URI,
            'scope': ' '.join(SCOPES),
            'state': self.state,
            'code_challenge': self.code_challenge,
            'code_challenge_method': 'S256',
            'response_mode': 'query'
        }
        
        auth_url = f"{AUTH_URL}?{urllib.parse.urlencode(params)}"
        print(f"\nAuthorization URL:\n{auth_url}\n")
        print(f"State: {self.state}")
        print(f"Code challenge: {self.code_challenge}")
        print(f"Code verifier: {self.code_verifier[:20]}...")
        
        # Open browser
        QDesktopServices.openUrl(QUrl(auth_url))
        
    def exchange_code_for_token(self, code):
        print("\n=== UDVEKSLER CODE TIL TOKEN ===")
        QgsMessageLog.logMessage("Udveksler authorization code til access token...", "OIDC")
        
        data = {
            'grant_type': 'authorization_code',
            'code': code,
            'redirect_uri': REDIRECT_URI,
            'client_id': CLIENT_ID,
            'code_verifier': self.code_verifier
        }
        
        print(f"Token URL: {TOKEN_URL}")
        print(f"Request data:")
        for key, value in data.items():
            if key == 'code' or key == 'code_verifier':
                print(f"  {key}: {value[:20]}...")
            else:
                print(f"  {key}: {value}")
        
        try:
            print("\nSender POST request...")
            response = requests.post(TOKEN_URL, data=data)
            
            print(f"\nResponse status: {response.status_code}")
            print(f"Response Content-Type: {response.headers.get('Content-Type')}")
            
            response.raise_for_status()
            
            # Tjek om responset er JSON
            content_type = response.headers.get('Content-Type', '')
            if 'application/json' not in content_type:
                error_msg = f"Server returnerede ikke JSON (Content-Type: {content_type})"
                print(f"\n✗ FEJL: {error_msg}")
                print(f"Response body preview:\n{response.text[:500]}...\n")
                QgsMessageLog.logMessage(error_msg, "OIDC")
                
                # Tjek om det er en Identify error side
                if 'Internal server error' in response.text:
                    print("Server fejl: Internal server error - muligvis problem med PKCE configuration")
                return
            
            token_data = response.json()
            access_token = token_data.get('access_token')
            
            QgsMessageLog.logMessage("Login OK - token modtaget", "OIDC")
            print("\n✓ SUCCESS!")
            print("\nACCESS TOKEN:")
            print(access_token)
            print("\nFULL TOKEN DATA:")
            print(token_data)
            
        except requests.exceptions.HTTPError as e:
            error_msg = f"HTTP fejl {response.status_code}: {response.text[:500]}"
            QgsMessageLog.logMessage(f"Fejl ved token udveksling: {error_msg}", "OIDC")
            print(f"\n✗ HTTP ERROR: {error_msg}")
        except Exception as e:
            QgsMessageLog.logMessage(f"Fejl ved token udveksling: {e}", "OIDC")
            print(f"\n✗ ERROR: {e}")
            import traceback
            traceback.print_exc()


# Luk gammel listener hvis den eksisterer
try:
    if 'poc' in globals() and hasattr(poc, 'listener'):
        poc.listener.close()
        print("Lukkede gammel listener")
except:
    pass

poc = OidcPoC()
poc.start()
