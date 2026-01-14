from PyQt5.QtCore import QUrl, QObject
from PyQt5.QtGui import QDesktopServices
from PyQt5.QtNetwork import QTcpServer, QTcpSocket
from qgis.core import QgsMessageLog

import urllib.parse
import requests
import secrets

# Miljøportalen DEMO konfiguration
AUTHORITY = "https://log-in.test.miljoeportal.dk/runtime/oauth2"
AUTH_URL = f"{AUTHORITY}/authorize.idp"
TOKEN_URL = f"{AUTHORITY}/token"

CLIENT_ID = "qgisplugin-integration-daiedittest"
CLIENT_SECRET = None  # Sæt til din client secret hvis du har en
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
        print(f"Path: {path}")
        
        # Parse query parameters
        query = urllib.parse.urlparse(path).query
        params = urllib.parse.parse_qs(query)
        
        if 'code' in params:
            code = params['code'][0]
            print(f"Authorization code modtaget: {code[:20]}...")
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
        print("\n=== STARTER OIDC LOGIN (DEBUG VERSION) ===")
        print(f"Client ID: {CLIENT_ID}")
        print(f"Client Secret: {'[SAT]' if CLIENT_SECRET else '[IKKE SAT]'}")
        QgsMessageLog.logMessage("Starter OIDC login", "OIDC")
        
        # Start listener
        self._start_listener()
        
        # Build authorization URL (UDEN PKCE)
        params = {
            'response_type': 'code',
            'client_id': CLIENT_ID,
            'redirect_uri': REDIRECT_URI,
            'scope': ' '.join(SCOPES),
            'state': self.state,
            'response_mode': 'query'
        }
        
        auth_url = f"{AUTH_URL}?{urllib.parse.urlencode(params)}"
        print(f"\nAuthorization URL:\n{auth_url}\n")
        
        # Open browser
        QDesktopServices.openUrl(QUrl(auth_url))
        
    def exchange_code_for_token(self, code):
        print("\n=== UDVEKSLER CODE TIL TOKEN ===")
        QgsMessageLog.logMessage("Udveksler authorization code til access token...", "OIDC")
        
        # Byg request data
        data = {
            'grant_type': 'authorization_code',
            'code': code,
            'redirect_uri': REDIRECT_URI,
            'client_id': CLIENT_ID
        }
        
        # Tilføj client_secret hvis den er sat
        if CLIENT_SECRET:
            data['client_secret'] = CLIENT_SECRET
            print("Client secret inkluderet i request")
        else:
            print("INGEN client secret - sender som public client")
        
        print(f"\nToken URL: {TOKEN_URL}")
        print(f"Authorization code længde: {len(code)} tegn")
        
        # Headers
        headers = {
            'Content-Type': 'application/x-www-form-urlencoded',
            'Accept': 'application/json'
        }
        
        # Test 1: Standard POST med form data
        self._try_token_exchange("Standard POST (form-urlencoded)", TOKEN_URL, data, headers)
        
        # Test 2: Prøv med Basic Auth hvis vi har client secret
        if CLIENT_SECRET:
            print("\n\n=== PRØVER MED BASIC AUTH ===")
            import base64
            auth_string = f"{CLIENT_ID}:{CLIENT_SECRET}"
            auth_bytes = base64.b64encode(auth_string.encode('utf-8')).decode('utf-8')
            
            headers_basic = {
                'Content-Type': 'application/x-www-form-urlencoded',
                'Accept': 'application/json',
                'Authorization': f'Basic {auth_bytes}'
            }
            
            data_basic = {
                'grant_type': 'authorization_code',
                'code': code,
                'redirect_uri': REDIRECT_URI
            }
            
            self._try_token_exchange("Basic Auth", TOKEN_URL, data_basic, headers_basic)
    
    def _try_token_exchange(self, method_name, url, data, headers):
        print(f"\n=== FORSØG: {method_name} ===")
        
        try:
            response = requests.post(url, data=data, headers=headers)
            
            print(f"Response status: {response.status_code}")
            print(f"Response Content-Type: {response.headers.get('Content-Type')}")
            
            # Tjek om det var success
            if response.status_code == 200:
                content_type = response.headers.get('Content-Type', '')
                if 'application/json' in content_type:
                    token_data = response.json()
                    print("\n✓✓✓ SUCCESS! ✓✓✓")
                    print(f"\nACCESS TOKEN:")
                    print(token_data.get('access_token'))
                    print(f"\nFULL TOKEN DATA:")
                    print(token_data)
                    return True
                else:
                    print(f"✗ Server returnerede text/html i stedet for JSON")
                    if "Internal server error" in response.text:
                        print("  → Internal server error detekteret")
            else:
                print(f"✗ HTTP fejl {response.status_code}")
                try:
                    error_data = response.json()
                    print(f"  Error: {error_data}")
                except:
                    print(f"  Response preview: {response.text[:200]}")
                    
        except Exception as e:
            print(f"✗ Exception: {e}")
            import traceback
            traceback.print_exc()
        
        return False


# Luk gammel listener hvis den eksisterer
try:
    if 'poc' in globals() and hasattr(poc, 'listener'):
        poc.listener.close()
        print("Lukkede gammel listener")
except:
    pass

print("\n" + "="*80)
print("OIDC DEBUG SCRIPT")
print("="*80)
print("\nDette script tester forskellige authentication metoder.")
print("Hvis du har en client secret, sæt CLIENT_SECRET variablen i toppen af filen.")
print("="*80 + "\n")

poc = OidcPoC()
poc.start()
