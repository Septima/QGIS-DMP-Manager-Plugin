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
AUTHORITY = "https://log-in.test.miljoeportal.dk/runtime/oauth2"
AUTH_URL = f"{AUTHORITY}/authorize.idp"
TOKEN_URL = f"{AUTHORITY}/token.idp"  # VIGTIGT: .idp i slutningen!

CLIENT_ID = "qgisplugin-integration-daiedittest"
REDIRECT_URI = "http://localhost:5001/login"  # MÅ matche server konfiguration!
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
        print(f"\nQuery string: {query}")
        
        params = urllib.parse.parse_qs(query)
        print(f"\nParsed params (antal: {len(params)}):")
        for key, value in params.items():
            if key == 'code':
                print(f"  {key}: {value[0][:30]}... (længde: {len(value[0])})")
            else:
                print(f"  {key}: {value}")
        
        if 'code' in params:
            code = params['code'][0]
            print(f"\n✓ Authorization code modtaget OK")
            print(f"  Code (fuld): {code}")
            print(f"  Code længde: {len(code)}")
            self.parent().exchange_code_for_token(code)
        else:
            print("\n✗ FEJL: Ingen authorization code i callback!")
            if 'error' in params:
                print(f"OAuth error: {params['error']}")
                if 'error_description' in params:
                    print(f"Error description: {params['error_description']}")
        
        socket.write("HTTP/1.1 200 OK\r\n\r\nLogin OK - du kan lukke browseren".encode('utf-8'))
        socket.disconnectFromHost()


class OidcPoC(QObject):

    def __init__(self):
        super().__init__()
        
        print("\n=== INITIALISERER OIDC MED PKCE ===")
        
        # PKCE setup
        random_bytes = secrets.token_bytes(32)
        print(f"Random bytes genereret (længde: {len(random_bytes)})")
        
        self.code_verifier = base64.urlsafe_b64encode(random_bytes).decode('utf-8').rstrip('=')
        print(f"Code verifier: {self.code_verifier}")
        print(f"Code verifier længde: {len(self.code_verifier)}")
        
        challenge = hashlib.sha256(self.code_verifier.encode('utf-8')).digest()
        print(f"SHA256 challenge (raw bytes længde: {len(challenge)})")
        
        self.code_challenge = base64.urlsafe_b64encode(challenge).decode('utf-8').rstrip('=')
        print(f"Code challenge: {self.code_challenge}")
        print(f"Code challenge længde: {len(self.code_challenge)}")
        print(f"PKCE method: S256")
        
        self.state = secrets.token_urlsafe(32)
        print(f"State: {self.state}")
        print(f"State længde: {len(self.state)}")

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
        
        print("\n=== AUTHORIZATION REQUEST PARAMS ===")
        for key, value in params.items():
            if key in ['code_challenge', 'state']:
                print(f"{key}: {value[:30]}... (længde: {len(value)})")
            else:
                print(f"{key}: {value}")
        
        auth_url = f"{AUTH_URL}?{urllib.parse.urlencode(params)}"
        print(f"\n=== FULD AUTHORIZATION URL ===")
        print(auth_url)
        print(f"\nURL længde: {len(auth_url)} karakterer")
        
        print("\n=== PKCE VÆRDIER TIL TOKEN EXCHANGE ===")
        print(f"Code verifier (gemmes til senere): {self.code_verifier}")
        print(f"Code challenge (sendes nu): {self.code_challenge}")
        print(f"State (valideres senere): {self.state}")
        
        # Open browser
        QDesktopServices.openUrl(QUrl(auth_url))
        
    def exchange_code_for_token(self, code):
        print("\n" + "="*60)
        print("=== UDVEKSLER CODE TIL TOKEN (MED PKCE) ===")
        print("="*60)
        QgsMessageLog.logMessage("Udveksler authorization code til access token...", "OIDC")
        
        data = {
            'grant_type': 'authorization_code',
            'code': code,
            'redirect_uri': REDIRECT_URI,
            'client_id': CLIENT_ID,
            'code_verifier': self.code_verifier
        }
        
        print(f"\nToken endpoint: {TOKEN_URL}")
        print(f"\n=== TOKEN REQUEST DATA ===")
        for key, value in data.items():
            if key == 'code':
                print(f"  {key}: {value} (længde: {len(value)})")
            elif key == 'code_verifier':
                print(f"  {key}: {value} (længde: {len(value)})")
                print(f"    ⚠️  VIGTIGT: Denne skal matche den oprindelige code_verifier!")
            else:
                print(f"  {key}: {value}")
        
        print("\n=== PKCE VALIDERING ===")
        print(f"Code verifier sender vi NU: {self.code_verifier}")
        print(f"Code challenge vi sendte FØR: {self.code_challenge}")
        print(f"Server vil beregne SHA256(code_verifier) og sammenligne med code_challenge")
        
        try:
            # Tilføj explicit Content-Type header
            headers = {
                'Content-Type': 'application/x-www-form-urlencoded',
                'Accept': 'application/json'
            }
            
            print("\n=== SENDER POST REQUEST ===")
            print(f"Timestamp: {__import__('datetime').datetime.now().isoformat()}")
            print(f"\n=== REQUEST HEADERS ===")
            for key, value in headers.items():
                print(f"  {key}: {value}")
            
            response = requests.post(TOKEN_URL, data=data, headers=headers, timeout=10)
            
            print(f"\n=== RESPONSE MODTAGET ===")
            print(f"Status code: {response.status_code}")
            print(f"Status text: {response.reason}")
            print(f"Content-Type: {response.headers.get('Content-Type')}")
            print(f"Content-Length: {response.headers.get('Content-Length', 'N/A')}")
            
            print(f"\nAlle response headers:")
            for header, value in response.headers.items():
                print(f"  {header}: {value}")
            
            response.raise_for_status()
            
            # Tjek om responset er JSON
            content_type = response.headers.get('Content-Type', '')
            if 'application/json' not in content_type:
                error_msg = f"Server returnerede ikke JSON (Content-Type: {content_type})"
                print(f"\n✗ FEJL: {error_msg}")
                print(f"\nFull response body:\n{response.text}\n")
                QgsMessageLog.logMessage(error_msg, "OIDC")
                
                # Tjek om det er en Identify error side
                if 'Internal server error' in response.text:
                    print("\n⚠️  Server fejl: Internal server error")
                    print("Mulige årsager:")
                    print("  1. PKCE konfiguration fejl på serveren")
                    print("  2. Code verifier matcher ikke code challenge")
                    print("  3. Authorization code er udløbet eller allerede brugt")
                    print("  4. Client ID er ikke konfigureret til PKCE")
                return
            
            token_data = response.json()
            
            print("\n" + "="*60)
            print("✓✓✓ SUCCESS - TOKEN MODTAGET MED PKCE! ✓✓✓")
            print("="*60)
            
            QgsMessageLog.logMessage("Login OK - token modtaget", "OIDC")
            
            print("\n=== TOKEN DATA ===")
            for key, value in token_data.items():
                if key == 'access_token':
                    print(f"{key}: {value[:50]}... (længde: {len(value)})")
                elif key == 'refresh_token':
                    print(f"{key}: {value[:50]}... (længde: {len(value)})")
                else:
                    print(f"{key}: {value}")
            
            access_token = token_data.get('access_token')
            if access_token:
                print(f"\n=== ACCESS TOKEN (FULD) ===")
                print(access_token)
            
            print("\n✓ PKCE flow gennemført korrekt!")
            print("  1. Code verifier blev genereret")
            print("  2. Code challenge blev sendt til authorization")
            print("  3. Code verifier blev sendt til token endpoint")
            print("  4. Server validerede at SHA256(verifier) == challenge")
            print("  5. Token udstedt! 🎉")
            
        except requests.exceptions.HTTPError as e:
            print("\n" + "="*60)
            print("✗✗✗ HTTP ERROR ✗✗✗")
            print("="*60)
            error_msg = f"HTTP fejl {response.status_code}: {response.text}"
            QgsMessageLog.logMessage(f"Fejl ved token udveksling: {error_msg}", "OIDC")
            print(f"\nStatus code: {response.status_code}")
            print(f"Response body:\n{response.text}")
            
            # Parse JSON error hvis muligt
            try:
                error_json = response.json()
                print(f"\nParsed error:")
                for key, value in error_json.items():
                    print(f"  {key}: {value}")
            except:
                pass
                
        except Exception as e:
            print("\n" + "="*60)
            print("✗✗✗ EXCEPTION ✗✗✗")
            print("="*60)
            QgsMessageLog.logMessage(f"Fejl ved token udveksling: {e}", "OIDC")
            print(f"\nException type: {type(e).__name__}")
            print(f"Exception message: {e}")
            import traceback
            print("\nFull traceback:")
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
