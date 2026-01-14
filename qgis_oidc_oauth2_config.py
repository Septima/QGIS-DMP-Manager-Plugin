from PyQt5.QtCore import QUrl, QObject
from PyQt5.QtGui import QDesktopServices
from PyQt5.QtNetwork import QTcpServer, QTcpSocket
from qgis.core import QgsMessageLog, Qgis

import urllib.parse
import requests
import secrets
import json
import os


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
        
        # Parse query parameters
        query = urllib.parse.urlparse(path).query
        params = urllib.parse.parse_qs(query)
        
        if 'code' in params:
            code = params['code'][0]
            self.parent().exchange_code_for_token(code)
        else:
            if 'error' in params:
                error_msg = f"OAuth error: {params['error']}"
                if 'error_description' in params:
                    error_msg += f" - {params['error_description']}"
                QgsMessageLog.logMessage(error_msg, "OIDC", level=Qgis.Critical)
        
        socket.write("HTTP/1.1 200 OK\r\n\r\nLogin OK - du kan lukke browseren".encode('utf-8'))
        socket.disconnectFromHost()


class OidcClient(QObject):
    """OIDC Client der læser konfiguration fra configuration.json"""

    def __init__(self, config_name="mp_demo", config_file=None):
        super().__init__()
        
        # Load configuration
        self.config_name = config_name
        self.config = self._load_config(config_name, config_file)
        
        self.state = secrets.token_urlsafe(32)
        self.access_token = None
        self.refresh_token = None
        self.token_callback = None

    def _load_config(self, config_name, config_file=None):
        """Læs konfiguration fra configuration.json"""
        
        if config_file is None:
            # Prøv at finde configuration.json i dmp_manager mappen
            script_dir = os.path.dirname(os.path.abspath(__file__))
            config_file = os.path.join(script_dir, "dmp_manager", "configuration.json")
            
            if not os.path.exists(config_file):
                # Prøv i parent directory
                config_file = os.path.join(os.path.dirname(script_dir), "dmp_manager", "configuration.json")
        
        try:
            with open(config_file, 'r', encoding='utf-8') as f:
                data = json.load(f)
            
            if config_name not in data['Access']:
                available = ', '.join(data['Access'].keys())
                raise ValueError(f"Config '{config_name}' ikke fundet. Tilgængelige: {available}")
            
            config = data['Access'][config_name]
            return config
            
        except Exception as e:
            QgsMessageLog.logMessage(f"Fejl ved læsning af config: {e}", "OIDC", level=Qgis.Critical)
            raise

    def _start_listener(self):
        """Start lokal HTTP server til at modtage callback"""
        self.listener = RedirectListener(self)
        port = self.config['port']
        success = self.listener.listen(port=port)
        
        if not success:
            QgsMessageLog.logMessage(f"FEJL: Kunne ikke lytte på port {port}", "OIDC", level=Qgis.Critical)

    def login(self, callback=None):
        """Start OIDC login flow
        
        Args:
            callback: Optional function der kaldes med token_data når login er komplet
                     Signature: callback(token_data)
        """
        self.token_callback = callback
        QgsMessageLog.logMessage(f"Starter OIDC login for {self.config['Name']}", "OIDC")
        
        # Start listener
        self._start_listener()
        
        # Build authorization URL
        authority = self.config['authority']
        auth_url = f"{authority}/authorize.idp"
        
        params = {
            'response_type': 'code',
            'client_id': self.config['clientId'],
            'redirect_uri': self.config['redirectUri'],
            'scope': self.config['scope'],
            'state': self.state,
            'response_mode': 'query'
        }
        
        full_auth_url = f"{auth_url}?{urllib.parse.urlencode(params)}"
        
        # Open browser
        QDesktopServices.openUrl(QUrl(full_auth_url))
        
    def exchange_code_for_token(self, code):
        """Udveksler authorization code til access token"""
        authority = self.config['authority']
        token_url = f"{authority}/token.idp"
        
        data = {
            'grant_type': 'authorization_code',
            'code': code,
            'redirect_uri': self.config['redirectUri'],
            'client_id': self.config['clientId']
        }
        
        headers = {
            'Content-Type': 'application/x-www-form-urlencoded',
            'Accept': 'application/json'
        }
        
        try:
            response = requests.post(token_url, data=data, headers=headers, timeout=10)
            response.raise_for_status()
            
            # Tjek om responset er JSON
            content_type = response.headers.get('Content-Type', '')
            if 'application/json' not in content_type:
                error_msg = f"Server returnerede ikke JSON (Content-Type: {content_type})"
                QgsMessageLog.logMessage(error_msg, "OIDC", level=Qgis.Critical)
                return None
            
            token_data = response.json()
            self.access_token = token_data.get('access_token')
            self.refresh_token = token_data.get('refresh_token')
            
            QgsMessageLog.logMessage(f"Login OK - token modtaget for {self.config['Name']}", "OIDC", level=Qgis.Success)
            
            # Kald callback hvis den er sat
            if self.token_callback:
                self.token_callback(token_data)
            
            return token_data
            
        except requests.exceptions.HTTPError as e:
            error_msg = f"HTTP fejl {response.status_code}"
            QgsMessageLog.logMessage(error_msg, "OIDC", level=Qgis.Critical)
            return None
            
        except Exception as e:
            QgsMessageLog.logMessage(f"Fejl ved token udveksling: {e}", "OIDC", level=Qgis.Critical)
            return None

    def get_access_token(self):
        """Returner det aktuelle access token"""
        return self.access_token

    def refresh_token(self, refresh_token=None):
        """Refresh access token ved hjælp af refresh token
        
        Args:
            refresh_token: Optional refresh token. Hvis ikke angivet, bruges den gemte.
        
        Returns:
            token_data dict hvis success, None hvis fejl
        """
        # Brug enten parameter eller gemt refresh token
        token_to_use = refresh_token or self.refresh_token
        
        if not token_to_use:
            QgsMessageLog.logMessage("Ingen refresh token tilgængelig", "OIDC", level=Qgis.Warning)
            return None
        
        authority = self.config['authority']
        token_url = f"{authority}/token.idp"
        
        data = {
            'grant_type': 'refresh_token',
            'refresh_token': token_to_use,
            'client_id': self.config['clientId']
        }
        
        headers = {
            'Content-Type': 'application/x-www-form-urlencoded',
            'Accept': 'application/json'
        }
        
        try:
            response = requests.post(token_url, data=data, headers=headers, timeout=10)
            response.raise_for_status()
            
            # Tjek om responset er JSON
            content_type = response.headers.get('Content-Type', '')
            if 'application/json' not in content_type:
                error_msg = f"Server returnerede ikke JSON (Content-Type: {content_type})"
                QgsMessageLog.logMessage(error_msg, "OIDC", level=Qgis.Critical)
                return None
            
            token_data = response.json()
            
            # Opdater tokens (serveren sender ofte ny refresh token også)
            self.access_token = token_data.get('access_token')
            if 'refresh_token' in token_data:
                self.refresh_token = token_data.get('refresh_token')
            
            QgsMessageLog.logMessage(f"Token refreshed for {self.config['Name']}", "OIDC", level=Qgis.Success)
            
            # Kald callback hvis den er sat
            if self.token_callback:
                self.token_callback(token_data)
            
            return token_data
            
        except requests.exceptions.HTTPError as e:
            error_msg = f"HTTP fejl ved refresh: {response.status_code}"
            QgsMessageLog.logMessage(error_msg, "OIDC", level=Qgis.Critical)
            return None
            
        except Exception as e:
            QgsMessageLog.logMessage(f"Fejl ved token refresh: {e}", "OIDC", level=Qgis.Critical)
            return None


# ==================== USAGE EXAMPLES ====================

# Luk gammel listener hvis den eksisterer
try:
    if 'client' in globals() and hasattr(client, 'listener'):
        client.listener.close()
except:
    pass

# Start login (browser åbnes)
client = OidcClient("mp_demo")
client.login()

# Efter du har logget ind i browseren, kan du hente tokenet:
# token = client.get_access_token()

# Når tokenet udløber, refresh det:
# client.refresh_token()
# new_token = client.get_access_token()

# For at bruge PRODUKTION i stedet:
# client = OidcClient("mp_produktion")
# client.login()

