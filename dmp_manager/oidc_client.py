"""
/***************************************************************************
OIDC/OAuth2 Client for DMP Manager QGIS Plugin
Handles authentication with miljoeportalen using OAuth2 with PKCE.

        copyright            : (C) 2026 by Morten Fuglsang, Septima
        email                : morten.fuglsang@septima.dk
 ***************************************************************************/

"""

import json
import os
import hashlib
import base64
import secrets
import webbrowser
from datetime import datetime, timedelta
from urllib.parse import urlencode

import requests
from PyQt5.QtCore import QObject, pyqtSignal
from PyQt5.QtNetwork import QTcpServer, QHostAddress

from qgis.core import QgsMessageLog, Qgis


class RedirectListener(QObject):
    """Listens for OAuth redirect callback on localhost"""
    
    auth_code_received = pyqtSignal(str)  # Signal emitted with authorization code
    
    def __init__(self, port=5001):
        super().__init__()
        self.port = port
        self.server = QTcpServer()
        self.server.newConnection.connect(self.handle_connection)
        
    def start(self):
        """Start listening for connections"""
        if self.server.listen(QHostAddress.LocalHost, self.port):
            QgsMessageLog.logMessage(f"Listening on port {self.port}", "OIDC", Qgis.Info)
            return True
        else:
            QgsMessageLog.logMessage(f"Failed to start server on port {self.port}", "OIDC", Qgis.Critical)
            return False
    
    def stop(self):
        """Stop listening"""
        self.server.close()
        
    def handle_connection(self):
        """Handle incoming connection"""
        socket = self.server.nextPendingConnection()
        if socket:
            socket.readyRead.connect(lambda: self.read_request(socket))
            
    def read_request(self, socket):
        """Read the HTTP request and extract the authorization code"""
        data = socket.readAll().data().decode('utf-8')
        
        # Extract code from request
        code = None
        if 'GET /login?code=' in data:
            start = data.find('code=') + 5
            end = data.find('&', start)
            if end == -1:
                end = data.find(' ', start)
            code = data[start:end]
            
        # Send response
        if code:
            response = (
                "HTTP/1.1 200 OK\r\n"
                "Content-Type: text/html\r\n"
                "\r\n"
                "<html><body><h1>Login Success!</h1>"
                "<p>You can close this window and return to QGIS.</p>"
                "</body></html>"
            )
        else:
            response = (
                "HTTP/1.1 400 Bad Request\r\n"
                "Content-Type: text/html\r\n"
                "\r\n"
                "<html><body><h1>Login Failed</h1>"
                "<p>No authorization code received.</p>"
                "</body></html>"
            )
            
        socket.write(response.encode('utf-8'))
        socket.flush()
        socket.disconnectFromHost()
        
        if code:
            QgsMessageLog.logMessage("Authorization code received", "OIDC", Qgis.Success)
            self.auth_code_received.emit(code)
            self.stop()


class OidcClient(QObject):
    """OIDC/OAuth2 Client with PKCE support"""
    
    token_received = pyqtSignal(dict)  # Signal emitted when token is received
    
    def __init__(self, config_name="mp_demo", config_file=None):
        """
        Initialize OIDC client from configuration
        
        Args:
            config_name: Name of configuration to use (e.g., "mp_demo" or "mp_produktion")
            config_file: Path to configuration.json (defaults to configuration.json in same directory as script)
        """
        super().__init__()
        
        # Load configuration
        if config_file is None:
            config_file = os.path.join(os.path.dirname(__file__), 'configuration.json')
        
        with open(config_file, 'r', encoding='utf-8') as f:
            config = json.load(f)
        
        # Get the specific environment config
        access_config = config['Access'][config_name]
        
        self.client_id = access_config['clientId']
        self.authority = access_config['authority']
        self.redirect_uri = access_config['redirectUri']
        self.scope = access_config['scope']
        self.port = access_config.get('port', 5001)
        
        # Token storage
        self.access_token = None
        self.refresh_token_value = None
        self.token_expiry = None
        
        # PKCE values
        self.code_verifier = None
        self.code_challenge = None
        
        # Listener
        self.listener = None
        self.callback = None
        
    def _generate_pkce(self):
        """Generate PKCE code verifier and challenge"""
        # Generate code verifier (43-128 characters)
        self.code_verifier = base64.urlsafe_b64encode(secrets.token_bytes(32)).decode('utf-8').rstrip('=')
        
        # Generate code challenge (SHA256 hash of verifier)
        challenge_bytes = hashlib.sha256(self.code_verifier.encode('utf-8')).digest()
        self.code_challenge = base64.urlsafe_b64encode(challenge_bytes).decode('utf-8').rstrip('=')
        
    def login(self, callback=None):
        """
        Start the login process
        
        Args:
            callback: Optional callback function to call when token is received.
                     Callback will receive dict with 'token', 'refresh_token', 'expiry'
        """
        self.callback = callback
        
        # Generate PKCE values
        self._generate_pkce()
        
        # Start listener
        self.listener = RedirectListener(self.port)
        self.listener.auth_code_received.connect(self._on_auth_code_received)
        
        if not self.listener.start():
            QgsMessageLog.logMessage("Failed to start redirect listener", "OIDC", Qgis.Critical)
            return False
        
        # Build authorization URL
        auth_params = {
            'client_id': self.client_id,
            'redirect_uri': self.redirect_uri,
            'response_type': 'code',
            'scope': self.scope,
            'code_challenge': self.code_challenge,
            'code_challenge_method': 'S256'
        }
        
        auth_url = f"{self.authority}/authorize.idp?{urlencode(auth_params)}"
        
        QgsMessageLog.logMessage(f"Opening browser for login", "OIDC", Qgis.Info)
        webbrowser.open(auth_url)
        
        return True
        
    def _on_auth_code_received(self, code):
        """Handle authorization code from redirect"""
        QgsMessageLog.logMessage("Exchanging code for token", "OIDC", Qgis.Info)
        
        # Exchange code for token
        token_data = self.exchange_code_for_token(code)
        
        if token_data:
            self.access_token = token_data.get('access_token')
            self.refresh_token_value = token_data.get('refresh_token')
            
            # Calculate expiry time
            expires_in = token_data.get('expires_in', 3600)
            self.token_expiry = datetime.now() + timedelta(seconds=expires_in)
            
            result = {
                'token': self.access_token,
                'refresh_token': self.refresh_token_value,
                'expiry': self.token_expiry
            }
            
            QgsMessageLog.logMessage("Login successful", "OIDC", Qgis.Success)
            
            # Emit signal
            self.token_received.emit(result)
            
            # Call callback if provided
            if self.callback:
                self.callback(result)
        
    def exchange_code_for_token(self, code):
        """Exchange authorization code for access token"""
        token_url = f"{self.authority}/token.idp"
        
        token_data = {
            'grant_type': 'authorization_code',
            'code': code,
            'redirect_uri': self.redirect_uri,
            'client_id': self.client_id,
            'code_verifier': self.code_verifier
        }
        
        try:
            response = requests.post(token_url, data=token_data)
            
            if response.status_code == 200:
                return response.json()
            else:
                QgsMessageLog.logMessage(
                    f"Token exchange failed: {response.status_code}", 
                    "OIDC", 
                    Qgis.Critical
                )
                return None
                
        except Exception as e:
            QgsMessageLog.logMessage(f"Token exchange error: {str(e)}", "OIDC", Qgis.Critical)
            return None
    
    def refresh_token(self, refresh_token=None):
        """
        Refresh the access token using refresh token
        
        Args:
            refresh_token: Optional refresh token. If not provided, uses stored refresh token
            
        Returns:
            dict with 'token', 'refresh_token', 'expiry' or None on failure
        """
        token_to_use = refresh_token or self.refresh_token_value
        
        if not token_to_use:
            QgsMessageLog.logMessage("No refresh token available", "OIDC", Qgis.Warning)
            return None
        
        token_url = f"{self.authority}/token.idp"
        
        token_data = {
            'grant_type': 'refresh_token',
            'refresh_token': token_to_use,
            'client_id': self.client_id
        }
        
        try:
            response = requests.post(token_url, data=token_data)
            
            if response.status_code == 200:
                token_result = response.json()
                
                self.access_token = token_result.get('access_token')
                self.refresh_token_value = token_result.get('refresh_token', token_to_use)
                
                # Calculate expiry time
                expires_in = token_result.get('expires_in', 3600)
                self.token_expiry = datetime.now() + timedelta(seconds=expires_in)
                
                result = {
                    'token': self.access_token,
                    'refresh_token': self.refresh_token_value,
                    'expiry': self.token_expiry
                }
                
                QgsMessageLog.logMessage("Token refreshed successfully", "OIDC", Qgis.Success)
                
                return result
            else:
                QgsMessageLog.logMessage(
                    f"Token refresh failed: {response.status_code}", 
                    "OIDC", 
                    Qgis.Critical
                )
                return None
                
        except Exception as e:
            QgsMessageLog.logMessage(f"Token refresh error: {str(e)}", "OIDC", Qgis.Critical)
            return None
    
    def is_token_expired(self):
        """Check if the current token is expired"""
        if not self.token_expiry:
            return True
        return datetime.now() >= self.token_expiry
    
    def get_valid_token(self):
        """
        Get a valid access token, refreshing if necessary
        
        Returns:
            Access token string or None if unable to get valid token
        """
        if not self.access_token:
            return None
            
        if self.is_token_expired() and self.refresh_token_value:
            result = self.refresh_token()
            if result:
                return result['token']
            return None
            
        return self.access_token
