"""
Serveur TCP sécurisé avec détection MITM
"""

import socket
import json
from typing import Optional
from message import Message
from detector import MITMDetector


class SecureServer:
    """Serveur TCP avec détection MITM"""
    
    def __init__(self, host: str = 'localhost', port: int = 5555):
        self.host = host
        self.port = port
        self.detector: Optional[MITMDetector] = None
        self.running = False
    
    def start(self):
        """Démarre le serveur"""
        server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server_socket.bind((self.host, self.port))
        server_socket.listen(1)
        
        print(f"\n[SERVEUR] En écoute sur {self.host}:{self.port}")
        print("[SERVEUR] En attente de connexion...\n")
        
        try:
            client_socket, client_addr = server_socket.accept()
            print(f"[SERVEUR] Client connecté: {client_addr}")
            
            self.detector = MITMDetector(f"SERVER-{client_addr[0]}:{client_addr[1]}")
            self.handle_client(client_socket)
            
        except KeyboardInterrupt:
            print("\n[SERVEUR] Arrêt")
        finally:
            server_socket.close()
            if self.detector:
                self.detector.print_report()
    
    def handle_client(self, client_socket):
        """Gère la communication avec le client"""
        try:
            while True:
                # Recevoir un message du client
                data = client_socket.recv(1024).decode()
                if not data:
                    break
                
                try:
                    msg = Message.from_json(data)
                    print(f"[SERVEUR] Message reçu: #{msg.sequence_num}")
                    
                    # Analyser pour détecter les attaques MITM
                    self.detector.analyze_message(msg)
                    
                    # Envoyer une réponse
                    response = self.detector.create_message(f"ACK-{msg.sequence_num}")
                    client_socket.send(response.to_json().encode())
                    
                except json.JSONDecodeError:
                    print("[SERVEUR] Erreur décodage message")
        
        except Exception as e:
            print(f"[SERVEUR] Erreur: {e}")
        finally:
            client_socket.close()

