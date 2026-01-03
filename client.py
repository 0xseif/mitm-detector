"""
Client TCP sécurisé avec détection MITM
"""

import socket
import time
from typing import Optional
from message import Message
from detector import MITMDetector


class SecureClient:
    """Client TCP avec détection MITM"""
    
    def __init__(self, host: str = 'localhost', port: int = 5555, num_messages: int = 5):
        self.host = host
        self.port = port
        self.num_messages = num_messages
        self.detector: Optional[MITMDetector] = None
    
    def connect_and_communicate(self):
        """Se connecte au serveur et envoie des messages"""
        try:
            client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            client_socket.connect((self.host, self.port))
            
            print(f"\n[CLIENT] Connecté à {self.host}:{self.port}\n")
            
            self.detector = MITMDetector(f"CLIENT-{self.host}:{self.port}")
            
            # Envoyer des messages
            for i in range(self.num_messages):
                msg = self.detector.create_message(f"Message {i+1} du client")
                client_socket.send(msg.to_json().encode())
                print(f"[CLIENT] Message envoyé: #{msg.sequence_num} - {msg.content}")
                
                # Recevoir la réponse
                response_data = client_socket.recv(1024).decode()
                response = Message.from_json(response_data)
                print(f"[CLIENT] Réponse reçue: #{response.sequence_num}")
                
                # Analyser la réponse pour détecter les attaques MITM
                self.detector.analyze_message(response)
                
                time.sleep(0.5)
            
            client_socket.close()
            self.detector.print_report()
        
        except Exception as e:
            print(f"[CLIENT] Erreur: {e}")

