#!/usr/bin/env python3
"""
Système de Détection d'Attaque Man-in-the-Middle (MITM)
Point d'entrée principal - Détection automatique des tentatives d'interception, 
modification, ou rejeu de messages
"""

import sys
from server import SecureServer
from client import SecureClient
from detector import MITMDetector
from simulation import simulate_mitm_attack


def main():
    """Fonction principale"""
    print("\n" + "="*60)
    print("SYSTÈME DE DÉTECTION D'ATTAQUE MAN-IN-THE-MIDDLE")
    print("="*60)
    
    if len(sys.argv) > 1 and sys.argv[1] == 'server':
        server = SecureServer()
        server.start()
    elif len(sys.argv) > 1 and sys.argv[1] == 'client':
        client = SecureClient(num_messages=5)
        client.connect_and_communicate()
    else:
        # Mode simulation
        print("\nModes d'utilisation:")
        print("  python main.py server  - Démarre le serveur")
        print("  python main.py client  - Démarre le client")
        print("  (pas d'argument)       - Lance la simulation d'attaques\n")
        
        detector = MITMDetector("SIMULATION")
        simulate_mitm_attack(detector)


if __name__ == "__main__":
    main()
