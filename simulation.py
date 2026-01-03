"""
Module de simulation d'attaques MITM pour démonstration
"""

import time
from detector import MITMDetector


def simulate_mitm_attack(detector: MITMDetector):
    """
    Simule des attaques MITM pour démontrer les capacités de détection
    """
    print("\n" + "="*60)
    print("SIMULATION D'ATTAQUES MITM")
    print("="*60 + "\n")
    
    # 1. Message normal
    msg1 = detector.create_message("Message normal")
    print(f"✓ Message normal créé: {msg1.content}")
    detector.analyze_message(msg1)
    
    # 2. Message modifié
    msg2 = detector.create_message("Message 2")
    msg2.content = "CONTENU MODIFIÉ"  # Modification du contenu
    print(f"\n✗ Tentative de modification: {msg2.content}")
    detector.analyze_message(msg2)
    
    # 3. Rejeu de message (replay attack)
    print(f"\n✗ Tentative de rejeu du message 1")
    detector.analyze_message(msg1)  # Renvoyer le même message
    
    # 4. Message hors ordre
    msg3 = detector.create_message("Message 3")
    msg4 = detector.create_message("Message 4")
    print(f"\n✗ Envoi hors ordre: Message 4 avant Message 3")
    detector.analyze_message(msg4)
    detector.analyze_message(msg3)
    
    # 5. Message avec timestamp suspect
    msg5 = detector.create_message("Message ancien")
    msg5.timestamp = time.time() - 20  # Timestamp très ancien
    print(f"\n✗ Tentative avec timestamp suspect (20s d'écart)")
    detector.analyze_message(msg5)
    
    detector.print_report()
