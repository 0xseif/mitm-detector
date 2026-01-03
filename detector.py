"""
Système de détection d'attaques Man-in-the-Middle (MITM)
"""

import hashlib
import hmac
import time
from typing import Dict, Set, Tuple
from message import Message
from utils import ThreatLevel, DetectionAlert


class MITMDetector:
    """
    Système de détection d'attaques MITM
    Analyse les incohérences et anomalies dans les échanges TCP
    """
    
    def __init__(self, connection_id: str, shared_secret: str = "secure_key"):
        """
        Initialise le détecteur MITM
        
        Args:
            connection_id: Identifiant unique de la connexion
            shared_secret: Clé secrète partagée pour HMAC
        """
        self.connection_id = connection_id
        self.shared_secret = shared_secret
        
        # Suivi des messages
        self.expected_sequence = 0
        self.received_messages: Dict[int, Message] = {}
        self.message_hashes: Set[str] = set()
        
        # Détection d'anomalies
        self.alerts: list[DetectionAlert] = []
        self.time_anomalies: Dict[int, float] = {}
        self.sequence_gaps: list[Tuple[int, int]] = []
        self.duplicate_count = 0
        self.modified_count = 0
        self.replay_count = 0
        
        # Seuils de détection
        self.max_time_delta = 10.0  # Délai maximum accepté entre messages (secondes)
        self.time_anomaly_threshold = 0.1  # Anomalie si écart > 0.1s
        
        print(f"[DÉTECTEUR MITM] Connexion {connection_id} initialisée")
    
    def calculate_checksum(self, message_data: str) -> str:
        """Calcule un HMAC-SHA256 pour vérifier l'intégrité"""
        return hmac.new(
            self.shared_secret.encode(),
            message_data.encode(),
            hashlib.sha256
        ).hexdigest()
    
    def create_message(self, content: str) -> Message:
        """Crée un message avec numéro de séquence et checksum"""
        msg = Message(
            sequence_num=self.expected_sequence,
            timestamp=time.time(),
            content=content,
            checksum=""
        )
        msg.checksum = self.calculate_checksum(f"{msg.sequence_num}{msg.timestamp}{content}")
        self.expected_sequence += 1
        return msg
    
    def detect_message_modification(self, msg: Message) -> bool:
        """
        Détecte si un message a été modifié
        
        Returns:
            True si modification détectée
        """
        expected_checksum = self.calculate_checksum(
            f"{msg.sequence_num}{msg.timestamp}{msg.content}"
        )
        
        if msg.checksum != expected_checksum:
            alert = DetectionAlert(
                threat_level=ThreatLevel.HIGH,
                alert_type="MESSAGE MODIFIÉ",
                description=f"Message #{msg.sequence_num} altéré - Checksum invalide",
                timestamp=time.time()
            )
            self.alerts.append(alert)
            self.modified_count += 1
            print(f"⚠️  {alert}")
            return True
        
        return False
    
    def detect_replay_attack(self, msg: Message) -> bool:
        """
        Détecte les attaques par rejeu (replay)
        
        Returns:
            True si rejeu/duplication détecté
        """
        msg_hash = hashlib.sha256(
            f"{msg.sequence_num}{msg.timestamp}{msg.content}".encode()
        ).hexdigest()
        
        if msg_hash in self.message_hashes:
            alert = DetectionAlert(
                threat_level=ThreatLevel.CRITICAL,
                alert_type="REJEU DE MESSAGE (REPLAY)",
                description=f"Message #{msg.sequence_num} dupliqué détecté",
                timestamp=time.time()
            )
            self.alerts.append(alert)
            self.replay_count += 1
            print(f"⚠️  {alert}")
            return True
        
        self.message_hashes.add(msg_hash)
        return False
    
    def detect_sequence_anomaly(self, msg: Message) -> bool:
        """
        Détecte les incohérences dans l'ordre des messages
        
        Returns:
            True si anomalie de séquence détectée
        """
        # Vérifier si le numéro de séquence correspond
        if msg.sequence_num != self.expected_sequence:
            if msg.sequence_num in self.received_messages:
                # Doublon exact
                self.duplicate_count += 1
                alert = DetectionAlert(
                    threat_level=ThreatLevel.CRITICAL,
                    alert_type="DOUBLON DE MESSAGE",
                    description=f"Message #{msg.sequence_num} reçu deux fois (attendu #{self.expected_sequence})",
                    timestamp=time.time()
                )
            elif msg.sequence_num < self.expected_sequence:
                # Message hors ordre (potentiellement rejoué)
                alert = DetectionAlert(
                    threat_level=ThreatLevel.HIGH,
                    alert_type="MESSAGE HORS ORDRE",
                    description=f"Message #{msg.sequence_num} reçu après #{self.expected_sequence-1}",
                    timestamp=time.time()
                )
            else:
                # Gap dans la séquence (message manquant)
                gap = (self.expected_sequence, msg.sequence_num)
                self.sequence_gaps.append(gap)
                alert = DetectionAlert(
                    threat_level=ThreatLevel.MEDIUM,
                    alert_type="GAP DANS LA SÉQUENCE",
                    description=f"Messages manquants: {self.expected_sequence} à {msg.sequence_num-1}",
                    timestamp=time.time()
                )
            
            self.alerts.append(alert)
            print(f"⚠️  {alert}")
            return True
        
        self.expected_sequence += 1
        return False
    
    def detect_timing_anomaly(self, msg: Message) -> bool:
        """
        Détecte les anomalies temporelles
        
        Returns:
            True si anomalie temporelle détectée
        """
        current_time = time.time()
        time_diff = current_time - msg.timestamp
        
        # Vérifier si le timestamp du message est trop ancien
        if time_diff > self.max_time_delta:
            alert = DetectionAlert(
                threat_level=ThreatLevel.MEDIUM,
                alert_type="TIMESTAMP SUSPECT",
                description=f"Message #{msg.sequence_num} avec délai de {time_diff:.2f}s",
                timestamp=current_time
            )
            self.alerts.append(alert)
            self.time_anomalies[msg.sequence_num] = time_diff
            print(f"⚠️  {alert}")
            return True
        
        return False
    
    def analyze_message(self, msg: Message) -> bool:
        """
        Analyse complète d'un message pour détecter les attaques MITM
        
        Returns:
            True si une menace est détectée
        """
        threats_detected = False
        
        # 1. Vérifier l'intégrité du message
        if self.detect_message_modification(msg):
            threats_detected = True
        
        # 2. Détecter les rejeux/doublons
        if self.detect_replay_attack(msg):
            threats_detected = True
        
        # 3. Vérifier l'ordre des messages
        if self.detect_sequence_anomaly(msg):
            threats_detected = True
        
        # 4. Analyser les anomalies temporelles
        if self.detect_timing_anomaly(msg):
            threats_detected = True
        
        # Enregistrer le message analysé
        self.received_messages[msg.sequence_num] = msg
        
        return threats_detected
    
    def get_threat_assessment(self) -> Dict:
        """Évalue le niveau de menace global"""
        if not self.alerts:
            threat_level = ThreatLevel.NONE
        elif self.critical_threats() > 0:
            threat_level = ThreatLevel.CRITICAL
        elif self.high_threats() > 0:
            threat_level = ThreatLevel.HIGH
        elif self.medium_threats() > 0:
            threat_level = ThreatLevel.MEDIUM
        else:
            threat_level = ThreatLevel.LOW
        
        return {
            "connexion_id": self.connection_id,
            "niveau_menace": threat_level.value,
            "alertes_totales": len(self.alerts),
            "messages_modifiés": self.modified_count,
            "rejeux_détectés": self.replay_count,
            "doublons": self.duplicate_count,
            "anomalies_temporelles": len(self.time_anomalies),
            "gaps_séquence": len(self.sequence_gaps),
            "communication_sûre": threat_level == ThreatLevel.NONE
        }
    
    def critical_threats(self) -> int:
        return sum(1 for a in self.alerts if a.threat_level == ThreatLevel.CRITICAL)
    
    def high_threats(self) -> int:
        return sum(1 for a in self.alerts if a.threat_level == ThreatLevel.HIGH)
    
    def medium_threats(self) -> int:
        return sum(1 for a in self.alerts if a.threat_level == ThreatLevel.MEDIUM)
    
    def print_report(self):
        """Affiche un rapport détaillé"""
        assessment = self.get_threat_assessment()
        print("\n" + "="*60)
        print("RAPPORT DE DÉTECTION MITM")
        print("="*60)
        print(f"Connexion: {assessment['connexion_id']}")
        print(f"Niveau de menace: {assessment['niveau_menace']}")
        print(f"Communication sûre: {'✓ OUI' if assessment['communication_sûre'] else '✗ NON'}")
        print(f"\nStatistiques:")
        print(f"  - Alertes totales: {assessment['alertes_totales']}")
        print(f"  - Messages modifiés: {assessment['messages_modifiés']}")
        print(f"  - Rejeux (replay): {assessment['rejeux_détectés']}")
        print(f"  - Doublons: {assessment['doublons']}")
        print(f"  - Anomalies temporelles: {assessment['anomalies_temporelles']}")
        print(f"  - Gaps de séquence: {len(self.sequence_gaps)}")
        
        if self.alerts:
            print(f"\nAlertes détaillées:")
            for alert in self.alerts:
                print(f"  {alert}")
        
        print("="*60 + "\n")
