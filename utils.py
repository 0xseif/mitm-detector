"""
Utilitaires et énumérations pour le système de détection MITM
"""

from enum import Enum
from dataclasses import dataclass
import time


class ThreatLevel(Enum):
    """Niveaux de menace détectés"""
    NONE = "AUCUNE"
    LOW = "BASSE"
    MEDIUM = "MOYENNE"
    HIGH = "ÉLEVÉE"
    CRITICAL = "CRITIQUE"


@dataclass
class DetectionAlert:
    """Alerte de sécurité détectée"""
    threat_level: ThreatLevel
    alert_type: str
    description: str
    timestamp: float
    
    def __str__(self) -> str:
        return (f"[{self.threat_level.value}] {self.alert_type}: {self.description} "
                f"({time.ctime(self.timestamp)})")
