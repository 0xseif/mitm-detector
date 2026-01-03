"""
Structure de message sécurisé pour les communications TCP
"""

import json
from dataclasses import dataclass, asdict


@dataclass
class Message:
    """Représentation d'un message TCP sécurisé"""
    sequence_num: int
    timestamp: float
    content: str
    checksum: str
    
    def to_json(self) -> str:
        return json.dumps(asdict(self))
    
    @staticmethod
    def from_json(data: str) -> 'Message':
        obj = json.loads(data)
        return Message(**obj)
