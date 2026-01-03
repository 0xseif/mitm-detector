# Système de Détection d'Attaque Man-in-the-Middle (MITM)

## 📋 Vue d'ensemble

Ce projet est un **système de détection automatique des attaques MITM** pour les communications TCP. Il identifie les tentatives d'interception, de modification ou de rejeu de messages entre un client et un serveur.

**Objectif pédagogique:** Démontrer qu'une communication TCP peut fonctionner tout en étant compromise par une attaque MITM, et montrer comment détecter ces menaces.

---

## 🎯 Fonctionnalités principales

### 1. **Vérification d'intégrité des messages**
- Utilise **HMAC-SHA256** pour créer une signature unique pour chaque message
- Détecte si un message a été modifié entre l'envoi et la réception
- **Menace détectée:** Message modifié

### 2. **Détection des rejeux (Replay Attack)**
- Crée un hash unique pour chaque message
- Refuse les messages dupliqués ou renvoyés
- **Menace détectée:** Message rejoué/dupliqué

### 3. **Vérification de la séquence**
- Assigne un numéro séquentiel à chaque message
- Détecte les messages hors ordre, les gaps ou les doublons
- **Menace détectée:** Messages reçus dans le désordre

### 4. **Analyse temporelle**
- Vérifie que les timestamps des messages sont valides
- Détecte les messages avec des timestamps trop anciens (> 10 secondes)
- **Menace détectée:** Timestamp suspect

### 5. **Rapport de sécurité**
- Génère un rapport complet avec le niveau de menace
- Classifie les alertes par gravité: CRITIQUE, ÉLEVÉE, MOYENNE, BASSE
- Fournit des statistiques détaillées

---

## 📁 Structure du projet

```
mitm-detect/
├── main.py              # Point d'entrée (orchestration)
├── message.py           # Structure des messages
├── utils.py             # Enums et alertes
├── detector.py          # Cœur du système de détection
├── server.py            # Serveur TCP
├── client.py            # Client TCP
├── simulation.py        # Simulation d'attaques
└── requirements.txt     # Dépendances (aucune!)
```

---

## 📚 Architecture détaillée

### **message.py** - Structure du message
```python
@dataclass
class Message:
    sequence_num: int      # Numéro d'ordre
    timestamp: float       # Heure d'envoi
    content: str          # Contenu du message
    checksum: str         # HMAC-SHA256 pour intégrité
```

Chaque message contient les informations nécessaires pour la détection d'attaques.

### **detector.py** - MITMDetector (cœur du système)

La classe `MITMDetector` implémente 4 niveaux de détection:

```python
class MITMDetector:
    # Initialisation
    def __init__(self, connection_id, shared_secret)
    
    # Création de messages sécurisés
    def create_message(content) -> Message
    def calculate_checksum(data) -> str
    
    # Détection des menaces
    def detect_message_modification(msg) -> bool
    def detect_replay_attack(msg) -> bool
    def detect_sequence_anomaly(msg) -> bool
    def detect_timing_anomaly(msg) -> bool
    
    # Analyse complète
    def analyze_message(msg) -> bool
    
    # Rapport
    def get_threat_assessment() -> Dict
    def print_report()
```

### **server.py** - SecureServer

```python
class SecureServer:
    def start()              # Démarre le serveur sur localhost:5555
    def handle_client()      # Gère la communication
```

- Écoute les connexions entrantes
- Reçoit les messages du client
- Les analyse avec MITMDetector
- Envoie des réponses

### **client.py** - SecureClient

```python
class SecureClient:
    def connect_and_communicate()
```

- Se connecte au serveur
- Envoie des messages sécurisés
- Reçoit et analyse les réponses
- Génère un rapport

---

## 🚀 Comment utiliser

### **Mode 1: Simulation (Démo automatique)**
```bash
python main.py
```
Lance une simulation d'attaques MITM avec:
- ✅ Message normal
- ❌ Message modifié
- ❌ Rejeu de message
- ❌ Message hors ordre
- ❌ Timestamp suspect

**Résultat:** Rapport de détection complet

---

### **Mode 2: Client-Serveur (Communication réelle)**

**Terminal 1 - Démarrer le serveur:**
```bash
python main.py server
```

**Terminal 2 - Démarrer le client:**
```bash
python main.py client
```

Le client envoie 5 messages au serveur. Les deux analysent les échanges et génèrent des rapports.

---

## 🔍 Exemple de résultat

### Simulation avec attaques détectées:
```
============================================================
RAPPORT DE DÉTECTION MITM
============================================================
Connexion: SIMULATION
Niveau de menace: CRITIQUE
Communication sûre: ✗ NON

Statistiques:
  - Alertes totales: 10
  - Messages modifiés: 2
  - Rejeux (replay): 1
  - Doublons: 1
  - Anomalies temporelles: 1
  - Gaps de séquence: 0

Alertes détaillées:
  [ÉLEVÉE] MESSAGE MODIFIÉ: Message #1 altéré
  [CRITIQUE] REJEU DE MESSAGE: Message #0 dupliqué
  [CRITIQUE] DOUBLON DE MESSAGE: Message #0 reçu deux fois
  ...
```

---

## 🛡️ Niveaux de menace

| Niveau | Signification | Exemple |
|--------|---------------|---------|
| **CRITIQUE** | Menace sévère | Message rejoué, doublon |
| **ÉLEVÉE** | Problème significatif | Message modifié, hors ordre |
| **MOYENNE** | Anomalie suspecte | Gap de séquence, timestamp ancien |
| **BASSE** | Avertissement mineur | Autre anomalie |
| **AUCUNE** | Aucun problème | Communication normale |

---

## 💡 Concepts clés expliqués

### **1. HMAC-SHA256**
- Crée une signature cryptographique basée sur:
  - Le contenu du message
  - Le numéro de séquence
  - Le timestamp
- Si quelqu'un modifie le message, le HMAC ne correspond plus

### **2. Numéro de séquence**
- Chaque message reçoit un numéro d'ordre (0, 1, 2, ...)
- Un message hors ordre ou dupliqué sera détecté
- Prévient les attaques par rejeu

### **3. Hash des messages**
- Garde une liste de tous les messages reçus (par hash)
- Empêche les doublons absolus
- Détecte les rejeux

### **4. Timestamp**
- Chaque message inclut l'heure d'envoi
- Un timestamp trop ancien = message suspecté d'être vieux
- Limite maximale: 10 secondes

---

## ⚙️ Configuration modifiable

Dans `detector.py`, vous pouvez ajuster:

```python
self.max_time_delta = 10.0           # Délai max entre messages (secondes)
self.time_anomaly_threshold = 0.1    # Seuil d'anomalie (secondes)
```

---

## 📦 Dépendances

**Aucune!** Le projet utilise uniquement la **stdlib Python**:
- `socket` - Communication TCP
- `hashlib` - Hachage SHA256
- `hmac` - Authentification des messages
- `json` - Sérialisation
- `time` - Timestamping
- `dataclasses` - Structures de données
- `enum` - Énumérations

**Requis:** Python 3.7+

---

## 🎓 Cas d'usage

### Cas 1: Communication sans attaque
```
Client envoie: "Bonjour" (seq#0, checksum OK)
Serveur reçoit: Valide ✓
→ Niveau de menace: AUCUNE
```

### Cas 2: Message modifié par attaquant
```
Client envoie: "Envoyer 100€" (checksum: ABC123)
Attaquant modifie: "Envoyer 1000€" (checksum: ABC123 - invalide!)
Serveur reçoit: Checksum ne correspond pas ✗
→ Menace détectée: MESSAGE MODIFIÉ (niveau ÉLEVÉE)
```

### Cas 3: Rejeu de message
```
Client envoie: "Paiement 50€" (seq#2, hash: XYZ789)
Attaquant renvoie le même message
Serveur reçoit: Hash déjà vu! ✗
→ Menace détectée: REJEU (niveau CRITIQUE)
```

---

## 🔐 Limitations et considérations

✅ **Ce système détecte:**
- Les modifications de contenu
- Les doublons et rejeux
- Les anomalies de séquence
- Les timestamps suspects

❌ **Ce système NE peut pas:**
- Bloquer les attaques (only detection)
- Empêcher l'interception initiale
- Gérer le chiffrement (TCP brut)
- Garantir l'authentification du serveur

**Note:** Pour une vraie sécurité, utiliser TLS/SSL et des certificats!

---

## 📝 Points clés à retenir

1. **MITM existe même si la communication fonctionne** - TCP ne garantit pas la sécurité
2. **La détection est basée sur l'analyse comportementale** - On cherche des incohérences
3. **Les signatures (HMAC) empêchent la modification cachée** - Mais pas l'interception
4. **La séquence prévient les attaques sophistiquées** - Comme le rejeu sélectif
5. **La surveillance continue est essentielle** - Tous les messages sont analysés

---

## 🚀 Extensibilité future

Améliorations possibles:
- ✓ Chiffrement des messages (AES)
- ✓ Authentification mutuelle (client ↔ serveur)
- ✓ Signature numérique (RSA/ECDSA)
- ✓ Journal persistant des alertes
- ✓ Blocage automatique des connexions suspectes
- ✓ Machine Learning pour détecter les patterns anormaux

---

**Créé:** Janvier 2026  
**Objectif:** Éducatif - Démonstration de détection d'attaques MITM  
# mitm-detector
