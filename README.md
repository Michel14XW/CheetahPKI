# CheetahPKI


**Version**: 0.0.12  
**Description**: Package pour la génération de paires de clés et de certificats numériques.  

CheetahPKI est un package Python permettant de générer des paires de clés (RSA, ECDSA, Ed25519, Ed448), de créer des certificats auto-signés, des certificats signés par une autorité de certification (CA), et de récupérer des informations sur les certificats.

## Fonctionnalités

- **Génération de paires de clés** : RSA 2048/4096, ECDSA P-256/P-384/P-521, Ed25519, Ed448.
- **Création de certificats auto-signés** : Génère des certificats pour des autorités racine.
- **Création de certificats signés** : Permet de signer un certificat utilisateur via une clé privée CA.
- **Création de certificats CA intermédiaires** : Signe un certificat CA intermédiaire via une CA root.
- **Génération et parsing de CSR** : Crée et analyse des Certificate Signing Requests.
- **Vérification de validité** : Vérifie la date d'expiration d'un certificat.
- **Extraction d'informations sur les certificats** : Propriétaire, numéro de série, dates de validité.
- **Empreinte cryptographique** : Calcule l'empreinte SHA256 d'une clé publique ou d'un certificat.

## Installation

```bash
pip install git+https://github.com/Michel14XW/cheetahpki.git
```

## Arborescence du projet

```
cheetahpki/
├── generateKeyPair.py          # Génération de paires de clés (RSA, EC, Ed25519, Ed448)
├── createSelfSignedRootCert.py # Certificat auto-signé pour CA root
├── createSignedCert.py         # Certificat utilisateur signé par CA intermédiaire
├── createSignedInterCert.py    # Certificat CA intermédiaire signé par CA root
├── checkCertValidity.py        # Vérification date d'expiration
├── fingerprint.py              # Empreinte SHA256 clé/certificat
├── generateCsr.py              # Génération de CSR
├── parseCsr.py                 # Parsing de CSR
├── exceptions.py               # Exceptions personnalisées
└── getCertInfo.py              # Extraction d'infos certificat
```

## Algorithmes supportés

| Algorithme | Paramètre | Statut |
|-----------|-----------|--------|
| RSA | `key_size=2048` ou `4096` | ✅ |
| ECDSA | `curve="P-256"` (secp256r1) | ✅ |
| ECDSA | `curve="P-384"` (secp384r1) | ✅ |
| ECDSA | `curve="P-521"` (secp521r1) | ✅ |
| Ed25519 | — | ✅ |
| Ed448 | — | ✅ |

## Utilisation

### 1. Génération d'une paire de clés

Fichier : `generateKeyPair.py` — Fonction : `generateKeyPair`

```python
from cheetahpki.generateKeyPair import generateKeyPair

# RSA 4096 (défaut — rétrocompatible)
priv, pub = generateKeyPair(uid="alice")

# RSA 2048
priv, pub = generateKeyPair(uid="alice", key_size=2048)

# ECDSA P-256 (recommandé pour TLS)
priv, pub = generateKeyPair(uid="bob", algorithm="EC", curve="P-256")

# ECDSA P-384 (haute sécurité)
priv, pub = generateKeyPair(uid="carol", algorithm="EC", curve="P-384")

# ECDSA P-521 (ultra-sécurité)
priv, pub = generateKeyPair(uid="dave", algorithm="EC", curve="P-521")

# Ed25519 (performance, SSH)
priv, pub = generateKeyPair(uid="eve", algorithm="Ed25519")

# Ed448 (future-proof)
priv, pub = generateKeyPair(uid="frank", algorithm="Ed448")

# Avec mot de passe sur la clé privée
priv, pub = generateKeyPair(uid="alice", algorithm="EC", curve="P-256",
                            private_key_password="s3cr3t")
```

**Paramètres :**

| Paramètre | Type | Défaut | Description |
|-----------|------|--------|-------------|
| `uid` | str | — | Identifiant du propriétaire (préfixe des fichiers) |
| `key_size` | int | 4096 | Taille RSA en bits (ignoré pour EC/Ed25519/Ed448) |
| `key_directory` | str | `"tmp/keys"` | Dossier de destination |
| `private_key_password` | str | None | Mot de passe de chiffrement de la clé privée |
| `algorithm` | str | `"RSA"` | `"RSA"`, `"EC"`, `"Ed25519"`, `"Ed448"` |
| `curve` | str | `"P-256"` | `"P-256"`, `"P-384"`, `"P-521"` (EC uniquement) |

**Retourne :** `(private_key_filename, public_key_filename)`

---

### 2. Création d'un certificat auto-signé (CA Root)

Fichier : `createSelfSignedRootCert.py` — Fonction : `createSelfSignedRootCert`

```python
from cheetahpki.createSelfSignedRootCert import createSelfSignedRootCert

cert_path = createSelfSignedRootCert(
    pseudo="RootCA",
    company="MyCompany",
    city="Lomé",
    region="Maritime",
    country_code="TG",
    email="caroot@mycompany.tg",
    valid_days=3650,
    private_key_path="tmp/keys/ca_root_private_key.pem",
    output_folder="tmp/certificate/root"
)
```

---

### 3. Création d'un certificat CA intermédiaire

Fichier : `createSignedInterCert.py` — Fonction : `createSignedInterCert`

```python
from cheetahpki.createSignedInterCert import createSignedInterCert

cert_path = createSignedInterCert(
    public_key_path="tmp/keys/ca_inter_public_key.pem",
    pseudo="CA_inter",
    company="MyCompany",
    department="IT",
    city="Lomé",
    region="Maritime",
    country_code="TG",
    email="cainter@mycompany.tg",
    valid_days=1825,
    ca_private_key_path="tmp/keys/root/ca_root_private_key.pem",
    ca_cert_path="tmp/certificate/root/root_ca_certificate.pem",
    output_folder="tmp/certificate/inter",
    output_filename="ca_inter"
)
```

---

### 4. Création d'un certificat utilisateur signé par la CA intermédiaire

Fichier : `createSignedCert.py` — Fonction : `createSignedCert`

```python
from cheetahpki.createSignedCert import createSignedCert

cert_path = createSignedCert(
    public_key_path="tmp/keys/user_public_key.pem",
    pseudo="user123",
    company="MyCompany",
    department="IT",
    city="Lomé",
    region="Maritime",
    country_code="TG",
    email="user@mycompany.tg",
    valid_days=365,
    ca_private_key_path="tmp/keys/ca_inter_private_key.pem",
    ca_cert_path="tmp/certificate/inter/ca_inter.pem",
    alt_names=["user.mycompany.tg"],
    ip_addresses=["192.168.1.10"],
    output_folder="tmp/certificate/users"
)
```

---

### 5. Vérification de la validité d'un certificat

```python
from cheetahpki.checkCertValidity import checkCertValidity

days_remaining = checkCertValidity(cert_file="path/to/cert.pem")
# Retourne le nombre de jours restants, ou None si expiré
```

---

### 6. Extraction d'informations sur le certificat

```python
from cheetahpki.getCertInfo import get_owner, get_serial_number, get_validity_start, get_validity_end

owner        = get_owner(cert_pem_path="path/to/cert.pem")
serial       = get_serial_number(cert_pem_path="path/to/cert.pem")
start_date   = get_validity_start(cert_pem_path="path/to/cert.pem")
end_date     = get_validity_end(cert_pem_path="path/to/cert.pem")
```

---

### 7. Empreinte cryptographique (SHA256)

```python
from cheetahpki.fingerprint import getCertificateFingerprint, getPublicKeyFingerprint

cert_fp = getCertificateFingerprint(cert_path="path/to/cert.pem")
key_fp  = getPublicKeyFingerprint(key_path="path/to/public_key.pem")
```

---

### 8. Génération d'un CSR

```python
from cheetahpki.generateCsr import generateCsr

csr_pem = generateCsr(
    private_key=private_key,       # objet clé privée cryptography
    country="TG",
    state="Maritime",
    city="Lomé",
    org="MyCompany",
    common_name="www.mycompany.tg",
    alt_names=["mycompany.tg", "lab.mycompany.local"],
    ip_addresses=["192.168.1.1"]
)

with open("csr.pem", "wb") as f:
    f.write(csr_pem)
```

---

### 9. Parsing d'un CSR

```python
from cheetahpki.parseCsr import parseCsr

csr_info = parseCsr("path/to/csr.pem")
print(csr_info)
```

---

## Exceptions

Toutes les exceptions héritent de `CertificateError` :

| Exception | Description |
|-----------|-------------|
| `UnsupportedAlgorithmError` | Algorithme ou courbe non supporté(e) |
| `InvalidKeySizeError` | Taille de clé RSA invalide |
| `KeyPairGenerationError` | Échec de la génération de clé |
| `KeySaveError` | Échec de l'écriture d'un fichier de clé |
| `DirectoryCreationError` | Impossible de créer le répertoire cible |
| `PrivateKeyFileNotFoundError` | Fichier de clé privée introuvable |
| `PublicKeyFileNotFoundError` | Fichier de clé publique introuvable |
| `PrivateKeyLoadError` | Échec du chargement de la clé privée |
| `PublicKeyLoadError` | Échec du chargement de la clé publique |
| `CertificateLoadError` | Échec du chargement du certificat |
| `CertificateSaveError` | Échec de l'enregistrement du certificat |

---

## Changelog

### 0.0.12 — 2026-04-19
- `generateKeyPair()` : ajout support ECDSA P-256, P-384, P-521, Ed25519 et Ed448
- Nouveau paramètre `algorithm` (`"RSA"` | `"EC"` | `"Ed25519"` | `"Ed448"`)
- Nouveau paramètre `curve` (`"P-256"` | `"P-384"` | `"P-521"`)
- Nouvelle exception `UnsupportedAlgorithmError`
- Rétrocompatibilité totale avec les appels RSA existants

### 0.0.11
- Mise à jour des fonctions d'empreinte (`getCertificateFingerprint`, `getPublicKeyFingerprint`)

### 0.0.9
- Ajout génération et parsing de CSR (`generateCsr`, `parseCsr`)

---

## Licence

Ce projet est sous licence MIT.  
Développé par Michel KPEKPASSI pour la plateforme PKI **vXtend_PKI**.
