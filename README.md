# CheetahPKI

**Version** : 0.0.13
**Auteur** : Michel KPEKPASSI | [GitHub](https://github.com/Michel14XW/cheetahpki)
**Licence** : MIT | Python ≥ 3.11

CheetahPKI est une bibliothèque Python de cryptographie PKI pour générer des paires de clés, créer et signer des certificats X.509, publier des CRL, extraire les métadonnées d'un certificat, calculer des empreintes et analyser des CSR.

Conçue pour être utilisée en backend Django (projet vXtend_PKI_v2) mais utilisable dans tout projet Python.

---

## Sommaire

- [Algorithmes supportés](#algorithmes-supportés)
- [Installation](#installation)
- [Arborescence](#arborescence)
- [Utilisation](#utilisation)
  - [1. Génération d'une paire de clés](#1-génération-dune-paire-de-clés--generatekeypair)
  - [2. Certificat auto-signé (CA racine)](#2-certificat-auto-signé-ca-racine--createselfsigedrootcert)
  - [3. Certificat CA intermédiaire](#3-certificat-ca-intermédiaire--createsignedintercert)
  - [4. Certificat utilisateur](#4-certificat-utilisateur--createsignedcert)
  - [5. Vérification de validité](#5-vérification-de-validité--checkcertvalidity)
  - [6. Informations sur un certificat](#6-informations-sur-un-certificat)
  - [7. Publication de CRL](#7-publication-de-crl--generatecrl-0013)
  - [8. Empreintes (fingerprints)](#8-empreintes-fingerprints)
  - [9. Génération et analyse de CSR](#9-génération-et-analyse-de-csr)
- [Exceptions](#exceptions)
- [Changelog](#changelog)
- [Licence](#licence)

---

## Algorithmes supportés

| Algorithme | Clé | Statut |
|-----------|-----|--------|
| RSA | 2048 / 4096 bits | ✅ Stable |
| ECDSA P-256 | 256 bits | ✅ Stable |
| ECDSA P-384 | 384 bits | ✅ Stable |
| ECDSA P-521 | 521 bits | ✅ Stable |
| Ed25519 | 256 bits | ✅ Stable |
| Ed448 | 448 bits | ✅ Stable |

Constantes exportées :

```python
from cheetahpki import SUPPORTED_ALGORITHMS, SUPPORTED_CURVES, SUPPORTED_REVOCATION_REASONS

# SUPPORTED_ALGORITHMS         = ("RSA", "EC", "Ed25519", "Ed448")
# SUPPORTED_CURVES             = ("P-256", "P-384", "P-521")
# SUPPORTED_REVOCATION_REASONS = ("unspecified", "key_compromise", "ca_compromise",
#                                  "affiliation_changed", "superseded",
#                                  "cessation_of_operation", "certificate_hold",
#                                  "privilege_withdrawn", "aa_compromise",
#                                  "remove_from_crl")
```

---

## Installation

```bash
# Depuis GitHub (branche main)
pip install git+https://github.com/Michel14XW/cheetahpki.git

# Depuis une archive locale
pip install cheetahpki-0.0.13.tar.gz
```

---

## Arborescence

```
cheetahpki/
├── __init__.py                 ← exports publics + constantes SUPPORTED_*
├── generateKeyPair.py          ← RSA, ECDSA P-256/384/521, Ed25519, Ed448
├── createSelfSignedRootCert.py ← certificat CA racine auto-signé
├── createSignedCert.py         ← cert utilisateur signé par CA (+ AIA/CRL 0.0.13)
├── createSignedInterCert.py    ← cert CA intermédiaire signé par CA racine (+ AIA/CRL 0.0.13)
├── generateCsr.py              ← génération de CSR à partir d'une clé privée
├── parseCsr.py                 ← analyse d'un fichier CSR existant
├── generateCRL.py              ← CRL RFC 5280 (nouveau 0.0.13)
├── checkCertValidity.py        ← jours restants avant expiration
├── getCertInfo.py              ← helpers unitaires (CN, serial, dates)
├── getCertificateInfo.py       ← extraction consolidée (nouveau 0.0.13)
├── fingerprint.py              ← empreintes SHA-256 de certificat et de clé publique
└── exceptions.py               ← hiérarchie d'exceptions typées
```

---

## Utilisation

### 1. Génération d'une paire de clés — `generateKeyPair`

```python
from cheetahpki import generateKeyPair

# RSA 4096 (défaut — rétrocompatible avec toutes les versions précédentes)
priv, pub = generateKeyPair(uid="alice")

# RSA 2048 avec mot de passe sur la clé privée
priv, pub = generateKeyPair(uid="alice", key_size=2048,
                             private_key_password="monMotDePasse")

# ECDSA P-256
priv, pub = generateKeyPair(uid="bob", algorithm="EC", curve="P-256")

# ECDSA P-384 avec mot de passe
priv, pub = generateKeyPair(uid="carol", algorithm="EC", curve="P-384",
                             private_key_password="s3cr3t")

# ECDSA P-521
priv, pub = generateKeyPair(uid="dave", algorithm="EC", curve="P-521")

# Ed25519
priv, pub = generateKeyPair(uid="eve", algorithm="Ed25519")

# Ed448
priv, pub = generateKeyPair(uid="frank", algorithm="Ed448")
```

**Paramètres :**

| Paramètre | Type | Défaut | Description |
|-----------|------|--------|-------------|
| `uid` | str | — | Identifiant unique du propriétaire (utilisé dans le nom de fichier). |
| `key_size` | int | 4096 | Taille RSA en bits (ignoré pour EC/Ed*). |
| `key_directory` | str | `"tmp/keys"` | Répertoire de sortie. |
| `private_key_password` | str | None | Chiffrement PEM de la clé privée (optionnel). |
| `algorithm` | str | `"RSA"` | `"RSA"`, `"EC"`, `"Ed25519"`, `"Ed448"`. |
| `curve` | str | `"P-256"` | Courbe EC uniquement : `"P-256"`, `"P-384"`, `"P-521"`. |

**Retourne :** `(private_key_path: str, public_key_path: str)`

**Format des clés générées :**
- RSA → PEM `TraditionalOpenSSL` (compatibilité OpenSSL maximale).
- EC / Ed25519 / Ed448 → PEM `PKCS8` (standard NIST / RFC 5958).

> **Tip Vault** — Pour stocker la clé privée dans HashiCorp Vault, générez dans un répertoire temporaire, lisez le PEM, envoyez-le dans Vault, puis supprimez le fichier :
>
> ```python
> import tempfile
> from pathlib import Path
>
> with tempfile.TemporaryDirectory() as tmp:
>     priv_path, pub_path = generateKeyPair(uid="alice", key_directory=tmp)
>     private_pem = Path(priv_path).read_bytes()
>     # vault.store_private_key(uid="alice", pem_bytes=private_pem)
>     # Le TemporaryDirectory supprime le fichier automatiquement à la sortie
> ```

---

### 2. Certificat auto-signé (CA racine) — `createSelfSignedRootCert`

```python
from cheetahpki import createSelfSignedRootCert

cert_path = createSelfSignedRootCert(
    pseudo="RootCA",
    company="MonEntreprise",
    city="Lomé",
    region="Maritime",
    country_code="TG",
    email="ca@monentreprise.tg",
    valid_days=3650,
    private_key_path="tmp/keys/root_private_key.pem",
    key_password=None,           # optionnel
    output_folder="tmp/certs",
    output_filename="root_ca",
)
# Retourne : chemin vers le certificat PEM généré
```

---

### 3. Certificat CA intermédiaire — `createSignedInterCert`

```python
from cheetahpki import createSignedInterCert

cert_path = createSignedInterCert(
    public_key_path="tmp/keys/inter_public_key.pem",
    pseudo="CA_Inter",
    company="MonEntreprise",
    department="DSI",
    city="Lomé",
    region="Maritime",
    country_code="TG",
    email="inter@monentreprise.tg",
    valid_days=365,
    ca_private_key_path="tmp/keys/root_private_key.pem",
    ca_cert_path="tmp/certs/root_ca.pem",
    ca_key_password=None,
    alt_names=["ca-inter.monentreprise.tg"],
    ip_addresses=["192.168.1.10"],
    output_folder="tmp/certs",
    output_filename="inter_ca",
    # Extensions AIA + CRLDP (optionnelles, rétrocompatibles — nouveau 0.0.13)
    ocsp_url="http://pki.monentreprise.tg/ocsp/",
    ca_issuers_url="http://pki.monentreprise.tg/ca.pem",
    crl_url="http://pki.monentreprise.tg/crl/1/latest/",
)
```

---

### 4. Certificat utilisateur — `createSignedCert`

```python
from cheetahpki import createSignedCert

cert_path = createSignedCert(
    public_key_path="tmp/keys/user_public_key.pem",
    pseudo="alice",
    company="MonEntreprise",
    department="RH",
    city="Lomé",
    region="Maritime",
    country_code="TG",
    email="alice@monentreprise.tg",
    valid_days=60,
    ca_private_key_path="tmp/keys/inter_private_key.pem",
    ca_cert_path="tmp/certs/inter_ca.pem",
    ca_key_password=None,
    alt_names=["alice.monentreprise.tg"],
    ip_addresses=["192.168.1.50"],
    output_folder="tmp/certs",
    output_filename="alice_cert",
    # Extensions AIA + CRLDP (optionnelles — obligatoires en prod pour
    # que les clients puissent vérifier la validité en ligne)
    ocsp_url="http://pki.monentreprise.tg/ocsp/",
    ca_issuers_url="http://pki.monentreprise.tg/ca.pem",
    crl_url="http://pki.monentreprise.tg/crl/1/latest/",
)
```

> **Note** — Si `ocsp_url`, `ca_issuers_url` ou `crl_url` est omis, l'extension
> correspondante n'est pas injectée. Rétrocompatibilité totale avec les appels existants.

---

### 5. Vérification de validité — `checkCertValidity`

```python
from cheetahpki import checkCertValidity

days = checkCertValidity(cert_file="tmp/certs/alice_cert.pem")
# Retourne le nombre de jours restants (int), ou None si le certificat est expiré
```

---

### 6. Informations sur un certificat

#### Helpers unitaires — `getCertInfo`

```python
from cheetahpki import get_owner, get_serial_number, get_validity_start, get_validity_end

owner  = get_owner(cert_pem_path="tmp/certs/alice_cert.pem")
serial = get_serial_number(cert_pem_path="tmp/certs/alice_cert.pem")
start  = get_validity_start(cert_pem_path="tmp/certs/alice_cert.pem")
end    = get_validity_end(cert_pem_path="tmp/certs/alice_cert.pem")
```

#### Extraction consolidée — `getCertificateInfo` (0.0.13)

Récupère toutes les métadonnées en un seul appel. Conçu pour alimenter directement les champs d'un modèle Django `Certificate` après émission.

```python
from cheetahpki import getCertificateInfo

info = getCertificateInfo(cert_pem_path="tmp/certs/alice_cert.pem")

info["common_name"]                   # "alice"
info["subject_dn"]                    # "CN=alice,OU=RH,O=Acme,L=Lomé,..."
info["issuer_dn"]                     # DN complet de la CA intermédiaire
info["serial_number_int"]             # int — utilisé pour les entrées CRL
info["serial_number_hex"]             # "3F2A...", utile pour l'affichage
info["validity_start"]                # datetime UTC
info["validity_end"]                  # datetime UTC
info["days_remaining"]                # int
info["is_expired"]                    # bool
info["key_algorithm"]                 # "RSA" | "EC" | "Ed25519" | "Ed448"
info["key_size_or_curve"]             # "2048" | "secp256r1" | "256" | ...
info["signature_algorithm"]           # "sha256WithRSAEncryption" | ...
info["fingerprint_sha256"]            # "AA:BB:..."
info["public_key_fingerprint_sha256"] # "AA:BB:..."
info["san"]                           # {dns: [...], ip: [...], email: [...]}
info["aia"]                           # {ocsp_urls: [...], ca_issuers_urls: [...]}
info["crl_distribution_points"]       # ["http://.../crl/1/latest/", ...]
info["basic_constraints"]             # {ca: bool, path_length: int|None}
info["is_ca"]                         # bool
info["key_usage"]                     # {digital_signature: True, ...}
```

---

### 7. Publication de CRL — `generateCRL` (0.0.13)

Produit une Certificate Revocation List signée par la CA fournie, au format PEM et DER.

Pour une diffusion HTTP conforme RFC 5280, servir le DER avec `Content-Type: application/pkix-crl`.

```python
import datetime
from cheetahpki import generateCRL, CRLRevocationEntry, SUPPORTED_REVOCATION_REASONS

entries = [
    CRLRevocationEntry(
        serial_number=0x3F2A1E,  # int décimal (utiliser info["serial_number_int"] après getCertificateInfo)
        revocation_date=datetime.datetime.now(datetime.timezone.utc),
        reason="key_compromise",  # cf. SUPPORTED_REVOCATION_REASONS
    ),
    CRLRevocationEntry(
        serial_number=0xABCD,
        revocation_date=datetime.datetime(2026, 3, 15, 0, 0, tzinfo=datetime.timezone.utc),
        reason="cessation_of_operation",
    ),
]

crl_pem_path, crl_der_bytes = generateCRL(
    ca_cert_path="tmp/certs/inter_ca.pem",
    ca_private_key_path="tmp/keys/inter_private_key.pem",
    revoked_entries=entries,        # liste de CRLRevocationEntry
    crl_number=7,                   # strictement croissant à chaque nouvelle CRL
    next_update_days=7,             # durée de validité de la CRL en jours
    ca_key_password=None,           # optionnel
    output_folder="tmp/crl",
    output_filename="inter_ca_crl",
)

# crl_pem_path  : str   — chemin vers le fichier CRL PEM généré
# crl_der_bytes : bytes — contenu DER, prêt pour la diffusion HTTP
```

**Raisons de révocation supportées** (RFC 5280 §5.3.1) :

```python
SUPPORTED_REVOCATION_REASONS = (
    "unspecified",            # 0
    "key_compromise",         # 1 — clé privée compromise
    "ca_compromise",          # 2 — clé CA compromise
    "affiliation_changed",    # 3 — changement d'organisation
    "superseded",             # 4 — remplacé par un nouveau certificat
    "cessation_of_operation", # 5 — service arrêté
    "certificate_hold",       # 6 — suspension temporaire
    "privilege_withdrawn",    # 9 — privilèges retirés
    "aa_compromise",          # 10 — AA compromise
    "remove_from_crl",        # 8 — retrait de la CRL (suspension levée)
)
```

**Notes importantes :**
- `crl_number` doit être **strictement croissant** pour chaque CA — ne jamais réutiliser un numéro déjà émis.
- La CRL liste **tous les certificats révoqués actifs**, pas seulement les nouveaux. Reconstruire la liste complète à chaque publication.
- Les certificats expirés **peuvent** être retirés de la CRL après leur expiration (optimisation de taille).

---

### 8. Empreintes (fingerprints)

```python
from cheetahpki import getCertificateFingerprint, getPublicKeyFingerprint

fp_cert = getCertificateFingerprint(cert_pem_path="tmp/certs/alice_cert.pem")
# Retourne : "AA:BB:CC:..." (SHA-256 du certificat DER)

fp_key = getPublicKeyFingerprint(pub_key_pem_path="tmp/keys/user_public_key.pem")
# Retourne : "AA:BB:CC:..." (SHA-256 de la clé publique DER)
```

---

### 9. Génération et analyse de CSR

```python
from cheetahpki import generateCsr, parseCsr
from cryptography.hazmat.primitives.serialization import load_pem_private_key

# Générer une CSR à partir d'une clé privée existante
with open("tmp/keys/user_private_key.pem", "rb") as f:
    private_key = load_pem_private_key(f.read(), password=None)

csr_pem = generateCsr(
    private_key=private_key,
    country="TG",
    state="Maritime",
    city="Lomé",
    org="MonEntreprise",
    common_name="alice.monentreprise.tg",
    alt_names=["alice.monentreprise.tg"],   # optionnel
    ip_addresses=["192.168.1.50"],           # optionnel
)
# csr_pem : bytes PEM

with open("tmp/alice.csr", "wb") as f:
    f.write(csr_pem)

# Analyser un fichier CSR existant
info = parseCsr("tmp/alice.csr")
# Retourne un dict : {common_name, country, state, city, org, alt_names, ip_addresses, ...}
```

---

## Exceptions

| Exception | Déclenchée quand |
|-----------|-----------------|
| `CertificateFileNotFoundError` | Fichier certificat introuvable. |
| `CertificateFileEmptyError` | Fichier certificat vide. |
| `CertificateLoadError` | Impossible de charger le certificat (format invalide). |
| `CertificateSaveError` | Impossible d'enregistrer le certificat. |
| `CertificateSigningError` | Erreur lors de la signature du certificat. |
| `InvalidCertificateError` | Certificat structurellement invalide. |
| `CertificateDateError` | Dates de validité incohérentes. |
| `PrivateKeyFileNotFoundError` | Fichier de clé privée introuvable. |
| `PublicKeyFileNotFoundError` | Fichier de clé publique introuvable. |
| `PrivateKeyLoadError` | Impossible de charger la clé privée (format, mot de passe…). |
| `PublicKeyLoadError` | Impossible de charger la clé publique. |
| `InvalidKeySizeError` | Taille de clé RSA invalide (acceptées : 2048, 4096). |
| `KeyPairGenerationError` | Erreur générale lors de la génération de la paire. |
| `KeySaveError` | Impossible d'enregistrer la clé sur le filesystem. |
| `DirectoryCreationError` | Impossible de créer le répertoire de sortie. |
| `UnsupportedAlgorithmError` | Algorithme ou courbe non supporté (voir `SUPPORTED_ALGORITHMS`, `SUPPORTED_CURVES`). |

---

## Changelog

### 0.0.13 (2026-04-21)

- **Nouveau : `generateCRL`** — publication de CRL signée (RFC 5280) avec entrées `CRLRevocationEntry` (serial, date, raison). Export PEM + DER. Le DER est directement diffusable via HTTP (`Content-Type: application/pkix-crl`).
- **Nouveau : `getCertificateInfo`** — extraction consolidée des métadonnées d'un certificat : CN, DN, émetteur, serial (int + hex), validity, algo, courbe, fingerprints (cert + clé), SAN, AIA, CRL DP, BasicConstraints, KeyUsage, is_expired, is_ca. Conçu pour alimenter directement les champs d'un modèle Django `Certificate`.
- **`createSignedCert` / `createSignedInterCert`** : ajout des paramètres optionnels `ocsp_url`, `ca_issuers_url`, `crl_url` — injectent les extensions `AuthorityInformationAccess` (AIA/OCSP + CA_ISSUERS) et `CRLDistributionPoints`. Rétrocompatibilité totale : paramètres absents → extensions non injectées.
- **Export de `SUPPORTED_REVOCATION_REASONS`** dans `__init__.py`.

### 0.0.12 (2026-04-20)

- Ajout du support ECDSA P-256, P-384, P-521 dans `generateKeyPair()`.
- Ajout du support Ed25519 et Ed448.
- Format PKCS8 pour les clés EC/Ed* (TraditionalOpenSSL conservé pour RSA — compatibilité maximale).
- Export de `SUPPORTED_ALGORITHMS` et `SUPPORTED_CURVES` dans `__init__.py`.
- Ajout de `createSignedInterCert`, `generateCsr`, `parseCsr`.
- Réécriture complète des docstrings et messages d'erreur en français.

### 0.0.11 (précédent)

- RSA uniquement (2048 / 4096 bits).
- Fonctions de base : génération de clés, certificats auto-signés, certificats signés par CA.
- Vérification de validité, extraction d'infos, empreintes.

---

## Licence

MIT — Développé par Michel KPEKPASSI dans le cadre du projet vXtend PKI.
