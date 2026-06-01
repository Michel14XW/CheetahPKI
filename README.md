# CheetahPKI

**Version** : 0.0.20
**Auteur** : Michel KPEKPASSI | [GitHub](https://github.com/Michel14XW/cheetahpki)
**Licence** : MIT | Python ≥ 3.11

CheetahPKI est une bibliothèque Python de cryptographie PKI pour générer des paires de clés, créer et signer des certificats X.509, publier des CRL, vérifier la révocation via OCSP, extraire les métadonnées d'un certificat, calculer des empreintes et analyser des CSR.

Conçue pour être utilisée en backend Django (projet vXtend-PKI v3) mais utilisable dans tout projet Python.

> **Nouveau en 0.0.20** — Normalisation du sujet (DN) et du SubjectAltName,
> alignée RFC 5280 :
> - **E-mail optionnel** — un `email=""` est accepté (validé seulement s'il est fourni).
> - **E-mail hors DN** — `emailAddress` n'est plus dans le sujet (déprécié RFC 5280 §4.1.2.6) ; s'il est fourni, il va dans le SAN `rfc822Name`.
> - **Plus de RDN vides** — `ST`/`L`/`OU` vides ne sont plus émis ; le pays `C` n'est inclus que s'il fait 2 lettres (normalisé en majuscules) au lieu de planter.
> - **SAN conditionnel** — l'extension n'est posée que si elle contient au moins un nom.
>
> Aucune signature publique ne change. Détails : voir [Changelog 0.0.20](#0020-2026-06-01).
>
> **Nouveau en 0.0.17** — `generateCsr()` accepte désormais des clés Ed25519 et Ed448.
> Un helper interne `_hash_for_key()` détermine l'algorithme de hash de signature selon le type de clé : `None` pour Ed25519 / Ed448 (hash intégré au schéma de signature, exigé par `cryptography`), `SHA-256` pour RSA / ECDSA (comportement historique préservé). Corrige le `ValueError: "Algorithm must be None when signing via ed25519 or ed448"` rencontré lors de la génération d'une CSR avec une clé Edwards. Rétrocompatibilité totale — aucun changement de signature.
>
> Détails : voir [Changelog 0.0.17](#0017-2026-05-20).
>
> **Nouveau en 0.0.16** — Refonte v3 :
> - **Client OCSP léger** `checkOCSPStatus()` (RFC 6960) pour vérifier en ligne le statut d'un certificat sans dépendance HTTP tierce.
> - **`KeyPairResult` + `generateKeyPairBytesEx()`** — dataclass enrichi exposant `is_password_protected` et `fingerprint_sha256` calculés en une passe (zéro double-chargement).
> - **`extra_extensions`** sur `createSignedCertFromBytes` / `createSignedInterCertFromBytes` — injection d'extensions X.509 personnalisées via un `CertificateTemplate` côté Django.
> - **`DEFAULT_EXTENSIONS_BY_PROFILE`** — profils EKU prêts à l'emploi : `tls_server`, `tls_client`, `email_smime`, `code_signing`.
> - **Nettoyage `default_backend()`** — suppression complète des `backend=default_backend()` (déprécié depuis `cryptography` 3.x). Le module charge désormais sans aucun `CryptographyDeprecationWarning`.
>
> Détails : voir [Changelog 0.0.16](#0016-2026-05-15).
>
> **Nouveau en 0.0.14** — API *bytes-first* pour les workflows Vault / HSM : toutes les primitives de signature disposent d'une variante `*FromBytes` qui accepte du PEM en mémoire (plutôt qu'un chemin de fichier). Voir la section [API bytes (0.0.14)](#api-bytes-0014).

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
- [API bytes (0.0.14)](#api-bytes-0014)
- [Nouveautés 0.0.16](#nouveautés-0016)
  - [KeyPairResult — paire de clés enrichie](#keypairresult--paire-de-clés-enrichie)
  - [Client OCSP — checkOCSPStatus](#client-ocsp--checkocspstatus)
  - [Profils d'extensions — DEFAULT_EXTENSIONS_BY_PROFILE](#profils-dextensions--default_extensions_by_profile)
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

### Algorithmes post-quantiques (0.0.18)

| Algorithme | Famille | Niveau NIST | Norme | Statut |
|-----------|---------|-------------|-------|--------|
| ML-DSA-44 (Dilithium2) | Réseaux | 2 | FIPS 204 | 🧪 Expérimental |
| ML-DSA-65 (Dilithium3) | Réseaux | 3 | FIPS 204 | 🧪 Expérimental |
| ML-DSA-87 (Dilithium5) | Réseaux | 5 | FIPS 204 | 🧪 Expérimental |
| Falcon-512 | Réseaux NTRU | 1 | FIPS 206 (draft) | 🧪 Expérimental |
| Falcon-1024 | Réseaux NTRU | 5 | FIPS 206 (draft) | 🧪 Expérimental |
| SLH-DSA-SHA2-128f/128s/192f/256f | Haché | 1–5 | FIPS 205 | 🧪 Expérimental |
| SLH-DSA-SHAKE-128f/256f | Haché | 1–5 | FIPS 205 | 🧪 Expérimental |

> **Production :** installer `liboqs-python` (`pip install liboqs-python`) qui
> fournit toutes les familles ci-dessus via la bibliothèque C
> [liboqs](https://openquantumsafe.org/). Sans liboqs, un **fallback Python natif**
> couvre **uniquement ML-DSA-65** — il est *interne-cohérent* (sign/verify
> fonctionnent) mais **non interopérable** et **non audité** : RECHERCHE / DÉMO
> uniquement, jamais en production. Voir [Post-quantique (0.0.18)](#post-quantique-018).

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

from cheetahpki import SUPPORTED_PQC_ALGORITHMS, PQC_ALGORITHMS, PQC_BACKEND
# SUPPORTED_PQC_ALGORITHMS = ("ML-DSA-44", "ML-DSA-65", "ML-DSA-87",
#                             "Falcon-512", "Falcon-1024",
#                             "SLH-DSA-SHA2-128f", "SLH-DSA-SHA2-128s",
#                             "SLH-DSA-SHA2-192f", "SLH-DSA-SHA2-256f",
#                             "SLH-DSA-SHAKE-128f", "SLH-DSA-SHAKE-256f")
# PQC_BACKEND = "liboqs" | "python_native"
```

---

## Installation

```bash
# Depuis GitHub (branche main)
pip install git+https://github.com/Michel14XW/cheetahpki.git

# Depuis une archive locale
pip install dist/cheetahpki-0.0.18.tar.gz
# ou en wheel
pip install dist/cheetahpki-0.0.18-py3-none-any.whl

# En mode éditable (dev local)
pip install -e .
```

---

## Arborescence

```
cheetahpki/
├── __init__.py                 ← exports publics + constantes SUPPORTED_*
├── generateKeyPair.py          ← RSA, ECDSA P-256/384/521, Ed25519, Ed448
│                                  + KeyPairResult dataclass (0.0.16)
│                                  + generateKeyPairBytesEx() (0.0.16)
├── createSelfSignedRootCert.py ← certificat CA racine auto-signé
├── createSignedCert.py         ← cert utilisateur signé par CA (+ AIA/CRL 0.0.13, extra_extensions 0.0.16)
├── createSignedInterCert.py    ← cert CA intermédiaire signé par CA racine (+ AIA/CRL 0.0.13, extra_extensions 0.0.16)
├── generateCsr.py              ← génération de CSR à partir d'une clé privée
├── parseCsr.py                 ← analyse d'un fichier CSR existant
├── generateCRL.py              ← CRL RFC 5280 (nouveau 0.0.13)
├── checkCertValidity.py        ← jours restants avant expiration
├── checkOCSP.py                ← client OCSP RFC 6960 (nouveau 0.0.16)
├── getCertInfo.py              ← helpers unitaires (CN, serial, dates)
├── getCertificateInfo.py       ← extraction consolidée (nouveau 0.0.13)
├── extensions.py               ← DEFAULT_EXTENSIONS_BY_PROFILE (nouveau 0.0.16)
├── pqc.py                       ← signatures post-quantiques ML-DSA/Falcon/SLH-DSA (nouveau 0.0.18)
├── fingerprint.py              ← empreintes SHA-256 de certificat et de clé publique
└── exceptions.py               ← hiérarchie d'exceptions typées (+ OCSPCheckError 0.0.16)
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

## API bytes (0.0.14)

Les variantes `*FromBytes` opèrent intégralement en mémoire : elles prennent
du PEM sous forme de `bytes` et retournent du PEM sous forme de `bytes`.
Rien n'est écrit sur disque — idéal pour les intégrations Vault / HSM /
services managés qui fournissent les clés via API.

```python
from cheetahpki import (
    createSelfSignedRootCertFromBytes,
    createSignedCertFromBytes,
    createSignedInterCertFromBytes,
    get_owner_from_bytes,
    get_serial_number_from_bytes,
    get_validity_start_from_bytes,
    get_validity_end_from_bytes,
)

# 1. Certificat auto-signé (CA racine) à partir d'une clé privée en mémoire
root_cert_pem: bytes = createSelfSignedRootCertFromBytes(
    pseudo="RootCA",
    company="Acme",
    city="Lomé",
    region="Maritime",
    country_code="TG",
    email="ca@acme.tg",
    valid_days=3650,
    private_key_pem=root_priv_pem,   # bytes — lus depuis Vault/KMS
    key_password=None,
)

# 2. Certificat intermédiaire signé par la racine, tout en mémoire
inter_cert_pem: bytes = createSignedInterCertFromBytes(
    public_key_pem=inter_pub_pem,
    pseudo="CA_Inter",
    company="Acme",
    department="DSI",
    city="Lomé",
    region="Maritime",
    country_code="TG",
    email="inter@acme.tg",
    valid_days=1825,
    ca_private_key_pem=root_priv_pem,
    ca_cert_pem=root_cert_pem,
    ocsp_url="http://pki.acme.tg/ocsp/",
    ca_issuers_url="http://pki.acme.tg/ca.pem",
    crl_url="http://pki.acme.tg/crl/1/latest/",
)

# 3. Certificat utilisateur signé par l'intermédiaire
user_cert_pem: bytes = createSignedCertFromBytes(
    public_key_pem=user_pub_pem,
    pseudo="alice",
    company="Acme",
    department="RH",
    city="Lomé",
    region="Maritime",
    country_code="TG",
    email="alice@acme.tg",
    valid_days=365,
    ca_private_key_pem=inter_priv_pem,
    ca_cert_pem=inter_cert_pem,
    ocsp_url="http://pki.acme.tg/ocsp/",
    ca_issuers_url="http://pki.acme.tg/ca.pem",
    crl_url="http://pki.acme.tg/crl/1/latest/",
)

# 4. Métadonnées sans toucher au disque
owner  = get_owner_from_bytes(user_cert_pem)
serial = get_serial_number_from_bytes(user_cert_pem)
start  = get_validity_start_from_bytes(user_cert_pem)
end    = get_validity_end_from_bytes(user_cert_pem)
```

**Convention** : toutes les fonctions `*FromBytes` attendent et retournent
du PEM. Si vos sources sont en DER, convertissez d'abord via
`cryptography.x509.load_der_x509_certificate(...).public_bytes(
serialization.Encoding.PEM)`.

Les variantes chemin historiques (`createSelfSignedRootCert`,
`createSignedCert`, `createSignedInterCert`, `get_owner`, …) sont
conservées et délèguent désormais aux variantes bytes — rétrocompatibilité
totale.

---

## Post-quantique (0.0.18)

CheetahPKI 0.0.18 introduit un module `pqc` qui ajoute le support des schémas de
signature résistants à l'ordinateur quantique normalisés (ou en cours de
normalisation) par le NIST : **ML-DSA** (FIPS 204, ex-Dilithium), **Falcon**
(FN-DSA, FIPS 206 *draft*) et **SLH-DSA** (FIPS 205, ex-SPHINCS+).

### Stratégie en deux couches

1. **liboqs (production)** — si `liboqs-python` est installé, *tous* les
   algorithmes du catalogue sont disponibles, via la bibliothèque C
   [Open Quantum Safe](https://openquantumsafe.org/).
2. **Fallback Python natif (recherche)** — si liboqs est absent, seul
   **ML-DSA-65** est disponible via une implémentation Python pure. Elle est
   **interne-cohérente** (une signature produite est vérifiable localement) mais
   **non interopérable** avec liboqs/OpenSSL et **non auditée** :
   RECHERCHE / DÉMO uniquement.

```python
from cheetahpki import PQC_BACKEND, PQC_AVAILABLE, list_pqc_algorithms
print(PQC_BACKEND)            # "liboqs" ou "python_native"
print(list_pqc_algorithms())  # algos réellement utilisables sur ce système
```

### Génération de clés — `generateKeyPairPQC`

Retourne un `PQCKeyPairResult` (dataclass `frozen`) calqué sur `KeyPairResult`
classique (mêmes champs `private_key_pem` / `public_key_pem` /
`is_password_protected` / `fingerprint_sha256`), enrichi de `backend` et
`is_experimental`. La clé publique est encodée en **SubjectPublicKeyInfo** PEM,
la clé privée en **PKCS#8** PEM (ou, si un mot de passe est fourni, dans un
conteneur chiffré `PQC ENCRYPTED PRIVATE KEY` — PBKDF2-SHA256 + AES-256-GCM).

```python
from cheetahpki import generateKeyPairPQC, load_pqc_private_key_pem

kp = generateKeyPairPQC("ML-DSA-65")            # alias acceptés : "Dilithium3"
print(kp.key_algorithm, kp.backend, kp.fingerprint_sha256)

# Clé privée chiffrée
kpe = generateKeyPairPQC("ML-DSA-65", private_key_password="motdepasse")
alg, raw_secret = load_pqc_private_key_pem(kpe.private_key_pem, "motdepasse")
```

### Certificat X.509 signé par une CA PQC — `createSignedCertPQC`

`cryptography` ne sait pas (encore) signer un certificat X.509 avec une clé
ML-DSA/Falcon/SLH-DSA. CheetahPKI encode donc lui-même le **TBSCertificate**
(RFC 5280) et le signe via le backend PQC ; l'OID de signature provient du
catalogue `PQC_ALGORITHMS`. Le certificat produit se charge avec
`cryptography.x509.load_pem_x509_certificate` (extensions BasicConstraints,
KeyUsage, EKU, SAN, SKI, AKI, AIA, CRLDP comprises).

```python
from cheetahpki import generateKeyPairPQC, createSignedCertPQC

ca   = generateKeyPairPQC("ML-DSA-65")
leaf = generateKeyPairPQC("ML-DSA-65")

cert_pem = createSignedCertPQC(
    subject_public_key_pem=leaf.public_key_pem,
    pseudo="alice", company="ACME", department="IT",
    city="Lomé", region="Maritime", country_code="TG",
    email="alice@acme.tg", valid_days=365,
    ca_private_key_pem=ca.private_key_pem,
    ca_public_key_pem=ca.public_key_pem,          # pour l'AuthorityKeyIdentifier
    ca_subject={"common_name": "ACME Root PQC", "country_code": "TG",
                "company": "ACME"},
    ca_algorithm="ML-DSA-65",
    ocsp_url="http://ocsp.acme.tg",
    crl_url="http://crl.acme.tg/root.crl",
    alt_names=["alice.acme.tg"], ip_addresses=["10.0.0.5"],
)
# CA intermédiaire : is_ca=True, path_length=0
```

### Catalogue `PQC_ALGORITHMS`

Dictionnaire `{nom canonique -> métadonnées}` : `oid`, `family`, `type`
(`lattice`/`hash`), `nist_level`, `fips`, `experimental`, `oqs_names`,
`aliases`, `summary`. `resolve_pqc_algorithm("Dilithium3")` renvoie
`"ML-DSA-65"` ; `is_pqc_algorithm(name)` teste l'appartenance.

> ⚠ **OID Falcon provisoires** : FN-DSA (FIPS 206) n'est pas finalisé ; les OID
> utilisés (`1.3.9999.3.*`) sont ceux d'interopérabilité OQS et changeront.

---

## Nouveautés 0.0.16

### KeyPairResult — paire de clés enrichie

`generateKeyPairBytesEx()` retourne un `KeyPairResult` (dataclass `frozen`) qui
contient à la fois les PEM, l'algorithme, la taille/courbe, le flag
`is_password_protected` (utile pour alimenter `KeyPair.is_password_protected`
côté Django) **et** le fingerprint SHA-256 de la clé publique — évite un
second chargement via `getPublicKeyFingerprintFromBytes`.

```python
from cheetahpki import generateKeyPairBytesEx, KeyPairResult

result: KeyPairResult = generateKeyPairBytesEx(
    algorithm="EC",
    curve="P-256",
    private_key_password="s3cret",
)

result.private_key_pem        # bytes
result.public_key_pem         # bytes
result.key_algorithm          # "EC"
result.key_size_or_curve      # "P-256"
result.is_password_protected  # True
result.fingerprint_sha256     # "DD:A2:..."
```

La fonction historique `generateKeyPairBytes()` reste inchangée et continue
de retourner `(priv_pem, pub_pem)` — **rétrocompatibilité totale**. Les
intégrations qui veulent les métadonnées enrichies basculent simplement vers
`generateKeyPairBytesEx`.

### Client OCSP — `checkOCSPStatus`

Client OCSP minimal (RFC 6960) basé uniquement sur `cryptography` et la
stdlib (`urllib`) — aucune dépendance HTTP tierce, ce qui simplifie le
packaging et reste cohérent avec `cryptography>=43.0.3`.

```python
from cheetahpki import checkOCSPStatus, OCSPCheckError

try:
    status, reason, this_update = checkOCSPStatus(
        cert_pem=user_cert_pem,           # bytes PEM du cert à vérifier
        ca_cert_pem=inter_ca_pem,         # bytes PEM de la CA émettrice
        ocsp_url="http://pki.example.org/ocsp/",
        timeout=10,                       # secondes
    )

    if status == "GOOD":
        print("Certificat valide selon le répondeur OCSP.")
    elif status == "REVOKED":
        print(f"Certificat révoqué — raison : {reason}")
    elif status == "UNKNOWN":
        print("Certificat inconnu du répondeur (vérifier la chaîne).")

except OCSPCheckError as exc:
    print(f"Échec OCSP : {exc}")
```

**Retour** : `(status: str, revocation_reason: str | None, this_update: datetime)`
où `status ∈ {"GOOD", "REVOKED", "UNKNOWN"}` et `revocation_reason` est l'une
des valeurs de `SUPPORTED_REVOCATION_REASONS` (ou `None` si non révoqué).

`OCSPCheckError` couvre : échec réseau, réponse OCSP malformée, statut non
SUCCESSFUL (MALFORMED_REQUEST, INTERNAL_ERROR, TRY_LATER, …).

### Profils d'extensions — `DEFAULT_EXTENSIONS_BY_PROFILE`

Les fonctions de signature `createSignedCertFromBytes` et
`createSignedInterCertFromBytes` acceptent désormais le paramètre optionnel
`extra_extensions` : une liste d'extensions X.509 supplémentaires injectées
avant la signature. Chaque élément est soit un `x509.ExtensionType`, soit
un tuple `(extension, critical: bool)`.

`DEFAULT_EXTENSIONS_BY_PROFILE` fournit 4 profils EKU prêts à l'emploi :

```python
from cheetahpki import (
    DEFAULT_EXTENSIONS_BY_PROFILE,
    createSignedCertFromBytes,
)

# Profils disponibles : "tls_server", "tls_client", "email_smime", "code_signing"
extras = DEFAULT_EXTENSIONS_BY_PROFILE["email_smime"]

cert_pem = createSignedCertFromBytes(
    public_key_pem=user_pub_pem,
    pseudo="alice", company="Acme", department="RH",
    city="Lomé", region="Maritime", country_code="TG",
    email="alice@acme.tg", valid_days=365,
    ca_private_key_pem=inter_priv_pem,
    ca_cert_pem=inter_cert_pem,
    extra_extensions=extras,
)
```

> ⚠️ **OID unique** : X.509 interdit deux extensions du même OID dans le
> même certificat. La signature par défaut inclut déjà un `ExtendedKeyUsage`
> (`serverAuth` + `clientAuth`) — ne pas ré-injecter d'EKU via
> `extra_extensions` si vous comptez réutiliser cet emplacement. Utilisez
> `extra_extensions` plutôt pour des extensions complémentaires :
> `CertificatePolicies`, `NameConstraints`, `SubjectKeyIdentifier` custom, etc.

Pour ajouter votre propre profil :

```python
from cryptography import x509
from cryptography.x509.oid import ObjectIdentifier

my_policy_oid = ObjectIdentifier("1.3.6.1.4.1.99999.1.1")
custom_profile = [
    (x509.CertificatePolicies([
        x509.PolicyInformation(my_policy_oid, None),
    ]), False),
]

cert_pem = createSignedCertFromBytes(..., extra_extensions=custom_profile)
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
| `OCSPCheckError` *(0.0.16)* | Échec d'une vérification OCSP — réseau, réponse malformée, statut non SUCCESSFUL. |

---

## Changelog

### 0.0.20 (2026-06-01)

Normalisation du **sujet (DN)** et du **SubjectAltName** — alignement RFC 5280,
corrige des défauts communs aux trois émetteurs (`createSignedCert`,
`createSignedInterCert`, `createSelfSignedRootCert`) **et** au moteur DER PQC.

- **L'e-mail devient optionnel.** Un `email=""` (ou absent) est désormais
  accepté ; il n'est validé que s'il est fourni. Auparavant tout émetteur levait
  `ValueError: Adresse email invalide` sur un e-mail vide.
- **L'e-mail quitte le DN.** L'attribut `emailAddress` (`1.2.840.113549.1.9.1`)
  n'est plus placé dans le sujet — il est **déprécié par la RFC 5280 §4.1.2.6**.
  Lorsqu'un e-mail est fourni, il figure uniquement dans le **SAN `rfc822Name`**.
- **Plus de RDN vides dans le DN.** Les composants vides (`ST`, `L`, `OU`, …) ne
  sont plus émis : fini les sujets du type `…,L=,ST=,C=TG`. Le pays (`C`) n'est
  inclus que s'il fait **exactement 2 lettres** (sinon omis au lieu de planter
  avec « Attribute's length must be >= 2 and <= 2, but it was 0 ») et est
  normalisé en majuscules.
- **SAN posé seulement s'il est non vide.** Sans e-mail ni `alt_names`/
  `ip_addresses`, l'extension SAN n'est plus ajoutée (un SAN vide est invalide).
- Nouveau module interne `cheetahpki/_name.py` : `build_subject_name(...)`,
  `build_san_general_names(...)` (et `is_valid_email`), partagé par les émetteurs.

> **Impact** : le DN des certificats nouvellement émis change (e-mail retiré,
> champs vides supprimés). Les certificats déjà émis ne sont pas affectés.
> Aucune signature de fonction publique ne change. Rétro-compatible 0.0.19.

### 0.0.19 (2026-05-31)

- **`createSignedCertHybrid(...)`** : émet un certificat X.509 dont le **sujet**
  porte une clé post-quantique (ML-DSA / Falcon / SLH-DSA), signé par une CA dont
  la clé peut être **classique** (RSA / EC / Ed25519 / Ed448) **ou** PQC. Le TBS
  est encodé en DER (car `cryptography` refuse une clé sujet PQC dans
  `CertificateBuilder`) puis signé avec la clé de la CA ; l'algorithme de
  signature suit la CA, la clé du sujet reste indépendante (RFC 5280). `issuer`
  et AuthorityKeyIdentifier dérivés de `ca_cert_pem`. Cas d'usage : une CA
  intermédiaire classique signe une feuille post-quantique. Rétro-compatible 0.0.18.

### 0.0.18 (2026-05-30)

- **Module post-quantique `cheetahpki.pqc`.** Support des schémas de signature
  PQC normalisés par le NIST : **ML-DSA** (FIPS 204 — ML-DSA-44/65/87),
  **Falcon** (FN-DSA, FIPS 206 *draft* — Falcon-512/1024) et **SLH-DSA**
  (FIPS 205 — variantes SHA2 et SHAKE). Stratégie en deux couches : backend
  `liboqs` (production, tous les algorithmes) ou fallback Python natif
  (ML-DSA-65 uniquement, RECHERCHE — interne-cohérent, non interopérable).
- **`generateKeyPairPQC(algorithm, private_key_password=None)`** → `PQCKeyPairResult`
  (clé publique SPKI PEM, clé privée PKCS#8 PEM ou conteneur chiffré
  PBKDF2-SHA256 + AES-256-GCM).
- **`createSignedCertPQC(...)`** : certificat X.509 (RFC 5280) signé par une CA
  à clé PQC. Le TBSCertificate est encodé en DER par la bibliothèque (puisque
  `cryptography` ne signe pas encore avec une clé PQC), puis signé via le
  backend PQC. Extensions BasicConstraints, KeyUsage, EKU, SAN, SKI, AKI, AIA,
  CRLDP. Mode CA intermédiaire (`is_ca`, `path_length`).
- **Helpers** : `PQCSigner`, `list_pqc_algorithms()`, `resolve_pqc_algorithm()`,
  `is_pqc_algorithm()`, `load_pqc_public_key_pem()`, `load_pqc_private_key_pem()`.
- **Constantes** : `PQC_ALGORITHMS` (catalogue + métadonnées : OID, famille,
  niveau NIST, FIPS), `SUPPORTED_PQC_ALGORITHMS`, `PQC_AVAILABLE`, `PQC_BACKEND`.

### 0.0.17 (2026-05-20)

- **Correctif : `generateCsr()` supporte Ed25519 et Ed448.** Ajout du helper
  interne `_hash_for_key(private_key)` qui retourne `None` pour les clés
  Edwards (`Ed25519PrivateKey`, `Ed448PrivateKey`) et `hashes.SHA256()` pour
  RSA / ECDSA. Sans ce correctif, signer une CSR avec une clé Ed25519 / Ed448
  levait `ValueError: "Algorithm must be None when signing via ed25519 or
  ed448"` (issue 046 vXtend).
- **Rétrocompatibilité totale** : la signature publique de `generateCsr()`
  est inchangée. Les appels existants avec des clés RSA / ECDSA continuent
  d'utiliser SHA-256 — aucun comportement modifié pour ces algorithmes.
- Bump version `__version__ = "0.0.17"`, `setup.py VERSION = "0.0.17"`.

### 0.0.16 (2026-05-15)

- **Nouveau : `checkOCSPStatus()`** — client OCSP léger RFC 6960. Retourne
  `(status, revocation_reason, this_update)`. Aucune dépendance HTTP tierce
  (`urllib` stdlib + `cryptography.x509.ocsp`). Voir
  [Client OCSP — checkOCSPStatus](#client-ocsp--checkocspstatus).
- **Nouveau : `KeyPairResult` + `generateKeyPairBytesEx()`** — dataclass
  `frozen` exposant `private_key_pem`, `public_key_pem`, `key_algorithm`,
  `key_size_or_curve`, `is_password_protected`, `fingerprint_sha256`. Permet
  d'alimenter directement les champs Django `KeyPair.is_password_protected`
  et `KeyPair.fingerprint_sha256` sans rechargement.
- **Nouveau : paramètre `extra_extensions`** sur `createSignedCertFromBytes`
  et `createSignedInterCertFromBytes` — injection d'extensions X.509 custom
  (typiquement issues d'un `CertificateTemplate` côté Django).
- **Nouveau : `DEFAULT_EXTENSIONS_BY_PROFILE`** — 4 profils EKU prêts à
  l'emploi : `tls_server`, `tls_client`, `email_smime`, `code_signing`.
- **Nouveau : `OCSPCheckError`** — exception dédiée pour les échecs OCSP
  (réseau, réponse malformée, statut non SUCCESSFUL).
- **Nettoyage : suppression complète des `backend=default_backend()`** dans
  `generateKeyPair.py`, `createSignedInterCert.py`, `generateCRL.py`.
  L'API moderne de `cryptography` (>= 3.x) gère le backend implicitement.
  Effet : `python -W error -c "import cheetahpki"` ne lève plus aucun
  `CryptographyDeprecationWarning`. Corrige aussi un `NameError` latent
  dans `createSignedInterCertFromBytes` (l'import `default_backend` manquait).
- **Rétrocompatibilité** : `generateKeyPairBytes()` continue de retourner
  `(priv_pem, pub_pem)`. Toutes les anciennes signatures restent valides ;
  les nouveaux paramètres (`extra_extensions`) sont optionnels.
- Bump version `__version__ = "0.0.16"`, `setup.py VERSION = "0.0.16"`.

### 0.0.14 (2026-04-24)

- **Nouveau : API *bytes-first*** — variantes `*FromBytes` pour toutes les primitives de signature et d'extraction :
  - `createSelfSignedRootCertFromBytes(..., private_key_pem: bytes, ...) -> bytes`
  - `createSignedCertFromBytes(..., public_key_pem: bytes, ca_private_key_pem: bytes, ca_cert_pem: bytes, ...) -> bytes`
  - `createSignedInterCertFromBytes(..., public_key_pem: bytes, ca_private_key_pem: bytes, ca_cert_pem: bytes, ...) -> bytes`
  - `get_owner_from_bytes(cert_pem: bytes)`, `get_serial_number_from_bytes(...)`, `get_validity_start_from_bytes(...)`, `get_validity_end_from_bytes(...)`
- **Objectif** : permettre aux backends qui stockent les clés privées dans HashiCorp Vault / AWS KMS / HSM de signer sans jamais matérialiser le PEM sur disque.
- Les fonctions historiques (chemin de fichier) sont conservées et délèguent désormais à leur variante bytes — aucune régression.
- Bump version `__version__ = "0.0.14"`.

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
