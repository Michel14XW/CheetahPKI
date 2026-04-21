# CheetahPKI

**Version** : 0.0.13
**Auteur** : Michel KPEKPASSI | [GitHub](https://github.com/Michel14XW/cheetahpki)
**Licence** : MIT | Python ≥ 3.11

CheetahPKI est une bibliothèque Python de cryptographie PKI pour générer des paires de clés, créer et signer des certificats X.509, publier des CRL, extraire les métadonnées d'un certificat, calculer des empreintes et analyser des CSR.

---

## Algorithmes supportés

| Algorithme | Clé         | Statut  |
|-----------|-------------|---------|
| RSA       | 2048 / 4096 bits | ✅ Stable |
| ECDSA P-256 | 256 bits  | ✅ Stable |
| ECDSA P-384 | 384 bits  | ✅ Stable |
| ECDSA P-521 | 521 bits  | ✅ Stable |
| Ed25519   | 256 bits    | ✅ Stable |
| Ed448     | 448 bits    | ✅ Stable |

Constantes exportées :

```python
from cheetahpki import SUPPORTED_ALGORITHMS, SUPPORTED_CURVES

# SUPPORTED_ALGORITHMS = ("RSA", "EC", "Ed25519", "Ed448")
# SUPPORTED_CURVES      = ("P-256", "P-384", "P-521")
```

---

## Installation

```bash
# Depuis GitHub (branche main)
pip install git+https://github.com/Michel14XW/cheetahpki.git

# Depuis une archive locale (dist/)
pip install cheetahpki-0.0.12.tar.gz
```

---

## Arborescence

```
cheetahpki/
├── __init__.py                 ← exports publics + SUPPORTED_ALGORITHMS/CURVES/REVOCATION_REASONS
├── generateKeyPair.py          ← RSA, ECDSA P-256/384/521, Ed25519, Ed448
├── createSelfSignedRootCert.py
├── createSignedCert.py         ← cert utilisateur signé par CA intermédiaire (+ AIA/CRL)
├── createSignedInterCert.py    ← cert CA intermédiaire signé par CA racine (+ AIA/CRL)
├── generateCsr.py
├── parseCsr.py
├── generateCRL.py              ← CRL RFC 5280 (nouveau 0.0.13)
├── checkCertValidity.py
├── getCertInfo.py              ← helpers unitaires (CN, serial, dates)
├── getCertificateInfo.py       ← extraction consolidée (nouveau 0.0.13)
├── fingerprint.py
└── exceptions.py
```

---

## Utilisation
## Utilisation

### 1. Génération d'une paire de clés — `generateKeyPair`

```python
from cheetahpki import generateKeyPair

# RSA 4096 (défaut — rétrocompatible avec toutes les versions précédentes)
priv, pub = generateKeyPair(uid="alice")

# RSA 2048 avec mot de passe
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
| `uid` | str | — | Identifiant unique du propriétaire |
| `key_size` | int | 4096 | Taille RSA en bits (ignoré pour EC/Ed*) |
| `key_directory` | str | `"tmp/keys"` | Répertoire de sortie |
| `private_key_password` | str | None | Chiffrement de la clé privée (optionnel) |
| `algorithm` | str | `"RSA"` | `"RSA"`, `"EC"`, `"Ed25519"`, `"Ed448"` |
| `curve` | str | `"P-256"` | Courbe EC uniquement : `"P-256"`, `"P-384"`, `"P-521"` |

**Retourne :** `(private_key_path: str, public_key_path: str)`

**Format des clés générées :**
- RSA → PEM `TraditionalOpenSSL` (compatibilité OpenSSL maximale)
- EC / Ed25519 / Ed448 → PEM `PKCS8` (standard NIST / RFC 5958)

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
    # Extensions nouvelles 0.0.13 (optionnelles) :
    ocsp_url="http://pki.monentreprise.tg/ocsp/",
    ca_issuers_url="http://pki.monentreprise.tg/ca.pem",
    crl_url="http://pki.monentreprise.tg/crl/latest/",
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
    # Extensions nouvelles 0.0.13 (optionnelles) — obligatoires en prod pour
    # que les clients puissent vérifier la validité en ligne :
    ocsp_url="http://pki.monentreprise.tg/ocsp/",
    ca_issuers_url="http://pki.monentreprise.tg/ca.pem",
    crl_url="http://pki.monentreprise.tg/crl/latest/",
)
```

> **Note 0.0.13** — Si l'un des trois paramètres `ocsp_url`, `ca_issuers_url`,
> `crl_url` est omis, l'extension correspondante n'est pas injectée. Cela
> garantit la rétrocompatibilité avec les appels existants.

---

### 5. Vérification de validité — `checkCertValidity`

```python
from cheetahpki import checkCertValidity

days = checkCertValidity(cert_file="tmp/certs/alice_cert.pem")
# Retourne le nombre de jours restants, ou None si le certificat est expiré
```

---

### 6. Informations sur un certificat — `getCertInfo` (helpers unitaires)

```python
from cheetahpki import get_owner, get_serial_number, get_validity_start, get_validity_end

owner  = get_owner(cert_pem_path="tmp/certs/alice_cert.pem")
serial = get_serial_number(cert_pem_path="tmp/certs/alice_cert.pem")
start  = get_validity_start(cert_pem_path="tmp/certs/alice_cert.pem")
end    = get_validity_end(cert_pem_path="tmp/certs/alice_cert.pem")
```

### 6-bis. Extraction consolidée — `getCertificateInfo` (0.0.13)

Récupère toutes les métadonnées d'un certificat en un seul appel. Conçu pour
alimenter directement les champs d'un modèle Django `Certificate` après
émission (common_name, subject_dn, fingerprint, algo, key_size/curve, AIA, CRL DP,
etc.).

```python
from cheetahpki import getCertificateInfo

info = getCertificateInfo(cert_pem_path="tmp/certs/alice_cert.pem")

info["common_name"]                   # "alice"
info["subject_dn"]                    # "CN=alice,OU=RH,O=Acme,L=Lomé,..."
info["issuer_dn"]                     # DN complet de la CA intermédiaire
info["serial_number_int"]             # int — pour la CRL
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
info["crl_distribution_points"]       # ["http://.../crl/latest/", ...]
info["basic_constraints"]             # {ca: bool, path_length: int|None}
info["is_ca"]                         # bool
info["key_usage"]                     # {digital_signature: True, ...}
```

---

### 7. Publication de CRL — `generateCRL` (0.0.13)

Produit une Certificate Revocation List signée par la CA fournie, au format PEM
et DER. Pour une diffusion HTTP conforme RFC 5280, servir le DER avec
`Content-Type: application/pkix-crl`.

```python
import datetime
from cheetahpki import generateCRL, CRLRevocationEntry, SUPPORTED_REVOCATION_REASONS

entries = [
    CRLRevocationEntry(
        serial_number=0x3F2A1E...,                         # int décimal
        revocation_date=datetime.datetime.now(datetime.timezone.utc),
        reason="key_compromise",                           # cf. SUPPORTED_REVOCATION_REASONS
    ),
]

crl_pem_path, crl_der_bytes = generateCRL(
    ca_cert_path="tmp/certs/inter_ca.pem",
    ca_private_key_path="tmp/keys/inter_private_key.pem",
    revoked_entries=entries,
    crl_number=7,              # strictement croissant à chaque nouvelle CRL
    next_update_days=7,
    ca_key_password=None,
    output_folder="tmp/crl",
    output_filename="inter_ca_crl",
)
```

**Raisons supportées** (RFC 5280 §5.3.1) :

```python
SUPPORTED_REVOCATION_REASONS = (
    "unspecified", "key_compromise", "ca_compromise", "affiliation_changed",
    "superseded", "cessation_of_operation", "certificate_hold",
    "privilege_withdrawn", "aa_compromise", "remove_from_crl",
)
```

---

### 7. Empreintes (fingerprints)

```python
from cheetahpki import getCertificateFingerprint, getPublicKeyFingerprint

fp_cert = getCertificateFingerprint(cert_pem_path="tmp/certs/alice_cert.pem")
fp_key  = getPublicKeyFingerprint(pub_key_pem_path="tmp/keys/user_public_key.pem")
```

---

### 8. Génération et analyse de CSR

```python
from cheetahpki import generateCsr, parseCsr
from cryptography.hazmat.primitives.serialization import load_pem_private_key

with open("tmp/keys/user_private_key.pem", "rb") as f:
    private_key = load_pem_private_key(f.read(), password=None)

csr_pem = generateCsr(
    private_key=private_key,
    country="TG",
    state="Maritime",
    city="Lomé",
    org="MonEntreprise",
    common_name="alice.monentreprise.tg",
    alt_names=["alice.monentreprise.tg"],
    ip_addresses=["192.168.1.50"],
)

with open("tmp/alice.csr", "wb") as f:
    f.write(csr_pem)

# Analyser un CSR existant
info = parseCsr("tmp/alice.csr")
# Retourne un dict : {common_name, country, state, city, org, alt_names, ip_addresses, ...}
```

---

## Exceptions

| Exception | Déclenchée quand |
|-----------|-----------------|
| `CertificateFileNotFoundError` | Fichier certificat introuvable |
| `CertificateFileEmptyError` | Fichier certificat vide |
| `CertificateLoadError` | Impossible de charger le certificat |
| `CertificateSaveError` | Impossible d'enregistrer le certificat |
| `CertificateSigningError` | Erreur lors de la signature |
| `InvalidCertificateError` | Certificat invalide |
| `CertificateDateError` | Dates de validité incohérentes |
| `PrivateKeyFileNotFoundError` | Clé privée introuvable |
| `PublicKeyFileNotFoundError` | Clé publique introuvable |
| `PrivateKeyLoadError` | Impossible de charger la clé privée |
| `PublicKeyLoadError` | Impossible de charger la clé publique |
| `InvalidKeySizeError` | Taille de clé RSA invalide |
| `KeyPairGenerationError` | Erreur lors de la génération de la paire |
| `KeySaveError` | Impossible d'enregistrer la clé |
| `DirectoryCreationError` | Impossible de créer le répertoire |
| `UnsupportedAlgorithmError` | Algorithme ou courbe non supporté |

---

## Changelog

### 0.0.13 (2026-04-21)
- **Nouveau : `generateCRL`** — publication de CRL signée (RFC 5280) avec entrées
  `CRLRevocationEntry` (serial, date, raison). Export PEM + DER.
- **Nouveau : `getCertificateInfo`** — extraction consolidée des métadonnées d'un
  certificat (CN, DN, émetteur, serial, validity, algo, courbe, fingerprints,
  SAN, AIA, CRL DP, BasicConstraints, KeyUsage, signature_algorithm, is_expired,
  is_ca). Conçu pour alimenter les champs d'un modèle Django `Certificate`.
- **`createSignedCert` / `createSignedInterCert`** : ajout des paramètres
  optionnels `ocsp_url`, `ca_issuers_url`, `crl_url` qui injectent respectivement
  les extensions `AuthorityInformationAccess` (AIA/OCSP + CA_ISSUERS) et
  `CRLDistributionPoints`. Rétrocompatibilité totale : ces paramètres omis →
  aucune extension ajoutée.
- Export de `SUPPORTED_REVOCATION_REASONS` dans `__init__.py`.

### 0.0.12 (2026-04-20)
- Ajout du support ECDSA P-256, P-384, P-521 dans `generateKeyPair()`
- Ajout du support Ed25519 et Ed448
- Format PKCS8 pour les clés EC/Ed* (TraditionalOpenSSL conservé pour RSA)
- Export de `SUPPORTED_ALGORITHMS` et `SUPPORTED_CURVES` dans `__init__.py`
- Ajout de `createSignedInterCert`, `generateCsr`, `parseCsr`
- Réécriture complète des docstrings et messages d'erreur en français

### 0.0.11 (précédent)
- RSA uniquement (2048 / 4096 bits)
- Fonctions de base : génération de clés, certificats auto-signés, certificats signés
- Vérification de validité, extraction d'infos, empreintes

---

## Licence

MIT — Développé par Michel KPEKPASSI dans le cadre du projet vXtend PKI.
