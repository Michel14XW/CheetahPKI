"""
pqc.py — Algorithmes de signature post-quantique pour CheetahPKI (>= 0.0.18).

Ce module ajoute à CheetahPKI le support des schémas de signature résistants à
l'ordinateur quantique normalisés (ou en cours de normalisation) par le NIST :

  * ML-DSA  (FIPS 204, ex-CRYSTALS-Dilithium) — ML-DSA-44 / 65 / 87
  * Falcon  (FN-DSA, FIPS 206 en préparation) — Falcon-512 / Falcon-1024
  * SLH-DSA (FIPS 205, ex-SPHINCS+)           — variantes SHA2 et SHAKE

Stratégie d'intégration en couches (identique au module `apps/core/pqc.py`
de vXtend-PKI, dont ce module est la promotion dans la bibliothèque) :

  Niveau 1 — liboqs (recommandé en production) :
      Binding Python `liboqs-python` (https://openquantumsafe.org/). Couvre la
      totalité des algorithmes ci-dessus. Installation : `pip install liboqs-python`
      (nécessite la bibliothèque C liboqs compilée).

  Niveau 2 — Implémentation Python native (RECHERCHE / DÉMO uniquement) :
      ML-DSA-65 (Dilithium3) en Python pur. Cette implémentation est
      ÉDUCATIVE : elle n'est pas constante en temps, n'a pas été auditée et
      n'est pas interopérable avec d'autres bibliothèques. NE JAMAIS l'utiliser
      en production — installer liboqs-python.

Surface publique :
    PQC_ALGORITHMS          dict {nom canonique -> métadonnées}
    PQC_AVAILABLE           bool — au moins un backend opérationnel
    PQC_BACKEND             "liboqs" | "python_native"
    list_pqc_algorithms()   liste filtrée des algos réellement disponibles
    resolve_pqc_algorithm() normalise un alias (ex. "Dilithium3" -> "ML-DSA-65")
    is_pqc_algorithm()      True si le nom désigne un algo PQC connu
    PQCSigner               interface unifiée keygen / sign / verify
    generateKeyPairPQC()    paire de clés -> PQCKeyPairResult (PEM SPKI/PKCS#8)
    createSignedCertPQC()   certificat X.509 signé par une CA à clé PQC
    load_pqc_private_key_pem() / load_pqc_public_key_pem()

Exemple :
    from cheetahpki import generateKeyPairPQC, createSignedCertPQC, PQC_ALGORITHMS

    ca = generateKeyPairPQC("ML-DSA-65")
    leaf = generateKeyPairPQC("ML-DSA-65")
    cert_pem = createSignedCertPQC(
        subject_public_key_pem=leaf.public_key_pem,
        pseudo="alice", company="ACME", department="IT",
        city="Lomé", region="Maritime", country_code="TG",
        email="alice@acme.tg", valid_days=365,
        ca_private_key_pem=ca.private_key_pem,
        ca_subject={"common_name": "ACME Root PQC", "country_code": "TG",
                    "company": "ACME"},
        ca_algorithm="ML-DSA-65",
    )
"""

from __future__ import annotations

import datetime
import hashlib
import ipaddress
import logging
import os
import struct
from dataclasses import dataclass
from typing import Optional, Tuple

from .exceptions import (
    KeyPairGenerationError,
    PrivateKeyLoadError,
    PublicKeyLoadError,
    UnsupportedAlgorithmError,
)

logger = logging.getLogger(__name__)


# ═════════════════════════════════════════════════════════════════════════════
# Catalogue des algorithmes
# ═════════════════════════════════════════════════════════════════════════════
#
# Chaque entrée décrit un algorithme PQC :
#   oid          : OID X.509 du schéma de signature (dotted string)
#   type         : "lattice" (réseaux euclidiens) | "hash" (haché)
#   family       : "ML-DSA" | "Falcon" | "SLH-DSA"
#   nist_level   : niveau de sécurité NIST (1, 2, 3 ou 5)
#   fips         : norme NIST applicable
#   oqs_names    : noms candidats du mécanisme liboqs (du plus récent au plus ancien)
#   experimental : True si l'OID n'est pas encore définitif (Falcon/FN-DSA)
#   summary      : description courte (UI)
#
# OIDs ML-DSA et SLH-DSA : arc NIST CSOR 2.16.840.1.101.3.4.3.{17..35} (FIPS 204/205).
# OIDs Falcon : arc interopérabilité OQS 1.3.9999.3.* (FN-DSA non finalisé).

PQC_ALGORITHMS: dict = {
    # ── ML-DSA (FIPS 204) ────────────────────────────────────────────────────
    "ML-DSA-44": {
        "oid": "2.16.840.1.101.3.4.3.17",
        "type": "lattice", "family": "ML-DSA", "nist_level": 2,
        "fips": "FIPS 204", "experimental": False,
        "oqs_names": ("ML-DSA-44", "Dilithium2"),
        "aliases": ("Dilithium2",),
        "summary": "ML-DSA-44 (Dilithium2) — réseaux, niveau NIST 2",
    },
    "ML-DSA-65": {
        "oid": "2.16.840.1.101.3.4.3.18",
        "type": "lattice", "family": "ML-DSA", "nist_level": 3,
        "fips": "FIPS 204", "experimental": False,
        "oqs_names": ("ML-DSA-65", "Dilithium3"),
        "aliases": ("Dilithium3",),
        "summary": "ML-DSA-65 (Dilithium3) — réseaux, niveau NIST 3 (équilibré)",
    },
    "ML-DSA-87": {
        "oid": "2.16.840.1.101.3.4.3.19",
        "type": "lattice", "family": "ML-DSA", "nist_level": 5,
        "fips": "FIPS 204", "experimental": False,
        "oqs_names": ("ML-DSA-87", "Dilithium5"),
        "aliases": ("Dilithium5",),
        "summary": "ML-DSA-87 (Dilithium5) — réseaux, niveau NIST 5 (haute sécurité)",
    },
    # ── Falcon / FN-DSA (FIPS 206, en préparation — OID OQS provisoire) ───────
    "Falcon-512": {
        "oid": "1.3.9999.3.6",
        "type": "lattice", "family": "Falcon", "nist_level": 1,
        "fips": "FIPS 206 (draft)", "experimental": True,
        "oqs_names": ("Falcon-512",),
        "aliases": ("FN-DSA-512",),
        "summary": "Falcon-512 — réseaux NTRU, signature compacte, niveau NIST 1",
    },
    "Falcon-1024": {
        "oid": "1.3.9999.3.9",
        "type": "lattice", "family": "Falcon", "nist_level": 5,
        "fips": "FIPS 206 (draft)", "experimental": True,
        "oqs_names": ("Falcon-1024",),
        "aliases": ("FN-DSA-1024",),
        "summary": "Falcon-1024 — réseaux NTRU, signature compacte, niveau NIST 5",
    },
    # ── SLH-DSA (FIPS 205, fondé sur le haché — sans état) ────────────────────
    "SLH-DSA-SHA2-128f": {
        "oid": "2.16.840.1.101.3.4.3.21",
        "type": "hash", "family": "SLH-DSA", "nist_level": 1,
        "fips": "FIPS 205", "experimental": False,
        "oqs_names": ("SLH-DSA-SHA2-128f", "SPHINCS+-SHA2-128f-simple"),
        "aliases": ("SPHINCS+-SHA2-128f",),
        "summary": "SLH-DSA-SHA2-128f — haché, rapide, niveau NIST 1",
    },
    "SLH-DSA-SHA2-128s": {
        "oid": "2.16.840.1.101.3.4.3.20",
        "type": "hash", "family": "SLH-DSA", "nist_level": 1,
        "fips": "FIPS 205", "experimental": False,
        "oqs_names": ("SLH-DSA-SHA2-128s", "SPHINCS+-SHA2-128s-simple"),
        "aliases": ("SPHINCS+-SHA2-128s",),
        "summary": "SLH-DSA-SHA2-128s — haché, signature compacte, niveau NIST 1",
    },
    "SLH-DSA-SHA2-192f": {
        "oid": "2.16.840.1.101.3.4.3.23",
        "type": "hash", "family": "SLH-DSA", "nist_level": 3,
        "fips": "FIPS 205", "experimental": False,
        "oqs_names": ("SLH-DSA-SHA2-192f", "SPHINCS+-SHA2-192f-simple"),
        "aliases": ("SPHINCS+-SHA2-192f",),
        "summary": "SLH-DSA-SHA2-192f — haché, niveau NIST 3",
    },
    "SLH-DSA-SHA2-256f": {
        "oid": "2.16.840.1.101.3.4.3.25",
        "type": "hash", "family": "SLH-DSA", "nist_level": 5,
        "fips": "FIPS 205", "experimental": False,
        "oqs_names": ("SLH-DSA-SHA2-256f", "SPHINCS+-SHA2-256f-simple"),
        "aliases": ("SPHINCS+-SHA2-256f",),
        "summary": "SLH-DSA-SHA2-256f — haché, niveau NIST 5",
    },
    "SLH-DSA-SHAKE-128f": {
        "oid": "2.16.840.1.101.3.4.3.27",
        "type": "hash", "family": "SLH-DSA", "nist_level": 1,
        "fips": "FIPS 205", "experimental": False,
        "oqs_names": ("SLH-DSA-SHAKE-128f", "SPHINCS+-SHAKE-128f-simple"),
        "aliases": ("SPHINCS+-SHAKE-128f",),
        "summary": "SLH-DSA-SHAKE-128f — haché (SHAKE), niveau NIST 1",
    },
    "SLH-DSA-SHAKE-256f": {
        "oid": "2.16.840.1.101.3.4.3.31",
        "type": "hash", "family": "SLH-DSA", "nist_level": 5,
        "fips": "FIPS 205", "experimental": False,
        "oqs_names": ("SLH-DSA-SHAKE-256f", "SPHINCS+-SHAKE-256f-simple"),
        "aliases": ("SPHINCS+-SHAKE-256f",),
        "summary": "SLH-DSA-SHAKE-256f — haché (SHAKE), niveau NIST 5",
    },
}

# Index alias (insensible à la casse) -> nom canonique
_ALIAS_INDEX: dict = {}
for _canon, _meta in PQC_ALGORITHMS.items():
    _ALIAS_INDEX[_canon.lower()] = _canon
    for _al in _meta.get("aliases", ()):
        _ALIAS_INDEX[_al.lower()] = _canon


def resolve_pqc_algorithm(name: str) -> str:
    """Normalise un nom/alias d'algorithme PQC vers son nom canonique.

    >>> resolve_pqc_algorithm("Dilithium3")
    'ML-DSA-65'
    """
    if not name:
        raise UnsupportedAlgorithmError("Nom d'algorithme PQC vide.")
    canon = _ALIAS_INDEX.get(name.strip().lower())
    if canon is None:
        raise UnsupportedAlgorithmError(
            f"Algorithme PQC inconnu : {name!r}. "
            f"Connus : {', '.join(PQC_ALGORITHMS)}"
        )
    return canon


def is_pqc_algorithm(name: str) -> bool:
    """True si `name` désigne un algorithme PQC connu (alias inclus)."""
    return bool(name) and name.strip().lower() in _ALIAS_INDEX


# ═════════════════════════════════════════════════════════════════════════════
# Détection du backend liboqs
# ═════════════════════════════════════════════════════════════════════════════

_liboqs = None
PQC_AVAILABLE = False
PQC_BACKEND = "none"

try:
    import oqs  # type: ignore  # liboqs-python

    _liboqs = oqs
    PQC_AVAILABLE = True
    PQC_BACKEND = "liboqs"
    logger.info("[PQC] liboqs-python détecté — backend OQS activé.")
except Exception:  # ImportError, ou erreur de chargement de la lib C
    PQC_BACKEND = "python_native"
    PQC_AVAILABLE = True  # le fallback natif couvre au moins ML-DSA-65
    logger.info(
        "[PQC] liboqs-python indisponible — fallback Python natif "
        "(ML-DSA-65, RECHERCHE UNIQUEMENT). Installer : pip install liboqs-python"
    )

# Algorithmes couverts par l'implémentation native (recherche)
_NATIVE_SUPPORTED = {"ML-DSA-65"}


def _oqs_mechanism_for(canonical: str) -> Optional[str]:
    """Retourne le nom de mécanisme liboqs activé pour `canonical`, ou None."""
    if _liboqs is None:
        return None
    try:
        enabled = set(_liboqs.get_enabled_sig_mechanisms())
    except Exception:
        enabled = set()
    for candidate in PQC_ALGORITHMS[canonical]["oqs_names"]:
        if candidate in enabled:
            return candidate
    return None


def list_pqc_algorithms() -> dict:
    """Liste les algorithmes PQC réellement disponibles sur ce système.

    :returns: dict {backend, signature: [...], all: [...]} où `signature`
        contient les noms canoniques utilisables avec le backend courant et
        `all` la totalité du catalogue (métadonnées).
    """
    if _liboqs is not None:
        usable = [c for c in PQC_ALGORITHMS if _oqs_mechanism_for(c) is not None]
        return {"backend": "liboqs", "signature": usable, "all": list(PQC_ALGORITHMS)}
    return {
        "backend": "python_native",
        "signature": sorted(_NATIVE_SUPPORTED),
        "all": list(PQC_ALGORITHMS),
    }


# ═════════════════════════════════════════════════════════════════════════════
# PQCSigner — interface unifiée keygen / sign / verify
# ═════════════════════════════════════════════════════════════════════════════

class PQCError(Exception):
    """Erreur générique du sous-système PQC de CheetahPKI."""


class PQCSigner:
    """Interface unifiée pour les schémas de signature post-quantique.

    Sélectionne automatiquement le meilleur backend :
        1. liboqs (production) — tous les algorithmes du catalogue ;
        2. Python natif (recherche) — ML-DSA-65 uniquement.

    :param algorithm: nom canonique ou alias (ex. "ML-DSA-65", "Dilithium3").
    """

    def __init__(self, algorithm: str = "ML-DSA-65"):
        self.algorithm = resolve_pqc_algorithm(algorithm)
        self.meta = PQC_ALGORITHMS[self.algorithm]
        self._mechanism = _oqs_mechanism_for(self.algorithm)

        if self._mechanism is not None:
            self.backend = "liboqs"
        elif self.algorithm in _NATIVE_SUPPORTED:
            self.backend = "python_native"
            self._native = _Dilithium3Native()
            logger.warning(
                "[PQC] Backend Python natif pour %s — RECHERCHE UNIQUEMENT, "
                "non interopérable. Installer liboqs-python pour la production.",
                self.algorithm,
            )
        else:
            raise UnsupportedAlgorithmError(
                f"Algorithme PQC '{self.algorithm}' indisponible : liboqs-python "
                f"est requis (le fallback natif ne couvre que {sorted(_NATIVE_SUPPORTED)})."
            )

    # ── Opérations cryptographiques ──────────────────────────────────────────

    def generate_keypair(self) -> Tuple[bytes, bytes]:
        """Génère (public_key_bytes, secret_key_bytes) bruts."""
        if self.backend == "liboqs":
            with _liboqs.Signature(self._mechanism) as signer:
                pub = signer.generate_keypair()
                sec = signer.export_secret_key()
                return pub, sec
        return self._native.keygen()

    def sign(self, message: bytes, secret_key: bytes) -> bytes:
        """Signe `message` avec la clé secrète brute."""
        if self.backend == "liboqs":
            with _liboqs.Signature(self._mechanism, secret_key) as signer:
                return signer.sign(message)
        return self._native.sign(message, secret_key)

    def verify(self, message: bytes, signature: bytes, public_key: bytes) -> bool:
        """Vérifie une signature ; retourne True/False (jamais d'exception)."""
        try:
            if self.backend == "liboqs":
                with _liboqs.Signature(self._mechanism) as verifier:
                    return bool(verifier.verify(message, signature, public_key))
            return self._native.verify(message, signature, public_key)
        except Exception:
            return False

    @property
    def oid(self) -> str:
        return self.meta["oid"]

    def __repr__(self) -> str:
        return f"<PQCSigner algorithm={self.algorithm} backend={self.backend}>"


# ═════════════════════════════════════════════════════════════════════════════
# Encodeur DER ASN.1 minimal (autonome, sans dépendance externe)
# ═════════════════════════════════════════════════════════════════════════════
#
# Suffisant pour produire un SubjectPublicKeyInfo, un PrivateKeyInfo (PKCS#8) et
# un Certificate X.509 (RFC 5280) signés par un schéma PQC. Toutes les fonctions
# retournent des `bytes` DER complets (tag + longueur + contenu).

def _der_len(length: int) -> bytes:
    if length < 0x80:
        return bytes([length])
    out = []
    while length:
        out.insert(0, length & 0xFF)
        length >>= 8
    return bytes([0x80 | len(out)]) + bytes(out)


def _der(tag: int, content: bytes) -> bytes:
    return bytes([tag]) + _der_len(len(content)) + content


def _der_seq(*items: bytes) -> bytes:
    return _der(0x30, b"".join(items))


def _der_set(*items: bytes) -> bytes:
    return _der(0x31, b"".join(items))


def _der_int(value: int) -> bytes:
    if value == 0:
        return _der(0x02, b"\x00")
    raw = value.to_bytes((value.bit_length() + 7) // 8, "big")
    if raw[0] & 0x80:  # éviter une interprétation négative
        raw = b"\x00" + raw
    return _der(0x02, raw)


def _der_bitstring(data: bytes, unused: int = 0) -> bytes:
    return _der(0x03, bytes([unused]) + data)


def _der_octet(data: bytes) -> bytes:
    return _der(0x04, data)


def _der_null() -> bytes:
    return _der(0x05, b"")


def _der_bool(value: bool) -> bytes:
    return _der(0x01, b"\xff" if value else b"\x00")


def _der_oid(dotted: str) -> bytes:
    parts = [int(p) for p in dotted.split(".")]
    first = 40 * parts[0] + parts[1]
    body = bytearray([first])
    for n in parts[2:]:
        if n < 0x80:
            body.append(n)
            continue
        stack = []
        while n:
            stack.insert(0, n & 0x7F)
            n >>= 7
        for i in range(len(stack) - 1):
            stack[i] |= 0x80
        body.extend(stack)
    return _der(0x06, bytes(body))


def _der_utf8(text: str) -> bytes:
    return _der(0x0C, text.encode("utf-8"))


def _der_printable(text: str) -> bytes:
    return _der(0x13, text.encode("ascii"))


def _der_ia5(text: str) -> bytes:
    return _der(0x16, text.encode("ascii"))


def _der_time(dt: datetime.datetime) -> bytes:
    """UTCTime si année < 2050, sinon GeneralizedTime (RFC 5280 §4.1.2.5)."""
    dt = dt.astimezone(datetime.timezone.utc)
    if dt.year < 2050:
        return _der(0x17, dt.strftime("%y%m%d%H%M%SZ").encode("ascii"))
    return _der(0x18, dt.strftime("%Y%m%d%H%M%SZ").encode("ascii"))


def _der_ctx(num: int, content: bytes, constructed: bool = True) -> bytes:
    """Tag contextuel [num]. constructed=True -> 0xA0+num, sinon 0x80+num."""
    tag = (0xA0 if constructed else 0x80) + num
    return _der(tag, content)


def _algid(oid: str, params: Optional[bytes] = None) -> bytes:
    """AlgorithmIdentifier. Pour les schémas PQC, le champ parameters est ABSENT."""
    body = _der_oid(oid)
    if params is not None:
        body += params
    return _der_seq(body)


# ── Minimal DER reader (pour relire un SubjectPublicKeyInfo) ──────────────────

def _read_tlv(data: bytes, offset: int = 0):
    """Lit un TLV. Retourne (tag, contenu_bytes, offset_après)."""
    tag = data[offset]
    offset += 1
    first = data[offset]
    offset += 1
    if first < 0x80:
        length = first
    else:
        nbytes = first & 0x7F
        length = int.from_bytes(data[offset:offset + nbytes], "big")
        offset += nbytes
    content = data[offset:offset + length]
    return tag, content, offset + length


# ═════════════════════════════════════════════════════════════════════════════
# Encodage / décodage des clés PQC (SPKI + PKCS#8, avec chiffrement maison)
# ═════════════════════════════════════════════════════════════════════════════

_PQC_PUB_LABEL = "PUBLIC KEY"
_PQC_PRIV_LABEL = "PRIVATE KEY"
_PQC_ENC_PRIV_LABEL = "PQC ENCRYPTED PRIVATE KEY"
# OID maison pour le conteneur chiffré (PBKDF2-SHA256 + AES-256-GCM)
_PQC_ENC_CONTAINER_OID = "1.3.6.1.4.1.99999.1.1"
_PBKDF2_ITERS = 200_000


def _b64_pem(label: str, der: bytes) -> bytes:
    import base64

    b64 = base64.encodebytes(der).decode("ascii").strip()
    return (
        f"-----BEGIN {label}-----\n{b64}\n-----END {label}-----\n"
    ).encode("ascii")


def _pem_to_der(pem: bytes, expected_labels) -> Tuple[str, bytes]:
    import base64

    text = pem.decode("ascii") if isinstance(pem, (bytes, bytearray)) else pem
    lines = [l.strip() for l in text.strip().splitlines()]
    if not lines or not lines[0].startswith("-----BEGIN "):
        raise ValueError("PEM invalide : en-tête manquant.")
    label = lines[0][len("-----BEGIN "):-len("-----")]
    if isinstance(expected_labels, str):
        expected_labels = (expected_labels,)
    if label not in expected_labels:
        raise ValueError(f"Label PEM inattendu : {label!r} (attendu {expected_labels}).")
    body = "".join(l for l in lines[1:-1])
    return label, base64.b64decode(body)


def _spki_der(algorithm: str, raw_public_key: bytes) -> bytes:
    """SubjectPublicKeyInfo DER pour une clé publique PQC brute."""
    oid = PQC_ALGORITHMS[algorithm]["oid"]
    return _der_seq(_algid(oid), _der_bitstring(raw_public_key))


def _pkcs8_der(algorithm: str, raw_secret_key: bytes) -> bytes:
    """PrivateKeyInfo (PKCS#8) DER pour une clé privée PQC brute.

    Le matériel privé PQC est encapsulé dans un OCTET STRING (conformément aux
    drafts LAMPS pour ML-DSA/SLH-DSA), lui-même contenu dans le champ
    `privateKey` (OCTET STRING) de la structure PKCS#8.
    """
    oid = PQC_ALGORITHMS[algorithm]["oid"]
    inner = _der_octet(raw_secret_key)
    return _der_seq(_der_int(0), _algid(oid), _der_octet(inner))


def _encrypt_secret_pem(algorithm: str, raw_secret_key: bytes, password: str) -> bytes:
    """Chiffre la clé privée brute (PBKDF2-SHA256 + AES-256-GCM) au format PEM.

    Conteneur DER :
        SEQUENCE {
            OID            <_PQC_ENC_CONTAINER_OID>,
            algorithm      UTF8String,        -- nom canonique PQC
            iterations     INTEGER,
            salt           OCTET STRING (16),
            nonce          OCTET STRING (12),
            ciphertext     OCTET STRING       -- AES-GCM(secret) || tag
        }
    """
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
    from cryptography.hazmat.primitives import hashes as _h

    salt = os.urandom(16)
    nonce = os.urandom(12)
    kdf = PBKDF2HMAC(algorithm=_h.SHA256(), length=32, salt=salt, iterations=_PBKDF2_ITERS)
    key = kdf.derive(password.encode("utf-8"))
    ciphertext = AESGCM(key).encrypt(nonce, raw_secret_key, None)
    der = _der_seq(
        _der_oid(_PQC_ENC_CONTAINER_OID),
        _der_utf8(algorithm),
        _der_int(_PBKDF2_ITERS),
        _der_octet(salt),
        _der_octet(nonce),
        _der_octet(ciphertext),
    )
    return _b64_pem(_PQC_ENC_PRIV_LABEL, der)


def load_pqc_public_key_pem(pem: bytes) -> Tuple[str, bytes]:
    """Charge un SubjectPublicKeyInfo PQC -> (algorithme_canonique, clé_publique_brute)."""
    try:
        _, der = _pem_to_der(pem, _PQC_PUB_LABEL)
        _, spki, _ = _read_tlv(der)              # contenu du SEQUENCE racine
        _, algid, after = _read_tlv(spki)        # AlgorithmIdentifier
        _, oid_bytes, _ = _read_tlv(algid)       # OID
        tag, bitstr, _ = _read_tlv(spki, after)  # BIT STRING
        raw_pub = bitstr[1:]                     # retirer l'octet "unused bits"
        oid = _decode_oid(oid_bytes)
        algorithm = _algorithm_for_oid(oid)
        return algorithm, raw_pub
    except Exception as e:
        raise PublicKeyLoadError(f"Clé publique PQC illisible : {e}")


def load_pqc_private_key_pem(pem: bytes, password: Optional[str] = None) -> Tuple[str, bytes]:
    """Charge une clé privée PQC -> (algorithme_canonique, clé_secrète_brute).

    Accepte le PKCS#8 clair (`PRIVATE KEY`) ou le conteneur chiffré maison
    (`PQC ENCRYPTED PRIVATE KEY`, requiert `password`).
    """
    try:
        label, der = _pem_to_der(pem, (_PQC_PRIV_LABEL, _PQC_ENC_PRIV_LABEL))
        if label == _PQC_ENC_PRIV_LABEL:
            if not password:
                raise PrivateKeyLoadError("Mot de passe requis pour cette clé chiffrée.")
            return _decrypt_secret_der(der, password)
        # PKCS#8 clair
        _, body, _ = _read_tlv(der)              # contenu du SEQUENCE racine
        _, _version, after = _read_tlv(body)     # version INTEGER
        _, algid, after = _read_tlv(body, after)  # AlgorithmIdentifier
        _, oid_bytes, _ = _read_tlv(algid)
        _, priv_octet, _ = _read_tlv(body, after)  # OCTET STRING privateKey
        _, raw_sec, _ = _read_tlv(priv_octet)     # OCTET STRING interne
        algorithm = _algorithm_for_oid(_decode_oid(oid_bytes))
        return algorithm, raw_sec
    except PrivateKeyLoadError:
        raise
    except Exception as e:
        raise PrivateKeyLoadError(f"Clé privée PQC illisible : {e}")


def _decrypt_secret_der(der: bytes, password: str) -> Tuple[str, bytes]:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
    from cryptography.hazmat.primitives import hashes as _h

    _, body, _ = _read_tlv(der)
    _, _oid, off = _read_tlv(body)
    _, alg_bytes, off = _read_tlv(body, off)
    _, iters_bytes, off = _read_tlv(body, off)
    _, salt, off = _read_tlv(body, off)
    _, nonce, off = _read_tlv(body, off)
    _, ciphertext, _ = _read_tlv(body, off)
    algorithm = alg_bytes.decode("utf-8")
    iterations = int.from_bytes(iters_bytes, "big")
    kdf = PBKDF2HMAC(algorithm=_h.SHA256(), length=32, salt=salt, iterations=iterations)
    key = kdf.derive(password.encode("utf-8"))
    try:
        raw_secret = AESGCM(key).decrypt(nonce, ciphertext, None)
    except Exception:
        raise PrivateKeyLoadError("Mot de passe incorrect ou clé corrompue.")
    return resolve_pqc_algorithm(algorithm), raw_secret


def _decode_oid(oid_bytes: bytes) -> str:
    first = oid_bytes[0]
    parts = [first // 40, first % 40]
    value = 0
    for b in oid_bytes[1:]:
        value = (value << 7) | (b & 0x7F)
        if not (b & 0x80):
            parts.append(value)
            value = 0
    return ".".join(str(p) for p in parts)


_OID_INDEX = {meta["oid"]: name for name, meta in PQC_ALGORITHMS.items()}


def _algorithm_for_oid(oid: str) -> str:
    try:
        return _OID_INDEX[oid]
    except KeyError:
        raise UnsupportedAlgorithmError(f"OID PQC inconnu : {oid}")


# ═════════════════════════════════════════════════════════════════════════════
# generateKeyPairPQC
# ═════════════════════════════════════════════════════════════════════════════

@dataclass(frozen=True)
class PQCKeyPairResult:
    """Résultat d'une génération de paire de clés post-quantique.

    Champs alignés sur `cheetahpki.KeyPairResult` (classique) pour faciliter
    l'intégration côté Django (modèle KeyPair de vXtend-PKI).

    Attributes:
        private_key_pem (bytes): PKCS#8 PEM (ou conteneur chiffré si mot de passe).
        public_key_pem (bytes): SubjectPublicKeyInfo PEM.
        key_algorithm (str): nom canonique ("ML-DSA-65", "Falcon-512", ...).
        key_size_or_curve (str): identique à key_algorithm (pas de notion de taille).
        is_password_protected (bool): True si la clé privée est chiffrée.
        fingerprint_sha256 (str): empreinte SHA-256 de la clé publique brute (hex ":").
        backend (str): "liboqs" ou "python_native".
        is_experimental (bool): True si l'OID/algorithme n'est pas définitif.
        raw_public_key (bytes): clé publique brute.
        raw_secret_key (bytes): clé secrète brute (NE PAS persister hors Vault).
    """

    private_key_pem: bytes
    public_key_pem: bytes
    key_algorithm: str
    key_size_or_curve: str
    is_password_protected: bool
    fingerprint_sha256: str
    backend: str
    is_experimental: bool
    raw_public_key: bytes
    raw_secret_key: bytes


def generateKeyPairPQC(
    algorithm: str = "ML-DSA-65",
    private_key_password: Optional[str] = None,
) -> PQCKeyPairResult:
    """Génère une paire de clés post-quantique **en mémoire**.

    Args:
        algorithm: nom canonique ou alias (ex. "ML-DSA-65", "Dilithium3",
            "Falcon-512", "SLH-DSA-SHA2-128f").
        private_key_password: mot de passe optionnel — chiffre la clé privée
            (PBKDF2-SHA256 + AES-256-GCM, conteneur PEM `PQC ENCRYPTED PRIVATE KEY`).

    Returns:
        PQCKeyPairResult.

    Raises:
        UnsupportedAlgorithmError: algorithme inconnu ou indisponible sur ce backend.
        KeyPairGenerationError: échec de la génération.
    """
    canonical = resolve_pqc_algorithm(algorithm)
    if private_key_password is not None and not isinstance(private_key_password, str):
        raise ValueError("Le mot de passe doit être une chaîne de caractères.")

    signer = PQCSigner(canonical)
    try:
        raw_pub, raw_sec = signer.generate_keypair()
    except UnsupportedAlgorithmError:
        raise
    except Exception as e:
        raise KeyPairGenerationError(f"Échec de génération PQC ({canonical}) : {e}")

    public_key_pem = _b64_pem(_PQC_PUB_LABEL, _spki_der(canonical, raw_pub))

    if private_key_password:
        private_key_pem = _encrypt_secret_pem(canonical, raw_sec, private_key_password)
        is_protected = True
    else:
        private_key_pem = _b64_pem(_PQC_PRIV_LABEL, _pkcs8_der(canonical, raw_sec))
        is_protected = False

    fp = ":".join(f"{b:02X}" for b in hashlib.sha256(raw_pub).digest())

    return PQCKeyPairResult(
        private_key_pem=private_key_pem,
        public_key_pem=public_key_pem,
        key_algorithm=canonical,
        key_size_or_curve=canonical,
        is_password_protected=is_protected,
        fingerprint_sha256=fp,
        backend=signer.backend,
        is_experimental=bool(signer.meta.get("experimental")),
        raw_public_key=raw_pub,
        raw_secret_key=raw_sec,
    )


# ═════════════════════════════════════════════════════════════════════════════
# createSignedCertPQC — certificat X.509 signé par une CA à clé PQC
# ═════════════════════════════════════════════════════════════════════════════

import re

_RDN_OIDS = {
    "country_code": "2.5.4.6",          # C  (PrintableString)
    "region": "2.5.4.8",                # ST
    "city": "2.5.4.7",                  # L
    "company": "2.5.4.10",              # O
    "department": "2.5.4.11",           # OU
    "common_name": "2.5.4.3",           # CN
    "email": "1.2.840.113549.1.9.1",    # emailAddress (IA5String)
}


def is_valid_email(email: str) -> bool:
    return bool(email and re.match(r"[^@]+@[^@]+\.[^@]+", email))


def _name_der(fields: dict) -> bytes:
    """Encode un X.501 Name (RDNSequence) depuis un dict de composants."""
    rdns = []
    order = ["country_code", "region", "city", "company", "department",
             "common_name", "email"]
    for key in order:
        value = fields.get(key)
        if not value:
            continue
        oid = _RDN_OIDS[key]
        if key == "country_code":
            val = _der_printable(value)
        elif key == "email":
            val = _der_ia5(value)
        else:
            val = _der_utf8(value)
        rdns.append(_der_set(_der_seq(_der_oid(oid), val)))
    return _der_seq(*rdns)


def _san_der(email, alt_names, ip_addresses) -> bytes:
    """SubjectAltName (GeneralNames) : rfc822Name [1], dNSName [2], iPAddress [7]."""
    names = []
    if email:
        names.append(_der_ctx(1, email.encode("ascii"), constructed=False))
    for dns in alt_names or []:
        names.append(_der_ctx(2, dns.encode("ascii"), constructed=False))
    for ip in ip_addresses or []:
        packed = ipaddress.ip_address(ip).packed
        names.append(_der_ctx(7, packed, constructed=False))
    return _der_seq(*names)


def _key_usage_der(*, key_cert_sign=False, crl_sign=False,
                   digital_signature=True, key_encipherment=False) -> bytes:
    """KeyUsage BIT STRING (RFC 5280 §4.2.1.3)."""
    # bit 0 digitalSignature ... bit 5 keyCertSign, bit 6 cRLSign
    bits = [0] * 9
    bits[0] = int(digital_signature)
    bits[2] = int(key_encipherment)
    bits[5] = int(key_cert_sign)
    bits[6] = int(crl_sign)
    # tronquer les zéros de poids faible
    last = max((i for i, b in enumerate(bits) if b), default=0)
    used = bits[:last + 1]
    byte = 0
    for i, b in enumerate(used):
        byte |= b << (7 - i)
    unused = 8 - len(used) if len(used) <= 8 else 0
    return _der_bitstring(bytes([byte]), unused if 0 <= unused < 8 else 0)


def _extension_der(oid: str, critical: bool, value_der: bytes) -> bytes:
    body = _der_oid(oid)
    if critical:
        body += _der_bool(True)
    body += _der_octet(value_der)
    return _der_seq(body)


def _spki_from_any_pem(public_key_pem: bytes) -> bytes:
    """Retourne le SubjectPublicKeyInfo DER à partir d'un PEM PQC ou classique.

    - PEM PQC produit par generateKeyPairPQC -> DER tel quel.
    - PEM classique (RSA/EC/Ed*) -> sérialisé via `cryptography`.
    """
    try:
        _, der = _pem_to_der(public_key_pem, _PQC_PUB_LABEL)
        # Vérifie que c'est bien un SPKI PQC connu (sinon laisse passer en classique)
        algorithm, _raw = load_pqc_public_key_pem(public_key_pem)
        return der
    except Exception:
        pass
    # Fallback classique via cryptography
    from cryptography.hazmat.primitives import serialization
    pub = serialization.load_pem_public_key(public_key_pem)
    return pub.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )


def _ski_from_spki(spki_der: bytes) -> bytes:
    """SubjectKeyIdentifier = SHA-1 du subjectPublicKey BIT STRING (RFC 5280)."""
    _, spki, _ = _read_tlv(spki_der)
    _, _algid, after = _read_tlv(spki)
    _, bitstr, _ = _read_tlv(spki, after)
    raw_pub = bitstr[1:]  # sans l'octet unused-bits
    return hashlib.sha1(raw_pub).digest()


def createSignedCertPQC(
    subject_public_key_pem: bytes,
    pseudo: str,
    company: str,
    department: str,
    city: str,
    region: str,
    country_code: str,
    email: str,
    valid_days: int,
    ca_private_key_pem: bytes,
    ca_subject: dict,
    ca_algorithm: str = "ML-DSA-65",
    ca_key_password: Optional[str] = None,
    ca_public_key_pem: Optional[bytes] = None,
    alt_names: Optional[list] = None,
    ip_addresses: Optional[list] = None,
    ocsp_url: Optional[str] = None,
    ca_issuers_url: Optional[str] = None,
    crl_url: Optional[str] = None,
    is_ca: bool = False,
    path_length: Optional[int] = None,
    serial_number: Optional[int] = None,
) -> bytes:
    """Crée un certificat X.509 (RFC 5280) signé par une CA dont la clé est PQC.

    Comme `cryptography` ne sait pas (encore) signer un certificat avec une clé
    ML-DSA/Falcon/SLH-DSA, le TBSCertificate est encodé en DER par ce module
    puis signé via `PQCSigner`. Le certificat produit est conforme aux drafts
    LAMPS (OID de signature dans le catalogue PQC_ALGORITHMS).

    Args:
        subject_public_key_pem: clé publique du sujet (PEM PQC ou classique).
        pseudo..email: composants du sujet (CN = pseudo).
        valid_days: durée de validité.
        ca_private_key_pem: clé privée PQC de la CA (générée par generateKeyPairPQC).
        ca_subject: dict des composants du nom de la CA (issuer). Clés acceptées :
            common_name, company, department, city, region, country_code, email.
        ca_algorithm: algorithme de la clé CA (canonique ou alias).
        ca_key_password: mot de passe de la clé CA si chiffrée.
        ca_public_key_pem: clé publique de la CA (pour l'AuthorityKeyIdentifier).
        is_ca / path_length: pour émettre un certificat intermédiaire.
        serial_number: numéro de série (aléatoire 64 bits si absent).

    Returns:
        bytes — certificat au format PEM.
    """
    if not pseudo or not company:
        raise ValueError("Les champs 'pseudo' et 'company' sont obligatoires.")
    if not is_valid_email(email):
        raise ValueError("Adresse email invalide.")
    if valid_days <= 0:
        raise ValueError("La durée de validité doit être positive.")

    ca_alg = resolve_pqc_algorithm(ca_algorithm)
    ca_oid = PQC_ALGORITHMS[ca_alg]["oid"]
    signer = PQCSigner(ca_alg)

    # Clé privée CA
    _alg_loaded, ca_secret = load_pqc_private_key_pem(ca_private_key_pem, ca_key_password)

    # SPKI du sujet + de la CA
    subject_spki = _spki_from_any_pem(subject_public_key_pem)
    ca_spki = _spki_from_any_pem(ca_public_key_pem) if ca_public_key_pem else None

    # ── Champs du TBSCertificate ─────────────────────────────────────────────
    serial = serial_number if serial_number is not None else int.from_bytes(os.urandom(8), "big") | 1
    valid_from = datetime.datetime.now(datetime.timezone.utc)
    valid_to = valid_from + datetime.timedelta(days=valid_days)

    subject_name = _name_der({
        "country_code": country_code, "region": region, "city": city,
        "company": company, "department": department,
        "common_name": pseudo, "email": email,
    })
    issuer_name = _name_der(ca_subject)

    # ── Extensions ───────────────────────────────────────────────────────────
    extensions = []

    # BasicConstraints
    if is_ca:
        bc_body = _der_bool(True)
        if path_length is not None:
            bc_body += _der_int(path_length)
        bc = _der_seq(bc_body)
    else:
        bc = _der_seq()  # cA défaut FALSE
    extensions.append(_extension_der("2.5.29.19", True, bc))

    # KeyUsage
    if is_ca:
        ku = _key_usage_der(digital_signature=True, key_cert_sign=True, crl_sign=True)
    else:
        ku = _key_usage_der(digital_signature=True, key_encipherment=False)
    extensions.append(_extension_der("2.5.29.15", True, ku))

    # ExtendedKeyUsage (serverAuth + clientAuth) — uniquement end-entity
    if not is_ca:
        eku = _der_seq(_der_oid("1.3.6.1.5.5.7.3.1"), _der_oid("1.3.6.1.5.5.7.3.2"))
        extensions.append(_extension_der("2.5.29.37", False, eku))

    # SubjectAltName
    san = _san_der(email, alt_names, ip_addresses)
    if len(san) > 2:  # pas seulement un SEQUENCE vide
        extensions.append(_extension_der("2.5.29.17", False, san))

    # SubjectKeyIdentifier
    ski = _ski_from_spki(subject_spki)
    extensions.append(_extension_der("2.5.29.14", False, _der_octet(ski)))

    # AuthorityKeyIdentifier (si clé publique CA fournie)
    if ca_spki is not None:
        aki = _ski_from_spki(ca_spki)
        extensions.append(
            _extension_der("2.5.29.35", False, _der_seq(_der_ctx(0, aki, constructed=False)))
        )

    # AuthorityInfoAccess (OCSP / CA Issuers)
    aia_items = []
    if ocsp_url:
        aia_items.append(_der_seq(_der_oid("1.3.6.1.5.5.7.48.1"),
                                  _der_ctx(6, ocsp_url.encode("ascii"), constructed=False)))
    if ca_issuers_url:
        aia_items.append(_der_seq(_der_oid("1.3.6.1.5.5.7.48.2"),
                                  _der_ctx(6, ca_issuers_url.encode("ascii"), constructed=False)))
    if aia_items:
        extensions.append(_extension_der("1.3.6.1.5.5.7.1.1", False, _der_seq(*aia_items)))

    # CRLDistributionPoints
    if crl_url:
        # DistributionPoint { distributionPoint [0] { fullName [0] { URI [6] } } }
        gn = _der_ctx(6, crl_url.encode("ascii"), constructed=False)
        full_name = _der_ctx(0, gn)              # fullName [0]
        dist_point = _der_ctx(0, full_name)      # distributionPoint [0]
        crldp = _der_seq(_der_seq(dist_point))
        extensions.append(_extension_der("2.5.29.31", False, crldp))

    extensions_der = _der_ctx(3, _der_seq(*extensions))  # [3] EXPLICIT Extensions

    # ── TBSCertificate ───────────────────────────────────────────────────────
    tbs = _der_seq(
        _der_ctx(0, _der_int(2)),                # version [0] v3 (=2)
        _der_int(serial),
        _algid(ca_oid),                          # signature AlgorithmIdentifier
        issuer_name,
        _der_seq(_der_time(valid_from), _der_time(valid_to)),
        subject_name,
        subject_spki,
        extensions_der,
    )

    # ── Signature PQC sur le TBS DER ─────────────────────────────────────────
    try:
        signature = signer.sign(tbs, ca_secret)
    except Exception as e:
        from .exceptions import CertificateSigningError
        raise CertificateSigningError(f"Échec de la signature PQC ({ca_alg}) : {e}")

    certificate = _der_seq(
        tbs,
        _algid(ca_oid),
        _der_bitstring(signature),
    )
    return _b64_pem("CERTIFICATE", certificate)


# ═════════════════════════════════════════════════════════════════════════════
# Implémentation Python native de ML-DSA-65 (Dilithium3) — FALLBACK RECHERCHE
#
#  ⚠  AVERTISSEMENT SÉCURITÉ ⚠
#  Implémentation ÉDUCATIVE / DE RECHERCHE uniquement : non constante en temps,
#  non auditée, NON INTEROPÉRABLE avec liboqs/OpenSSL. NE PAS utiliser en
#  production — installer liboqs-python. Identique au module apps/core/pqc.py
#  de vXtend-PKI (promu ici pour rendre CheetahPKI autonome).
# ═════════════════════════════════════════════════════════════════════════════

class _Dilithium3Native:
    """ML-DSA-65 (Dilithium3) — implémentation Python native, RECHERCHE UNIQUEMENT.

    Suit la structure de l'algorithme ML-DSA (FIPS 204) — ExpandA, ExpandMask,
    SampleInBall, Decompose/HighBits/LowBits, MakeHint/UseHint — avec une
    arithmétique polynomiale scolaire (sans NTT) modulo X^256 + 1.

    Garanties / limites :
      * INTERNE : keygen -> sign -> verify est cohérent (une signature produite
        ici est acceptée ici, une signature falsifiée est rejetée).
      * NON INTEROPÉRABLE : la sérialisation des clés/signatures n'est PAS celle
        de FIPS 204 (encodage lossless maison à 4 octets/coefficient, sans les
        tailles d'octets normatives). Une clé liboqs/OpenSSL n'est donc pas
        vérifiable ici et réciproquement.
      * NON SÛRE : non constante en temps, non auditée. NE PAS utiliser en
        production — installer liboqs-python.
    """

    # Paramètres Dilithium3 (NIST FIPS 204, Table 1)
    Q      = 8380417
    N      = 256
    K      = 6
    L      = 5
    ETA    = 4
    TAU    = 49
    BETA   = 196
    GAMMA1 = 1 << 19
    GAMMA2 = (Q - 1) // 32
    OMEGA  = 55
    D      = 13

    # ── API publique du backend natif ────────────────────────────────────────

    def keygen(self):
        seed = os.urandom(32)
        rho, rho_prime, key = self._expand_seed(seed)
        A = self._expand_A(rho)
        s1, s2 = self._sample_small_polyvec(rho_prime)
        t = self._polyvec_add(self._matrix_vec_mul(A, s1), s2)
        t1, t0 = self._power2round_vec(t)

        pk = self._pack(rho, self._pack_vec(t1))
        tr = self._hash(pk, 32)
        sk = self._pack(rho, key, tr,
                        self._pack_vec(s1), self._pack_vec(s2), self._pack_vec(t0))
        return pk, sk

    def sign(self, message, secret_key):
        rho, key, tr, s1, s2, t0 = self._unpack_sk(secret_key)
        A = self._expand_A(rho)
        mu = self._hash(tr + message, 64)
        rho_pp = self._hash(key + mu, 64)

        kappa = 0
        while True:
            y = self._sample_y(rho_pp, kappa)
            w = self._matrix_vec_mul(A, y)
            w1 = self._high_bits_vec(w)
            c_tilde = self._hash(mu + self._pack_vec(w1), 32)
            c = self._sample_challenge(c_tilde)

            cs1 = self._polyvec_scale(c, s1)
            cs2 = self._polyvec_scale(c, s2)
            z = self._polyvec_add(y, cs1)
            w_minus_cs2 = self._polyvec_sub(w, cs2)
            r0 = self._low_bits_vec(w_minus_cs2)

            if (self._polyvec_max_norm(z) >= self.GAMMA1 - self.BETA or
                    self._polyvec_max_norm(r0) >= self.GAMMA2 - self.BETA):
                kappa += self.L
                continue

            ct0 = self._polyvec_scale(c, t0)
            # h = MakeHint(-c*t0, w - c*s2 + c*t0)
            neg_ct0 = self._polyvec_negate(ct0)
            r_for_hint = self._polyvec_add(w_minus_cs2, ct0)
            h = self._make_hint_vec(neg_ct0, r_for_hint)

            if self._polyvec_max_norm(ct0) >= self.GAMMA2 or self._count_ones(h) > self.OMEGA:
                kappa += self.L
                continue

            return self._pack(c_tilde, self._pack_vec(z), self._pack_hint(h))

    def verify(self, message, signature, public_key):
        try:
            rho, t1_packed = self._unpack(public_key, 2)
            t1 = self._unpack_vec(t1_packed, self.K)
            c_tilde, z_packed, h_packed = self._unpack(signature, 3)
            z = self._unpack_vec(z_packed, self.L)
            h = self._unpack_hint(h_packed)

            if self._polyvec_max_norm(z) >= self.GAMMA1 - self.BETA:
                return False
            if self._count_ones(h) > self.OMEGA:
                return False

            A = self._expand_A(rho)
            tr = self._hash(public_key, 32)
            mu = self._hash(tr + message, 64)
            c = self._sample_challenge(c_tilde)

            Az = self._matrix_vec_mul(A, z)
            ct1_2d = self._polyvec_scale(c, [self._shift_left(p, self.D) for p in t1])
            w_approx = self._polyvec_sub(Az, ct1_2d)
            w1_prime = self._use_hint_vec(h, w_approx)

            return c_tilde == self._hash(mu + self._pack_vec(w1_prime), 32)
        except Exception:
            return False

    # ── Sérialisation lossless (format maison, non normatif) ──────────────────

    @staticmethod
    def _pack(*chunks):
        """Concatène des blocs préfixés de leur longueur (4 octets big-endian)."""
        out = bytearray()
        for ch in chunks:
            out += struct.pack(">I", len(ch))
            out += ch
        return bytes(out)

    @staticmethod
    def _unpack(blob, count):
        chunks, off = [], 0
        for _ in range(count):
            (length,) = struct.unpack(">I", blob[off:off + 4])
            off += 4
            chunks.append(blob[off:off + length])
            off += length
        return chunks

    def _pack_vec(self, vec):
        out = bytearray()
        for poly in vec:
            for coeff in poly:
                out += struct.pack(">i", int(coeff))
        return bytes(out)

    def _unpack_vec(self, data, rows):
        polys, idx = [], 0
        for _ in range(rows):
            poly = []
            for _ in range(self.N):
                (coeff,) = struct.unpack(">i", data[idx:idx + 4])
                idx += 4
                poly.append(coeff)
            polys.append(poly)
        return polys

    def _pack_hint(self, h):
        return self._pack_vec(h)

    def _unpack_hint(self, data):
        return self._unpack_vec(data, self.K)

    def _unpack_sk(self, sk):
        rho, key, tr, s1p, s2p, t0p = self._unpack(sk, 6)
        return (rho, key, tr,
                self._unpack_vec(s1p, self.L),
                self._unpack_vec(s2p, self.K),
                self._unpack_vec(t0p, self.K))

    # ── Primitives mathématiques ──────────────────────────────────────────────

    def _mod_q(self, x):
        return x % self.Q

    def _hash(self, data, length):
        h = hashlib.shake_256()
        h.update(data)
        return h.digest(length)

    def _expand_seed(self, seed):
        e = self._hash(seed, 128)
        return e[:32], e[32:96], e[96:128]

    def _expand_A(self, rho):
        A = []
        for i in range(self.K):
            row = [self._sample_uniform(rho + bytes([j, i])) for j in range(self.L)]
            A.append(row)
        return A

    def _sample_uniform(self, seed):
        stream = self._hash(seed, self.N * 6)
        result, i = [], 0
        while len(result) < self.N and i + 3 <= len(stream):
            val = stream[i] | (stream[i + 1] << 8) | ((stream[i + 2] & 0x7F) << 16)
            i += 3
            if val < self.Q:
                result.append(val)
        while len(result) < self.N:
            result.append(0)
        return result

    def _sample_small_polyvec(self, rho_prime):
        s1 = [self._sample_small(rho_prime + bytes([i])) for i in range(self.L)]
        s2 = [self._sample_small(rho_prime + bytes([self.L + i])) for i in range(self.K)]
        return s1, s2

    def _sample_small(self, seed):
        stream = self._hash(seed, self.N)
        return [self.ETA - (b % (2 * self.ETA + 1)) for b in stream[:self.N]]

    def _sample_y(self, rho_prime, kappa):
        polys = []
        for i in range(self.L):
            stream = self._hash(rho_prime + struct.pack("<H", kappa + i), self.N * 3)
            poly = []
            for j in range(self.N):
                val = stream[3 * j] | (stream[3 * j + 1] << 8) | ((stream[3 * j + 2] & 0x0F) << 16)
                poly.append(val - self.GAMMA1)
            polys.append(poly)
        return polys

    def _sample_challenge(self, c_tilde):
        c = [0] * self.N
        stream = self._hash(c_tilde, 8 + self.N)
        signs = int.from_bytes(stream[:8], "little")
        pos_bytes = stream[8:]
        sign_idx = 0
        # SampleInBall : place tau coefficients ±1 (ML-DSA, FIPS 204 Alg. 23)
        for i in range(self.N - self.TAU, self.N):
            j = pos_bytes[i % len(pos_bytes)] % (i + 1)
            c[i] = c[j]
            c[j] = 1 - 2 * ((signs >> sign_idx) & 1)
            sign_idx = (sign_idx + 1) % 64
        return c

    def _matrix_vec_mul(self, A, v):
        result = []
        for row in A:
            acc = [0] * self.N
            for i, poly in enumerate(row):
                prod = self._poly_mul_mod(poly, v[i])
                acc = [self._mod_q(acc[j] + prod[j]) for j in range(self.N)]
            result.append(acc)
        return result

    def _poly_mul_mod(self, a, b):
        result = [0] * self.N
        for i in range(self.N):
            ai = a[i]
            if ai == 0:
                continue
            for j in range(self.N):
                idx = i + j
                if idx >= self.N:
                    result[idx - self.N] -= ai * b[j]
                else:
                    result[idx] += ai * b[j]
        return [self._mod_q(x) for x in result]

    def _polyvec_add(self, a, b):
        return [[self._mod_q(a[i][j] + b[i][j]) for j in range(self.N)] for i in range(len(a))]

    def _polyvec_sub(self, a, b):
        return [[self._mod_q(a[i][j] - b[i][j]) for j in range(self.N)] for i in range(len(a))]

    def _polyvec_scale(self, c, v):
        return [self._poly_mul_mod(c, poly) for poly in v]

    def _polyvec_negate(self, v):
        return [[self._mod_q(-x) for x in poly] for poly in v]

    def _polyvec_max_norm(self, v):
        m = 0
        for poly in v:
            for x in poly:
                xc = x % self.Q
                val = xc if xc <= self.Q // 2 else self.Q - xc
                if val > m:
                    m = val
        return m

    def _power2round(self, r):
        r = r % self.Q
        r0 = r % (1 << self.D)
        if r0 > (1 << (self.D - 1)):
            r0 -= (1 << self.D)
        return (r - r0) >> self.D, r0

    def _power2round_vec(self, v):
        t1, t0 = [], []
        for poly in v:
            p1, p0 = [], []
            for x in poly:
                r1, r0 = self._power2round(x)
                p1.append(r1)
                p0.append(r0)
            t1.append(p1)
            t0.append(p0)
        return t1, t0

    def _decompose(self, r):
        r = r % self.Q
        alpha = 2 * self.GAMMA2
        r0 = r % alpha
        if r0 > self.GAMMA2:
            r0 -= alpha
        if r - r0 == self.Q - 1:
            return 0, r0 - 1
        return (r - r0) // alpha, r0

    def _high_bits(self, r):
        return self._decompose(r)[0]

    def _low_bits(self, r):
        return self._decompose(r)[1]

    def _high_bits_vec(self, v):
        return [[self._high_bits(x) for x in poly] for poly in v]

    def _low_bits_vec(self, v):
        return [[self._low_bits(x) for x in poly] for poly in v]

    def _make_hint(self, z, r):
        return 0 if self._high_bits(r) == self._high_bits(r + z) else 1

    def _make_hint_vec(self, zv, rv):
        return [[self._make_hint(zv[i][j], rv[i][j]) for j in range(self.N)]
                for i in range(len(rv))]

    def _use_hint(self, hint, r):
        m = (self.Q - 1) // (2 * self.GAMMA2)
        r1, r0 = self._decompose(r)
        if hint == 0:
            return r1
        return (r1 + 1) % m if r0 > 0 else (r1 - 1) % m

    def _use_hint_vec(self, h, v):
        return [[self._use_hint(h[i][j], v[i][j]) for j in range(self.N)]
                for i in range(len(v))]

    def _shift_left(self, poly, d):
        return [(x << d) % self.Q for x in poly]

    def _count_ones(self, h):
        return sum(sum(row) for row in h)
