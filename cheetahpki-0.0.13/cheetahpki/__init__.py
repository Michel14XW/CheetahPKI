from .checkCertValidity import checkCertValidity
from .createSelfSignedRootCert import is_valid_email, createSelfSignedRootCert
from .createSignedCert import is_valid_email, createSignedCert
from .getCertInfo import get_serial_number
from .getCertInfo import get_owner
from .getCertInfo import get_validity_end
from .getCertInfo import get_validity_start
from .getCertificateInfo import getCertificateInfo
from .exceptions import (
    CertificateError,
    CertificateFileNotFoundError,
    CertificateFileEmptyError,
    CertificateLoadError,
    CertificateSaveError,
    CertificateSigningError,
    InvalidCertificateError,
    CertificateDateError,
    PrivateKeyFileNotFoundError,
    PublicKeyFileNotFoundError,
    PrivateKeyLoadError,
    PublicKeyLoadError,
    InvalidKeySizeError,
    KeyPairGenerationError,
    KeySaveError,
    DirectoryCreationError,
    UnsupportedAlgorithmError,
)
from .generateKeyPair import generateKeyPair, generateKeyPairBytes
from .fingerprint import getCertificateFingerprint
from .fingerprint import getPublicKeyFingerprint
from .createSignedInterCert import createSignedInterCert
from .generateCsr import generateCsr
from .parseCsr import parseCsr
from .generateCRL import generateCRL, CRLRevocationEntry

__version__ = "0.0.13"
VERSION = __version__.split(".")

# ---------------------------------------------------------------------------
# Constantes publiques — algorithmes et courbes supportés
# Importables directement : from cheetahpki import SUPPORTED_ALGORITHMS
# ---------------------------------------------------------------------------
SUPPORTED_ALGORITHMS = ("RSA", "EC", "Ed25519", "Ed448")
SUPPORTED_CURVES = ("P-256", "P-384", "P-521")   # uniquement pour algorithm="EC"

# Raisons de révocation supportées (RFC 5280 §5.3.1). Exposées pour que les
# applications Django puissent les utiliser comme choix dans leurs modèles.
SUPPORTED_REVOCATION_REASONS = (
    "unspecified",
    "key_compromise",
    "ca_compromise",
    "affiliation_changed",
    "superseded",
    "cessation_of_operation",
    "certificate_hold",
    "privilege_withdrawn",
    "aa_compromise",
    "remove_from_crl",
)

__all__ = (
    # Fonctions de génération de clés
    'generateKeyPair',         # Écrit sur le filesystem (FileField / stockage local)
    'generateKeyPairBytes',    # Retourne des bytes PEM en mémoire (Vault / stockage sécurisé)
    'SUPPORTED_ALGORITHMS',
    'SUPPORTED_CURVES',
    'SUPPORTED_REVOCATION_REASONS',
    # Fonctions de création de certificats
    'createSelfSignedRootCert',
    'createSignedCert',
    'createSignedInterCert',
    # Fonctions CSR
    'generateCsr',
    'parseCsr',
    # Fonctions d'info et de validité
    'checkCertValidity',
    'is_valid_email',
    'get_owner',
    'get_serial_number',
    'get_validity_start',
    'get_validity_end',
    'getCertificateFingerprint',
    'getPublicKeyFingerprint',
    'getCertificateInfo',     # Nouveau (0.0.13) — extraction consolidée
    # CRL
    'generateCRL',            # Nouveau (0.0.13)
    'CRLRevocationEntry',     # Nouveau (0.0.13)
    # Exceptions
    'CertificateError',
    'CertificateFileNotFoundError',
    'CertificateFileEmptyError',
    'CertificateLoadError',
    'CertificateSaveError',
    'CertificateSigningError',
    'InvalidCertificateError',
    'CertificateDateError',
    'PrivateKeyFileNotFoundError',
    'PublicKeyFileNotFoundError',
    'PrivateKeyLoadError',
    'PublicKeyLoadError',
    'InvalidKeySizeError',
    'KeyPairGenerationError',
    'KeySaveError',
    'DirectoryCreationError',
    'UnsupportedAlgorithmError',
)
