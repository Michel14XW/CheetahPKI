from .checkCertValidity import checkCertValidity
from .createSelfSignedRootCert import (
    is_valid_email,
    createSelfSignedRootCert,
    createSelfSignedRootCertFromBytes,
)
from .createSignedCert import (
    is_valid_email,
    createSignedCert,
    createSignedCertFromBytes,
)
from .getCertInfo import (
    get_serial_number,
    get_serial_number_from_bytes,
    get_owner,
    get_owner_from_bytes,
    get_validity_end,
    get_validity_end_from_bytes,
    get_validity_start,
    get_validity_start_from_bytes,
)
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
from .fingerprint import (
    getCertificateFingerprint,
    getCertificateFingerprintFromBytes,
    getPublicKeyFingerprint,
    getPublicKeyFingerprintFromBytes,
)
from .createSignedInterCert import createSignedInterCert, createSignedInterCertFromBytes
from .generateCsr import generateCsr
from .parseCsr import parseCsr
from .generateCRL import generateCRL, CRLRevocationEntry

__version__ = "0.0.14"
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
    # Génération de clés
    'generateKeyPair',
    'generateKeyPairBytes',
    'SUPPORTED_ALGORITHMS',
    'SUPPORTED_CURVES',
    'SUPPORTED_REVOCATION_REASONS',
    # Création de certificats — variantes filesystem
    'createSelfSignedRootCert',
    'createSignedCert',
    'createSignedInterCert',
    # Création de certificats — variantes bytes (Vault / mémoire)
    'createSelfSignedRootCertFromBytes',
    'createSignedCertFromBytes',
    'createSignedInterCertFromBytes',
    # CSR
    'generateCsr',
    'parseCsr',
    # Info et validité
    'checkCertValidity',
    'is_valid_email',
    'get_owner',
    'get_owner_from_bytes',
    'get_serial_number',
    'get_serial_number_from_bytes',
    'get_validity_start',
    'get_validity_start_from_bytes',
    'get_validity_end',
    'get_validity_end_from_bytes',
    'getCertificateFingerprint',
    'getCertificateFingerprintFromBytes',
    'getPublicKeyFingerprint',
    'getPublicKeyFingerprintFromBytes',
    'getCertificateInfo',
    # CRL
    'generateCRL',
    'CRLRevocationEntry',
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
