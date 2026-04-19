from .checkCertValidity import checkCertValidity #TODO Renommer les autres fonction en nom_propre ainsi que les fichiers
from .createSelfSignedRootCert import is_valid_email, createSelfSignedRootCert
from .createSignedCert import is_valid_email, createSignedCert
from .getCertInfo import get_serial_number #TODO faire ressortir la hierarchie
from .getCertInfo import get_owner
from .getCertInfo import get_validity_end
from .getCertInfo import get_validity_start
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
from .generateKeyPair import generateKeyPair
from .fingerprint import getCertificateFingerprint
from .fingerprint import getPublicKeyFingerprint
from .createSignedInterCert import createSignedInterCert
from .generateCsr import generateCsr
from .parseCsr import parseCsr

__version__ = "0.0.12"
VERSION = __version__.split(".")

__all__ = (
    'checkCertValidity',
    'is_valid_email',
    'createSelfSignedRootCert',
    'createSignedCert',
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
    'generateKeyPair',
    'get_owner',
    'get_serial_number',
    'get_validity_start',
    'get_validity_end',
    'getCertificateFingerprint',
    'getPublicKeyFingerprint',
    'createSignedInterCert',
    'generateCsr',
    'parseCsr',
)

# update version 0.0.9