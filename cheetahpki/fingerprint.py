from cryptography.hazmat.primitives import hashes
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.serialization import load_pem_public_key


def _format_fingerprint(digest: bytes) -> str:
    return ":".join(f"{byte:02X}" for byte in digest)


def getPublicKeyFingerprintFromBytes(public_key_pem: bytes) -> str:
    """
    Calcule l'empreinte SHA-256 d'une clé publique PEM reçue en mémoire
    (aucun accès filesystem).

    Args:
        public_key_pem (bytes): Contenu PEM de la clé publique.

    Returns:
        str: Empreinte SHA-256 au format hex-majuscules séparé par ":".
    """
    public_key = load_pem_public_key(public_key_pem)
    public_key_der = public_key.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    digest = hashes.Hash(hashes.SHA256())
    digest.update(public_key_der)
    return _format_fingerprint(digest.finalize())


def getPublicKeyFingerprint(public_key_pem_path: str) -> str:
    """
    Calcule l'empreinte SHA-256 d'une clé publique au format PEM.

    Args:
        public_key_pem_path (str): Chemin de la clé publique au format PEM.

    Returns:
        str: Empreinte SHA-256 de la clé publique.
    """
    with open(public_key_pem_path, "rb") as file:
        public_key_pem = file.read()
    return getPublicKeyFingerprintFromBytes(public_key_pem)


def getCertificateFingerprintFromBytes(certificate_pem: bytes) -> str:
    """
    Calcule l'empreinte SHA-256 d'un certificat PEM reçu en mémoire.

    Args:
        certificate_pem (bytes): Contenu PEM du certificat.

    Returns:
        str: Empreinte SHA-256 au format hex-majuscules séparé par ":".
    """
    certificate = x509.load_pem_x509_certificate(certificate_pem)
    return _format_fingerprint(certificate.fingerprint(hashes.SHA256()))


def getCertificateFingerprint(certificate_pem_path: str) -> str:
    """
    Calcule l'empreinte SHA-256 d'un certificat au format PEM.

    Args:
        certificate_pem_path (str): Chemin du certificat au format PEM.

    Returns:
        str: Empreinte SHA-256 du certificat.
    """
    with open(certificate_pem_path, "rb") as file:
        certificate_pem = file.read()
    return getCertificateFingerprintFromBytes(certificate_pem)
