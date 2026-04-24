from cryptography import x509
from cryptography.hazmat.backends import default_backend


def _load_cert(cert_pem: bytes):
    return x509.load_pem_x509_certificate(cert_pem, default_backend())


def _read_path(cert_pem_path: str) -> bytes:
    with open(cert_pem_path, "rb") as cert_file:
        return cert_file.read()


# ---------------------------------------------------------------------------
# Variantes bytes (pas d'accès filesystem) — à privilégier avec Vault
# ---------------------------------------------------------------------------

def get_owner_from_bytes(cert_pem: bytes) -> str:
    """Retourne le CN (Common Name) d'un certificat PEM reçu en mémoire."""
    cert = _load_cert(cert_pem)
    return cert.subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)[0].value


def get_serial_number_from_bytes(cert_pem: bytes) -> int:
    """Retourne le numéro de série d'un certificat PEM reçu en mémoire."""
    return _load_cert(cert_pem).serial_number


def get_validity_end_from_bytes(cert_pem: bytes):
    """Retourne la date de fin de validité (datetime UTC) d'un certificat PEM en mémoire."""
    return _load_cert(cert_pem).not_valid_after_utc


def get_validity_start_from_bytes(cert_pem: bytes):
    """Retourne la date de début de validité (datetime UTC) d'un certificat PEM en mémoire."""
    return _load_cert(cert_pem).not_valid_before_utc


# ---------------------------------------------------------------------------
# Variantes legacy basées sur un chemin — conservées pour compat.
# ---------------------------------------------------------------------------

def get_owner(cert_pem_path: str) -> str:
    """Prend un chemin PEM et retourne le Common Name du sujet."""
    return get_owner_from_bytes(_read_path(cert_pem_path))


def get_serial_number(cert_pem_path: str) -> int:
    """Prend un chemin PEM et retourne le numéro de série."""
    return get_serial_number_from_bytes(_read_path(cert_pem_path))


def get_validity_end(cert_pem_path: str):
    """Prend un chemin PEM et retourne la date de fin de validité (UTC)."""
    return get_validity_end_from_bytes(_read_path(cert_pem_path))


def get_validity_start(cert_pem_path: str):
    """Prend un chemin PEM et retourne la date de début de validité (UTC)."""
    return get_validity_start_from_bytes(_read_path(cert_pem_path))
