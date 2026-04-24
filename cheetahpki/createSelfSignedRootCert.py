import os
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.asymmetric.ed448 import Ed448PrivateKey
import datetime
import uuid
import re

from .exceptions import (
    PrivateKeyFileNotFoundError,
    PrivateKeyLoadError,
    CertificateSaveError,
)


def _signing_hash(private_key):
    if isinstance(private_key, (Ed25519PrivateKey, Ed448PrivateKey)):
        return None
    return hashes.SHA256()


def is_valid_email(email):
    return re.match(r"[^@]+@[^@]+\.[^@]+", email)


def _validate_root_inputs(pseudo, company, email, valid_days):
    if not pseudo or not company:
        raise ValueError("Les champs 'pseudo' et 'company' sont obligatoires.")
    if not is_valid_email(email):
        raise ValueError("Adresse email invalide.")
    if valid_days <= 0:
        raise ValueError("La durée de validité doit être positive.")


def createSelfSignedRootCertFromBytes(
    pseudo: str,
    company: str,
    city: str,
    region: str,
    country_code: str,
    email: str,
    valid_days: int,
    private_key_pem: bytes,
    key_password: str = None,
) -> bytes:
    """
    Crée un certificat auto-signé pour une CA root et renvoie ses bytes PEM
    (aucun accès filesystem pour la clé privée ni pour le certificat).

    Args:
        pseudo, company, city, region, country_code, email, valid_days : identiques à createSelfSignedRootCert.
        private_key_pem (bytes): Contenu PEM de la clé privée.
        key_password (str, optional): Mot de passe pour déchiffrer la clé privée.

    Returns:
        bytes: Certificat au format PEM.
    """
    _validate_root_inputs(pseudo, company, email, valid_days)

    try:
        private_key = serialization.load_pem_private_key(
            private_key_pem,
            password=key_password.encode() if key_password else None,
            backend=default_backend(),
        )
    except (ValueError, TypeError) as e:
        raise PrivateKeyLoadError(f"Échec du chargement de la clé privée : {e}")

    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, country_code),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, region),
        x509.NameAttribute(NameOID.LOCALITY_NAME, city),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, company),
        x509.NameAttribute(NameOID.COMMON_NAME, pseudo),
        x509.NameAttribute(NameOID.EMAIL_ADDRESS, email),
    ])

    valid_from = datetime.datetime.now(datetime.UTC)
    valid_to = valid_from + datetime.timedelta(days=valid_days)

    certificate = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(valid_from)
        .not_valid_after(valid_to)
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True, key_cert_sign=True, crl_sign=True,
                key_encipherment=False, data_encipherment=False,
                content_commitment=False, key_agreement=False,
                encipher_only=False, decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(private_key.public_key()),
            critical=False,
        )
        .sign(
            private_key=private_key,
            algorithm=_signing_hash(private_key),
            backend=default_backend(),
        )
    )

    return certificate.public_bytes(serialization.Encoding.PEM)


def createSelfSignedRootCert(
    pseudo: str,
    company: str,
    city: str,
    region: str,
    country_code: str,
    email: str,
    valid_days: int,
    private_key_path: str,
    key_password: str = None,
    output_folder: str = None,
    output_filename: str = None,
):
    """
    Crée un certificat auto-signé pour une CA root sans champ département.
    Écrit le certificat sur le filesystem et retourne son chemin.

    Pour une variante sans filesystem, voir `createSelfSignedRootCertFromBytes`.
    """
    private_key_path = os.path.abspath(private_key_path)
    try:
        with open(private_key_path, "rb") as private_key_file:
            private_key_pem = private_key_file.read()
    except FileNotFoundError:
        raise PrivateKeyFileNotFoundError(
            f"Le fichier de clé privée est introuvable au chemin spécifié : {private_key_path}"
        )

    cert_pem = createSelfSignedRootCertFromBytes(
        pseudo=pseudo,
        company=company,
        city=city,
        region=region,
        country_code=country_code,
        email=email,
        valid_days=valid_days,
        private_key_pem=private_key_pem,
        key_password=key_password,
    )

    output_folder = output_folder or "certificate"
    os.makedirs(output_folder, exist_ok=True)

    if not output_filename:
        output_filename = f"root_ca_certificate_{uuid.uuid4()}"
    if not output_filename.endswith(".pem"):
        output_filename += ".pem"

    cert_filename = os.path.join(output_folder, output_filename)
    try:
        with open(cert_filename, "wb") as cert_file:
            cert_file.write(cert_pem)
    except OSError as e:
        raise CertificateSaveError(f"Échec de l'enregistrement du certificat : {e}")

    return cert_filename
