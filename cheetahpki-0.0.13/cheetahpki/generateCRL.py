"""
Génération de Certificate Revocation List (CRL) conformes RFC 5280.

`generateCRL` construit et signe une CRL à partir :
    - du certificat et de la clé privée de la CA émettrice
    - d'une liste d'entrées de révocation (serial_number, date, raison)

La CRL est écrite dans un fichier PEM (par défaut) et retournée sous forme
de bytes DER pour distribution via un endpoint HTTP.

Utilisation typique depuis l'application Django (chantier 3 — publication CRL) :

    from cheetahpki import generateCRL, CRLRevocationEntry
    entries = [
        CRLRevocationEntry(serial_number=42, revocation_date=some_datetime,
                           reason="key_compromise"),
    ]
    crl_pem_path, crl_der_bytes = generateCRL(
        ca_cert_path="tmp/certs/inter_ca.pem",
        ca_private_key_path="tmp/keys/inter_private_key.pem",
        ca_key_password=None,
        revoked_entries=entries,
        crl_number=7,
        next_update_days=7,
        output_folder="tmp/crl",
        output_filename="inter_ca_crl",
    )
"""

import datetime
import os
from dataclasses import dataclass, field
from typing import Optional

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.asymmetric.ed448 import Ed448PrivateKey

from .exceptions import (
    CertificateFileNotFoundError,
    CertificateLoadError,
    CertificateSaveError,
    CertificateSigningError,
    PrivateKeyFileNotFoundError,
    PrivateKeyLoadError,
)

# Mapping str → x509.ReasonFlags (RFC 5280 §5.3.1)
_REASON_MAP = {
    "unspecified": x509.ReasonFlags.unspecified,
    "key_compromise": x509.ReasonFlags.key_compromise,
    "ca_compromise": x509.ReasonFlags.ca_compromise,
    "affiliation_changed": x509.ReasonFlags.affiliation_changed,
    "superseded": x509.ReasonFlags.superseded,
    "cessation_of_operation": x509.ReasonFlags.cessation_of_operation,
    "certificate_hold": x509.ReasonFlags.certificate_hold,
    "privilege_withdrawn": x509.ReasonFlags.privilege_withdrawn,
    "aa_compromise": x509.ReasonFlags.aa_compromise,
    "remove_from_crl": x509.ReasonFlags.remove_from_crl,
}


@dataclass
class CRLRevocationEntry:
    """Une entrée dans la CRL.

    Attributes:
        serial_number (int): Numéro de série du certificat révoqué (décimal).
        revocation_date (datetime): Date UTC de la révocation.
        reason (str): L'une des clés de _REASON_MAP ("key_compromise", ...).
            Défaut : "unspecified".
    """

    serial_number: int
    revocation_date: datetime.datetime
    reason: str = "unspecified"


def _signing_hash(private_key):
    """SHA-256 pour RSA/EC, None pour Ed25519/Ed448."""
    if isinstance(private_key, (Ed25519PrivateKey, Ed448PrivateKey)):
        return None
    return hashes.SHA256()


def generateCRL(
    ca_cert_path: str,
    ca_private_key_path: str,
    revoked_entries: list,
    crl_number: int,
    next_update_days: int = 7,
    ca_key_password: str = None,
    output_folder: str = "crl",
    output_filename: str = None,
):
    """
    Génère une CRL signée par la CA fournie et retourne son chemin ainsi que son
    contenu DER.

    Args:
        ca_cert_path (str): Chemin vers le certificat PEM de la CA.
        ca_private_key_path (str): Chemin vers la clé privée PEM de la CA.
        revoked_entries (list[CRLRevocationEntry]): Liste des certificats
            révoqués à inclure dans la CRL.
        crl_number (int): Numéro de la CRL (extension CRLNumber). Doit être
            strictement croissant à chaque nouvelle émission.
        next_update_days (int, optional): Nombre de jours avant prochaine mise
            à jour de la CRL. Défaut : 7.
        ca_key_password (str, optional): Mot de passe de la clé privée de la CA.
        output_folder (str, optional): Dossier de sortie. Défaut : "crl".
        output_filename (str, optional): Nom du fichier sans extension.
            Défaut : "crl_<crl_number>".

    Returns:
        tuple: (crl_pem_path: str, crl_der_bytes: bytes)
            - crl_pem_path : chemin du fichier PEM écrit sur disque
            - crl_der_bytes : contenu DER (utile pour exposition HTTP avec
              Content-Type: application/pkix-crl)

    Raises:
        CertificateFileNotFoundError: Si le certificat de la CA est introuvable.
        CertificateLoadError: Si le certificat de la CA ne peut être chargé.
        PrivateKeyFileNotFoundError: Si la clé privée de la CA est introuvable.
        PrivateKeyLoadError: Si la clé privée de la CA ne peut être chargée.
        CertificateSigningError: Si la signature de la CRL échoue.
        CertificateSaveError: Si l'écriture de la CRL échoue.
    """
    # 1. Charger le certificat de la CA
    try:
        with open(ca_cert_path, "rb") as f:
            ca_cert = x509.load_pem_x509_certificate(f.read(), default_backend())
    except FileNotFoundError:
        raise CertificateFileNotFoundError(f"Certificat CA introuvable : {ca_cert_path}")
    except Exception as e:
        raise CertificateLoadError(f"Impossible de charger le certificat CA ({ca_cert_path}) : {e}")

    # 2. Charger la clé privée de la CA
    try:
        with open(ca_private_key_path, "rb") as f:
            ca_private_key = serialization.load_pem_private_key(
                f.read(),
                password=ca_key_password.encode() if ca_key_password else None,
                backend=default_backend(),
            )
    except FileNotFoundError:
        raise PrivateKeyFileNotFoundError(
            f"Clé privée CA introuvable : {ca_private_key_path}"
        )
    except Exception as e:
        raise PrivateKeyLoadError(
            f"Impossible de charger la clé privée CA ({ca_private_key_path}) : {e}"
        )

    # 3. Construire la CRL
    now = datetime.datetime.now(datetime.timezone.utc)
    next_update = now + datetime.timedelta(days=next_update_days)

    builder = (
        x509.CertificateRevocationListBuilder()
        .issuer_name(ca_cert.subject)
        .last_update(now)
        .next_update(next_update)
    )

    for entry in revoked_entries:
        if not isinstance(entry, CRLRevocationEntry):
            raise TypeError(
                "revoked_entries doit contenir uniquement des CRLRevocationEntry"
            )

        revocation_date = entry.revocation_date
        if revocation_date.tzinfo is None:
            revocation_date = revocation_date.replace(tzinfo=datetime.timezone.utc)

        reason = _REASON_MAP.get(entry.reason, x509.ReasonFlags.unspecified)

        revoked_cert = (
            x509.RevokedCertificateBuilder()
            .serial_number(entry.serial_number)
            .revocation_date(revocation_date)
            .add_extension(x509.CRLReason(reason), critical=False)
            .build(default_backend())
        )
        builder = builder.add_revoked_certificate(revoked_cert)

    # Extensions au niveau CRL : CRLNumber + AuthorityKeyIdentifier
    builder = builder.add_extension(
        x509.CRLNumber(crl_number), critical=False,
    ).add_extension(
        x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_private_key.public_key()),
        critical=False,
    )

    # 4. Signer la CRL
    try:
        crl = builder.sign(
            private_key=ca_private_key,
            algorithm=_signing_hash(ca_private_key),
            backend=default_backend(),
        )
    except Exception as e:
        raise CertificateSigningError(f"Erreur lors de la signature de la CRL : {e}")

    # 5. Écrire sur disque (PEM) et préparer la sortie DER
    output_filename = output_filename or f"crl_{crl_number}.pem"
    if not output_filename.endswith(".pem"):
        output_filename += ".pem"

    try:
        os.makedirs(output_folder, exist_ok=True)
    except OSError as e:
        raise CertificateSaveError(
            f"Impossible de créer le dossier de sortie ({output_folder}) : {e}"
        )

    output_path = os.path.join(output_folder, output_filename)
    try:
        pem_bytes = crl.public_bytes(serialization.Encoding.PEM)
        der_bytes = crl.public_bytes(serialization.Encoding.DER)
        with open(output_path, "wb") as f:
            f.write(pem_bytes)
    except Exception as e:
        raise CertificateSaveError(f"Impossible d'écrire la CRL ({output_path}) : {e}")

    return output_path, der_bytes
