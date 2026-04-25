import os
import ipaddress
from cryptography import x509
from cryptography.x509.oid import NameOID, AuthorityInformationAccessOID
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.asymmetric.ed448 import Ed448PrivateKey
import datetime
import re

from .exceptions import (
    PublicKeyFileNotFoundError,
    PublicKeyLoadError,
    PrivateKeyFileNotFoundError,
    PrivateKeyLoadError,
    CertificateLoadError,
    CertificateSaveError,
)


_HASH_ALIASES = {
    'sha256': hashes.SHA256,
    'sha-256': hashes.SHA256,
    'sha384': hashes.SHA384,
    'sha-384': hashes.SHA384,
    'sha512': hashes.SHA512,
    'sha-512': hashes.SHA512,
}


def _resolve_hash(name):
    if not name:
        return hashes.SHA256()
    key = name.strip().lower()
    if key not in _HASH_ALIASES:
        raise ValueError(
            f"Algorithme de hash non supporté : {name!r} "
            f"(acceptés : {', '.join(sorted(_HASH_ALIASES))})"
        )
    return _HASH_ALIASES[key]()


def _signing_hash(private_key, signature_hash: str = None):
    if isinstance(private_key, (Ed25519PrivateKey, Ed448PrivateKey)):
        return None
    return _resolve_hash(signature_hash)


def is_valid_email(email):
    return re.match(r"[^@]+@[^@]+\.[^@]+", email)


def createSignedInterCertFromBytes(
    public_key_pem: bytes,
    pseudo: str,
    company: str,
    department: str,
    city: str,
    region: str,
    country_code: str,
    email: str,
    valid_days: int,
    ca_private_key_pem: bytes,
    ca_cert_pem: bytes,
    ca_key_password: str = None,
    alt_names: list = None,
    ip_addresses: list = None,
    ocsp_url: str = None,
    ca_issuers_url: str = None,
    crl_url: str = None,
    signature_hash: str = None,
) -> bytes:
    """
    Crée un certificat de CA intermédiaire signé par la CA root et renvoie
    ses bytes PEM (sans accès filesystem).
    """
    if not pseudo or not company:
        raise ValueError("Les champs 'pseudo' et 'company' sont obligatoires.")
    if not is_valid_email(email):
        raise ValueError("Adresse email invalide.")
    if valid_days <= 0:
        raise ValueError("La durée de validité doit être positive.")

    try:
        public_key = serialization.load_pem_public_key(public_key_pem, backend=default_backend())
    except Exception as e:
        raise PublicKeyLoadError(f"Erreur lors du chargement de la clé publique : {e}")

    try:
        ca_cert = x509.load_pem_x509_certificate(ca_cert_pem, backend=default_backend())
    except Exception as e:
        raise CertificateLoadError(f"Erreur lors du chargement du certificat de la CA : {e}")

    try:
        ca_private_key = serialization.load_pem_private_key(
            ca_private_key_pem,
            password=ca_key_password.encode() if ca_key_password else None,
            backend=default_backend(),
        )
    except Exception as e:
        raise PrivateKeyLoadError(f"Erreur lors du chargement de la clé privée de la CA : {e}")

    subject = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, country_code),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, region),
        x509.NameAttribute(NameOID.LOCALITY_NAME, city),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, company),
        x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, department),
        x509.NameAttribute(NameOID.COMMON_NAME, pseudo),
        x509.NameAttribute(NameOID.EMAIL_ADDRESS, email),
    ])

    valid_from = datetime.datetime.now(datetime.UTC)
    valid_to = valid_from + datetime.timedelta(days=valid_days)

    extensions = [
        x509.BasicConstraints(ca=True, path_length=0),
        x509.KeyUsage(
            digital_signature=True, key_cert_sign=True, crl_sign=True,
            key_encipherment=False, data_encipherment=False,
            content_commitment=False, key_agreement=False,
            encipher_only=False, decipher_only=False,
        ),
        x509.ExtendedKeyUsage([
            x509.oid.ExtendedKeyUsageOID.SERVER_AUTH,
            x509.oid.ExtendedKeyUsageOID.CLIENT_AUTH,
        ]),
        x509.SubjectAlternativeName(
            [x509.RFC822Name(email)]
            + [x509.DNSName(name) for name in alt_names or []]
            + [x509.IPAddress(ipaddress.ip_address(ip)) for ip in ip_addresses or []]
        ),
        x509.SubjectKeyIdentifier.from_public_key(public_key),
        x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_private_key.public_key()),
    ]

    aia_descriptions = []
    if ocsp_url:
        aia_descriptions.append(x509.AccessDescription(
            AuthorityInformationAccessOID.OCSP,
            x509.UniformResourceIdentifier(ocsp_url),
        ))
    if ca_issuers_url:
        aia_descriptions.append(x509.AccessDescription(
            AuthorityInformationAccessOID.CA_ISSUERS,
            x509.UniformResourceIdentifier(ca_issuers_url),
        ))
    if aia_descriptions:
        extensions.append(x509.AuthorityInformationAccess(aia_descriptions))

    if crl_url:
        extensions.append(x509.CRLDistributionPoints([
            x509.DistributionPoint(
                full_name=[x509.UniformResourceIdentifier(crl_url)],
                relative_name=None, reasons=None, crl_issuer=None,
            )
        ]))

    builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(ca_cert.subject)
        .public_key(public_key)
        .serial_number(x509.random_serial_number())
        .not_valid_before(valid_from)
        .not_valid_after(valid_to)
    )
    for ext in extensions:
        builder = builder.add_extension(ext, critical=False)

    certificate = builder.sign(
        private_key=ca_private_key,
        algorithm=_signing_hash(ca_private_key, signature_hash),
        backend=default_backend(),
    )
    return certificate.public_bytes(serialization.Encoding.PEM)


def createSignedInterCert(
    public_key_path: str,
    pseudo: str,
    company: str,
    department: str,
    city: str,
    region: str,
    country_code: str,
    email: str,
    valid_days: int,
    ca_private_key_path: str,
    ca_cert_path: str,
    ca_key_password: str = None,
    alt_names: list = None,
    ip_addresses: list = None,
    output_folder: str = "certificate",
    output_filename: str = None,
    ocsp_url: str = None,
    ca_issuers_url: str = None,
    crl_url: str = None,
    signature_hash: str = None,
):
    """
    Variante filesystem : lit les PEM depuis des fichiers, écrit le certificat
    intermédiaire signé sur disque et retourne son chemin.
    Pour une exécution 100% en mémoire, voir `createSignedInterCertFromBytes`.
    """
    public_key_path = os.path.abspath(public_key_path)
    ca_private_key_path = os.path.abspath(ca_private_key_path)
    ca_cert_path = os.path.abspath(ca_cert_path)
    output_folder = os.path.abspath(output_folder)

    try:
        with open(public_key_path, "rb") as f:
            public_key_pem = f.read()
    except FileNotFoundError:
        raise PublicKeyFileNotFoundError(
            f"Le fichier de clé publique est introuvable : {public_key_path}"
        )

    try:
        with open(ca_cert_path, "rb") as f:
            ca_cert_pem = f.read()
    except FileNotFoundError:
        raise CertificateLoadError(
            f"Le fichier de certificat de la CA intermédiaire est introuvable : {ca_cert_path}"
        )

    try:
        with open(ca_private_key_path, "rb") as f:
            ca_private_key_pem = f.read()
    except FileNotFoundError:
        raise PrivateKeyFileNotFoundError(
            f"Le fichier de clé privée de la CA intermédiaire est introuvable : {ca_private_key_path}"
        )

    cert_pem = createSignedInterCertFromBytes(
        public_key_pem=public_key_pem,
        pseudo=pseudo,
        company=company,
        department=department,
        city=city,
        region=region,
        country_code=country_code,
        email=email,
        valid_days=valid_days,
        ca_private_key_pem=ca_private_key_pem,
        ca_cert_pem=ca_cert_pem,
        ca_key_password=ca_key_password,
        alt_names=alt_names,
        ip_addresses=ip_addresses,
        ocsp_url=ocsp_url,
        ca_issuers_url=ca_issuers_url,
        crl_url=crl_url,
        signature_hash=signature_hash,
    )

    output_filename = output_filename or f"{pseudo}_certificate.pem"
    if not output_filename.endswith(".pem"):
        output_filename += ".pem"
    output_path = os.path.join(output_folder, output_filename)

    try:
        os.makedirs(output_folder, exist_ok=True)
        with open(output_path, "wb") as f:
            f.write(cert_pem)
    except Exception as e:
        raise CertificateSaveError(
            f"Erreur lors de l'enregistrement du certificat ({output_path}) : {e}"
        )

    return output_path
