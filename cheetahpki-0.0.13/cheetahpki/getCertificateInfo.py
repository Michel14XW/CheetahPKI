"""
Extraction consolidée des métadonnées d'un certificat X.509.

Expose `getCertificateInfo(cert_pem_path)` qui renvoie un dictionnaire complet
couvrant :
    - identité (CN, DN complet, émetteur, numéro de série)
    - validité (not_before, not_after, jours restants)
    - clé publique (algorithme, taille RSA, courbe EC, empreinte SHA-256)
    - signature (algorithme, empreinte SHA-256 du certificat)
    - extensions (SAN, AIA/OCSP, CRL DP, AKI, SKI, BasicConstraints, KeyUsage)

Cette fonction est conçue pour alimenter directement les champs d'un modèle
Django `Certificate` (common_name, subject_dn, fingerprint_sha256,
key_algorithm, key_size_or_curve, signature_algorithm, validity_start/end, ...)
après l'émission d'un certificat.
"""

from datetime import datetime, timezone

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey
from cryptography.hazmat.primitives.asymmetric.ec import EllipticCurvePublicKey
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.hazmat.primitives.asymmetric.ed448 import Ed448PublicKey

from .exceptions import (
    CertificateFileNotFoundError,
    CertificateFileEmptyError,
    CertificateLoadError,
)


def _key_algorithm_and_size(public_key):
    """Retourne (algorithm: str, size_or_curve: str) d'une clé publique."""
    if isinstance(public_key, RSAPublicKey):
        return "RSA", str(public_key.key_size)
    if isinstance(public_key, EllipticCurvePublicKey):
        return "EC", public_key.curve.name  # ex: "secp256r1"
    if isinstance(public_key, Ed25519PublicKey):
        return "Ed25519", "256"
    if isinstance(public_key, Ed448PublicKey):
        return "Ed448", "448"
    return "UNKNOWN", ""


def _format_hex_fingerprint(raw: bytes) -> str:
    """Formate un hash brut en 'AA:BB:CC:...' majuscule."""
    return ":".join(f"{b:02X}" for b in raw)


def _extract_san(cert) -> dict:
    """Extrait Subject Alternative Name en listes DNS/IP/email."""
    try:
        san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
    except x509.ExtensionNotFound:
        return {"dns": [], "ip": [], "email": []}
    return {
        "dns": [v.value for v in san.get_values_for_type(x509.DNSName)],
        "ip": [str(v) for v in san.get_values_for_type(x509.IPAddress)],
        "email": [v for v in san.get_values_for_type(x509.RFC822Name)],
    }


def _extract_aia(cert) -> dict:
    """Extrait les URLs OCSP et CA issuers de l'extension AIA."""
    try:
        aia = cert.extensions.get_extension_for_class(x509.AuthorityInformationAccess).value
    except x509.ExtensionNotFound:
        return {"ocsp_urls": [], "ca_issuers_urls": []}

    ocsp_urls, issuers_urls = [], []
    for desc in aia:
        uri = desc.access_location
        if not isinstance(uri, x509.UniformResourceIdentifier):
            continue
        if desc.access_method == x509.AuthorityInformationAccessOID.OCSP:
            ocsp_urls.append(uri.value)
        elif desc.access_method == x509.AuthorityInformationAccessOID.CA_ISSUERS:
            issuers_urls.append(uri.value)
    return {"ocsp_urls": ocsp_urls, "ca_issuers_urls": issuers_urls}


def _extract_crl_dp(cert) -> list:
    """Extrait les URLs des CRL Distribution Points."""
    try:
        crl_dp = cert.extensions.get_extension_for_class(x509.CRLDistributionPoints).value
    except x509.ExtensionNotFound:
        return []

    urls = []
    for dp in crl_dp:
        if dp.full_name:
            for name in dp.full_name:
                if isinstance(name, x509.UniformResourceIdentifier):
                    urls.append(name.value)
    return urls


def _extract_basic_constraints(cert) -> dict:
    try:
        bc = cert.extensions.get_extension_for_class(x509.BasicConstraints).value
    except x509.ExtensionNotFound:
        return {"ca": False, "path_length": None}
    return {"ca": bc.ca, "path_length": bc.path_length}


def _extract_key_usage(cert) -> dict:
    try:
        ku = cert.extensions.get_extension_for_class(x509.KeyUsage).value
    except x509.ExtensionNotFound:
        return {}
    usages = {
        "digital_signature": ku.digital_signature,
        "content_commitment": ku.content_commitment,
        "key_encipherment": ku.key_encipherment,
        "data_encipherment": ku.data_encipherment,
        "key_agreement": ku.key_agreement,
        "key_cert_sign": ku.key_cert_sign,
        "crl_sign": ku.crl_sign,
    }
    if ku.key_agreement:
        usages["encipher_only"] = ku.encipher_only
        usages["decipher_only"] = ku.decipher_only
    return usages


def getCertificateInfo(cert_pem_path: str) -> dict:
    """
    Extrait toutes les métadonnées utiles d'un certificat X.509 au format PEM.

    Args:
        cert_pem_path (str): Chemin vers le fichier PEM du certificat.

    Returns:
        dict: Un dictionnaire complet avec toutes les métadonnées du certificat.
            Clés principales :
                - common_name (str)
                - subject_dn (str) — Distinguished Name complet (RFC 4514)
                - issuer_dn (str)
                - serial_number_int (int)
                - serial_number_hex (str) — majuscule, sans séparateur
                - validity_start (datetime, UTC)
                - validity_end (datetime, UTC)
                - days_remaining (int)
                - key_algorithm (str) — "RSA" | "EC" | "Ed25519" | "Ed448"
                - key_size_or_curve (str) — "2048", "secp256r1", ...
                - signature_algorithm (str) — ex: "sha256WithRSAEncryption"
                - fingerprint_sha256 (str) — empreinte du cert (AA:BB:...)
                - public_key_fingerprint_sha256 (str)
                - san (dict) — {dns: [...], ip: [...], email: [...]}
                - aia (dict) — {ocsp_urls: [...], ca_issuers_urls: [...]}
                - crl_distribution_points (list[str])
                - basic_constraints (dict) — {ca: bool, path_length: int|None}
                - key_usage (dict)
                - is_expired (bool)
                - is_ca (bool)

    Raises:
        CertificateFileNotFoundError: Si le fichier est introuvable.
        CertificateFileEmptyError: Si le fichier est vide.
        CertificateLoadError: Si le certificat ne peut pas être chargé.
    """
    try:
        with open(cert_pem_path, "rb") as f:
            data = f.read()
    except FileNotFoundError:
        raise CertificateFileNotFoundError(f"Fichier certificat introuvable : {cert_pem_path}")

    if not data:
        raise CertificateFileEmptyError(f"Fichier certificat vide : {cert_pem_path}")

    try:
        cert = x509.load_pem_x509_certificate(data)
    except Exception as e:
        raise CertificateLoadError(f"Impossible de charger le certificat ({cert_pem_path}) : {e}")

    public_key = cert.public_key()
    key_algorithm, key_size_or_curve = _key_algorithm_and_size(public_key)

    # Empreintes
    cert_fp = _format_hex_fingerprint(cert.fingerprint(hashes.SHA256()))
    pub_der = public_key.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    pk_digest = hashes.Hash(hashes.SHA256())
    pk_digest.update(pub_der)
    public_key_fp = _format_hex_fingerprint(pk_digest.finalize())

    # Common Name (peut être absent sur certains certs atypiques)
    try:
        common_name = cert.subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)[0].value
    except IndexError:
        common_name = ""

    # Validité
    not_before = cert.not_valid_before_utc
    not_after = cert.not_valid_after_utc
    now = datetime.now(timezone.utc)
    days_remaining = (not_after - now).days
    is_expired = now >= not_after

    # Algorithme de signature (str)
    try:
        sig_oid = cert.signature_algorithm_oid
        signature_algorithm = sig_oid._name  # ex: "sha256WithRSAEncryption"
    except Exception:
        signature_algorithm = ""

    basic_constraints = _extract_basic_constraints(cert)

    return {
        "common_name": common_name,
        "subject_dn": cert.subject.rfc4514_string(),
        "issuer_dn": cert.issuer.rfc4514_string(),
        "serial_number_int": cert.serial_number,
        "serial_number_hex": format(cert.serial_number, "X"),
        "validity_start": not_before,
        "validity_end": not_after,
        "days_remaining": days_remaining,
        "is_expired": is_expired,
        "key_algorithm": key_algorithm,
        "key_size_or_curve": key_size_or_curve,
        "signature_algorithm": signature_algorithm,
        "fingerprint_sha256": cert_fp,
        "public_key_fingerprint_sha256": public_key_fp,
        "san": _extract_san(cert),
        "aia": _extract_aia(cert),
        "crl_distribution_points": _extract_crl_dp(cert),
        "basic_constraints": basic_constraints,
        "is_ca": basic_constraints.get("ca", False),
        "key_usage": _extract_key_usage(cert),
    }


"""
# Exemple d'utilisation
info = getCertificateInfo("tmp/certs/alice_cert.pem")
print(info["common_name"], info["fingerprint_sha256"])
"""
