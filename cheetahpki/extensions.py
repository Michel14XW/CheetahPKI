"""
Extensions X.509 prédéfinies par profil de certificat (cheetahpki >= 0.0.16).

`DEFAULT_EXTENSIONS_BY_PROFILE` regroupe les extensions à injecter via le
paramètre `extra_extensions` de `createSignedCertFromBytes` /
`createSignedInterCertFromBytes` selon le `CertificateTemplate` Django choisi
par l'opérateur PKI.

Chaque profil expose une liste de tuples `(extension, critical: bool)` pour que
l'appelant puisse contrôler la criticité tout en restant aligné sur les bonnes
pratiques RFC 5280 §4.2.

Utilisation typique :

    from cheetahpki import DEFAULT_EXTENSIONS_BY_PROFILE, createSignedCertFromBytes
    cert_pem = createSignedCertFromBytes(
        ...,
        extra_extensions=DEFAULT_EXTENSIONS_BY_PROFILE["tls_server"],
    )

Profils fournis :
    - ``tls_server``   — Serveur TLS / HTTPS (EKU serverAuth).
    - ``tls_client``   — Authentification client TLS / mTLS (EKU clientAuth).
    - ``email_smime``  — Signature et chiffrement d'emails S/MIME (EKU emailProtection).
    - ``code_signing`` — Signature de code (EKU codeSigning).
"""

from cryptography import x509
from cryptography.x509.oid import ExtendedKeyUsageOID


# Profil TLS Server — RFC 5280 §4.2.1.12 + CA/Browser Forum BR §7.1.2.7.6
_TLS_SERVER = [
    (
        x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]),
        False,
    ),
]

# Profil TLS Client — authentification mutuelle TLS / mTLS.
_TLS_CLIENT = [
    (
        x509.ExtendedKeyUsage([ExtendedKeyUsageOID.CLIENT_AUTH]),
        False,
    ),
]

# Profil S/MIME — signature et chiffrement d'emails (RFC 8551).
_EMAIL_SMIME = [
    (
        x509.ExtendedKeyUsage([ExtendedKeyUsageOID.EMAIL_PROTECTION]),
        False,
    ),
]

# Profil Code Signing — signature d'exécutables / paquets logiciels.
_CODE_SIGNING = [
    (
        x509.ExtendedKeyUsage([ExtendedKeyUsageOID.CODE_SIGNING]),
        False,
    ),
]


DEFAULT_EXTENSIONS_BY_PROFILE = {
    "tls_server": _TLS_SERVER,
    "tls_client": _TLS_CLIENT,
    "email_smime": _EMAIL_SMIME,
    "code_signing": _CODE_SIGNING,
}


__all__ = ("DEFAULT_EXTENSIONS_BY_PROFILE",)
