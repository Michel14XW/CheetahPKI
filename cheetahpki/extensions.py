"""
Extensions X.509 prédéfinies par profil de certificat (cheetahpki >= 0.0.16).

`DEFAULT_EXTENSIONS_BY_PROFILE` regroupe les extensions à injecter via le
paramètre `extra_extensions` de `createSignedCertFromBytes` /
`createSignedInterCertFromBytes` / `createSignedCertHybrid` selon le
`CertificateTemplate` Django choisi par l'opérateur PKI.

Chaque profil expose une liste de tuples `(extension, critical: bool)` pour que
l'appelant puisse contrôler la criticité tout en restant aligné sur les bonnes
pratiques RFC 5280 §4.2.

Depuis 0.0.22, une extension de `extra_extensions` dont l'OID existe déjà dans
les extensions posées par défaut **remplace** celle par défaut (au lieu de lever
« This extension has already been set »). Convention : un
``x509.ExtendedKeyUsage([])`` (liste vide) signifie **« pas d'EKU »** — l'EKU par
défaut est retiré et aucune extension EKU n'est encodée (RFC 5280 interdit un
EKU vide, SIZE (1..MAX)).

Utilisation typique :

    from cheetahpki import DEFAULT_EXTENSIONS_BY_PROFILE, createSignedCertFromBytes
    cert_pem = createSignedCertFromBytes(
        ...,
        extra_extensions=DEFAULT_EXTENSIONS_BY_PROFILE["xroad_sign"],
    )

    # ou, de façon équivalente, avec les paramètres explicites (0.0.22) :
    from cheetahpki import certificate_profile_kwargs
    cert_pem = createSignedCertFromBytes(..., **certificate_profile_kwargs("xroad_sign"))

Profils fournis :
    - ``tls_server``   — Serveur TLS / HTTPS (EKU serverAuth).
    - ``tls_client``   — Authentification client TLS / mTLS (EKU clientAuth).
    - ``email_smime``  — Signature et chiffrement d'emails S/MIME (EKU emailProtection).
    - ``code_signing`` — Signature de code (EKU codeSigning).
    - ``xroad_sign``   — X-Road, certificat de signature : KeyUsage nonRepudiation
                         seul (critique), aucun EKU (0.0.22).
    - ``xroad_auth``   — X-Road, certificat d'authentification : KeyUsage
                         digitalSignature + keyEncipherment (critique),
                         EKU clientAuth + serverAuth (0.0.22).
    - ``ocsp_signing`` — Répondeur OCSP délégué (RFC 6960 §4.2.2.2) : KeyUsage
                         digitalSignature, EKU OCSPSigning, id-pkix-ocsp-nocheck (0.0.22).
    - ``timestamping`` — TSA RFC 3161 : KeyUsage digitalSignature + nonRepudiation,
                         EKU timeStamping **critique** (RFC 3161 §2.3) (0.0.22).
"""

from cryptography import x509
from cryptography.x509.oid import ExtendedKeyUsageOID


def _key_usage(*, digital_signature=False, content_commitment=False,
               key_encipherment=False, data_encipherment=False,
               key_agreement=False) -> x509.KeyUsage:
    """Fabrique un KeyUsage end-entity (jamais keyCertSign / cRLSign)."""
    return x509.KeyUsage(
        digital_signature=digital_signature,
        content_commitment=content_commitment,
        key_encipherment=key_encipherment,
        data_encipherment=data_encipherment,
        key_agreement=key_agreement,
        key_cert_sign=False,
        crl_sign=False,
        encipher_only=False,
        decipher_only=False,
    )


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

# ── Profils 0.0.22 (interopérabilité X-Road, OCSP délégué, TSA) ─────────────

# X-Road — certificat de SIGNATURE d'un membre : nonRepudiation SEUL, sans EKU.
_XROAD_SIGN = [
    (_key_usage(content_commitment=True), True),
    (x509.ExtendedKeyUsage([]), False),  # convention : EKU vide = pas d'EKU
]

# X-Road — certificat d'AUTHENTIFICATION d'un Security Server (TLS mutuel).
_XROAD_AUTH = [
    (_key_usage(digital_signature=True, key_encipherment=True), True),
    (
        x509.ExtendedKeyUsage([
            ExtendedKeyUsageOID.CLIENT_AUTH,
            ExtendedKeyUsageOID.SERVER_AUTH,
        ]),
        False,
    ),
]

# Répondeur OCSP délégué — RFC 6960 §4.2.2.2 (EKU id-kp-OCSPSigning) et
# §4.2.2.2.1 (id-pkix-ocsp-nocheck : le client ne vérifie pas la révocation
# du certificat du répondeur).
_OCSP_SIGNING = [
    (_key_usage(digital_signature=True), True),
    (x509.ExtendedKeyUsage([ExtendedKeyUsageOID.OCSP_SIGNING]), False),
    (x509.OCSPNoCheck(), False),
]

# Autorité d'horodatage — RFC 3161 §2.3 : EKU id-kp-timeStamping UNIQUE et
# CRITIQUE.
_TIMESTAMPING = [
    (_key_usage(digital_signature=True, content_commitment=True), True),
    (x509.ExtendedKeyUsage([ExtendedKeyUsageOID.TIME_STAMPING]), True),
]


DEFAULT_EXTENSIONS_BY_PROFILE = {
    "tls_server": _TLS_SERVER,
    "tls_client": _TLS_CLIENT,
    "email_smime": _EMAIL_SMIME,
    "code_signing": _CODE_SIGNING,
    "xroad_sign": _XROAD_SIGN,
    "xroad_auth": _XROAD_AUTH,
    "ocsp_signing": _OCSP_SIGNING,
    "timestamping": _TIMESTAMPING,
}


def certificate_profile_kwargs(profile: str) -> dict:
    """Traduit un profil en paramètres explicites des émetteurs (0.0.22).

    Retourne un dict utilisable tel quel en ``**kwargs`` de
    `createSignedCertFromBytes` / `createSignedCert` / `createSignedCertHybrid` :

    - ``key_usage``          : ``x509.KeyUsage`` ou ``None`` (défaut conservé) ;
    - ``extended_key_usage`` : liste d'OID, ``[]`` (pas d'EKU) ou ``None`` ;
    - ``extra_extensions``   : autres extensions du profil (ex. OCSPNoCheck),
      ou ``None``.

    :raises KeyError: profil inconnu.
    """
    try:
        items = DEFAULT_EXTENSIONS_BY_PROFILE[profile]
    except KeyError:
        raise KeyError(
            f"Profil de certificat inconnu : {profile!r} "
            f"(disponibles : {', '.join(sorted(DEFAULT_EXTENSIONS_BY_PROFILE))})"
        ) from None
    key_usage = None
    extended_key_usage = None
    extra = []
    for ext, critical in items:
        if isinstance(ext, x509.KeyUsage):
            key_usage = ext
        elif isinstance(ext, x509.ExtendedKeyUsage) and not critical:
            extended_key_usage = list(ext)
        else:
            # EKU critique (timestamping) ou autre extension : transmise telle
            # quelle pour conserver la criticité.
            extra.append((ext, critical))
    return {
        "key_usage": key_usage,
        "extended_key_usage": extended_key_usage,
        "extra_extensions": extra or None,
    }


# ─────────────────────────────────────────────────────────────────────────────
# Fusion des extensions (0.0.22) — partagée par tous les émetteurs
# ─────────────────────────────────────────────────────────────────────────────

def normalize_extension_items(items) -> list:
    """Normalise ``extra_extensions`` en liste de tuples ``(extension, critical)``.

    Accepte un ``x509.ExtensionType`` seul (criticité ``False``) ou un tuple
    ``(extension, critical)``.
    """
    normalized = []
    for item in items or []:
        if isinstance(item, tuple):
            ext_obj, critical = item
        else:
            ext_obj, critical = item, False
        normalized.append((ext_obj, bool(critical)))
    return normalized


def _is_eku_removal(ext) -> bool:
    return isinstance(ext, x509.ExtendedKeyUsage) and len(list(ext)) == 0


def merge_extensions(defaults, overrides) -> list:
    """Fusionne les extensions par défaut et les surcharges, **par OID**.

    - Une surcharge dont l'OID existe dans ``defaults`` **remplace** l'extension
      par défaut à la même position (ordre stable) ;
    - une surcharge d'OID nouveau est ajoutée à la fin ;
    - deux surcharges du même OID : la dernière gagne ;
    - un ``ExtendedKeyUsage([])`` retire l'EKU (aucune extension EKU encodée).

    :returns: liste ``[(extension, critical), ...]`` sans doublon d'OID.
    """
    merged = list(normalize_extension_items(defaults))
    for ext, critical in normalize_extension_items(overrides):
        oid = ext.oid
        idx = next((i for i, (e, _c) in enumerate(merged) if e.oid == oid), None)
        if idx is None:
            merged.append((ext, critical))
        else:
            merged[idx] = (ext, critical)
    return [(e, c) for e, c in merged if not _is_eku_removal(e)]


def build_override_extensions(key_usage=None, extended_key_usage=None,
                              extra_extensions=None) -> list:
    """Assemble les surcharges issues des paramètres explicites 0.0.22.

    Ordre de priorité (le dernier gagne) : ``extra_extensions`` puis
    ``key_usage`` / ``extended_key_usage`` explicites.

    - ``key_usage`` : ``x509.KeyUsage`` → posé **critique** (RFC 5280 §4.2.1.3).
    - ``extended_key_usage`` : liste d'``ObjectIdentifier`` ; ``[]`` = pas d'EKU ;
      ``None`` = inchangé. Un ``x509.ExtendedKeyUsage`` est aussi accepté.
    """
    overrides = list(normalize_extension_items(extra_extensions))
    if key_usage is not None:
        if not isinstance(key_usage, x509.KeyUsage):
            raise TypeError("key_usage doit être un cryptography.x509.KeyUsage.")
        overrides.append((key_usage, True))
    if extended_key_usage is not None:
        usages = list(extended_key_usage)  # liste d'OID ou x509.ExtendedKeyUsage
        for oid in usages:
            if not isinstance(oid, x509.ObjectIdentifier):
                raise TypeError(
                    "extended_key_usage doit contenir des cryptography.x509.ObjectIdentifier."
                )
        overrides.append((x509.ExtendedKeyUsage(usages), False))
    return overrides


__all__ = (
    "DEFAULT_EXTENSIONS_BY_PROFILE",
    "certificate_profile_kwargs",
    "merge_extensions",
    "normalize_extension_items",
    "build_override_extensions",
)
