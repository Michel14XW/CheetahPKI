"""
_name.py — construction normalisée du sujet X.501 et du SubjectAltName.

Centralise la logique partagée par `createSignedCert`, `createSignedInterCert`
et `createSelfSignedRootCert` (ajout 0.0.20) afin de corriger deux défauts
historiques communs aux trois émetteurs :

1. **Champs vides dans le DN** — les anciens émetteurs ajoutaient
   *inconditionnellement* `ST`, `L`, `OU`, … même lorsqu'on leur passait une
   chaîne vide. Résultat : des sujets du type `…,L=,ST=,C=TG` (RDN vides) et,
   pour le pays, l'erreur `cryptography` « Attribute's length must be >= 2 and
   <= 2, but it was 0 ». `build_subject_name` n'émet un RDN que si sa valeur
   est non vide, et n'inclut le pays (`C`) que s'il fait exactement 2 lettres.

2. **emailAddress dans le DN** — l'adresse e-mail était placée dans le sujet
   (`1.2.840.113549.1.9.1`). C'est **déprécié par la RFC 5280 §4.1.2.6** :
   l'e-mail appartient au SubjectAltName (`rfc822Name`), pas au DN. L'e-mail
   est donc retiré du sujet et ne subsiste que dans le SAN — et uniquement
   s'il est fourni (il devient **optionnel**).
"""
import ipaddress
import re

from cryptography import x509
from cryptography.x509.oid import NameOID


def is_valid_email(email) -> bool:
    """Validation e-mail volontairement permissive (présence d'un `@` et d'un
    domaine pointé). Retourne ``False`` pour une valeur vide ou ``None``."""
    return bool(email and re.match(r"[^@]+@[^@]+\.[^@]+", str(email)))


def build_subject_name(
    *,
    country_code: str = "",
    region: str = "",
    city: str = "",
    company: str = "",
    department: str = "",
    common_name: str = "",
) -> x509.Name:
    """Construit un ``x509.Name`` en omettant les composants vides.

    - Le pays (`C`) n'est inclus que s'il fait **exactement 2 caractères**
      (contrainte `cryptography` / RFC 5280) ; il est normalisé en majuscules.
    - L'e-mail n'est **jamais** placé dans le DN (cf. SAN, RFC 5280).
    - L'ordre des RDN suit la convention X.500 (C, ST, L, O, OU, CN).
    """
    attrs = []
    cc = (country_code or "").strip().upper()
    if len(cc) == 2:
        attrs.append(x509.NameAttribute(NameOID.COUNTRY_NAME, cc))
    for value, oid in (
        (region,      NameOID.STATE_OR_PROVINCE_NAME),
        (city,        NameOID.LOCALITY_NAME),
        (company,     NameOID.ORGANIZATION_NAME),
        (department,  NameOID.ORGANIZATIONAL_UNIT_NAME),
        (common_name, NameOID.COMMON_NAME),
    ):
        v = (value or "").strip()
        if v:
            attrs.append(x509.NameAttribute(oid, v))
    return x509.Name(attrs)


def build_san_general_names(
    email: str = "",
    alt_names: list = None,
    ip_addresses: list = None,
) -> list:
    """Assemble la liste des ``GeneralName`` du SubjectAltName.

    L'e-mail (`rfc822Name`) n'est ajouté que s'il est fourni et valide. La
    liste peut être vide : dans ce cas l'appelant **ne doit pas** poser
    l'extension SAN (``cryptography`` rejette un SAN vide).
    """
    names = []
    if email and is_valid_email(email):
        names.append(x509.RFC822Name(email))
    names.extend(x509.DNSName(name) for name in (alt_names or []))
    names.extend(
        x509.IPAddress(ipaddress.ip_address(ip)) for ip in (ip_addresses or [])
    )
    return names
