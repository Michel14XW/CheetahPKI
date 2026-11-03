"""
Révocation de certificat — wrapper de haut niveau au-dessus de `generateCRL`.

`generateCRL` exige la liste *complète* des certificats révoqués en entrée.
En pratique, révoquer un certificat consiste à :

    1. charger la CRL courante de la CA (si elle existe) ;
    2. en extraire les entrées de révocation déjà publiées ;
    3. y ajouter (ou mettre à jour) l'entrée du certificat à révoquer ;
    4. re-signer une nouvelle CRL avec un `crl_number` incrémenté.

`revokeCert` encapsule ces quatre étapes. Il est destiné aux scénarios
d'intégration / scripting où l'on ne maintient pas soi-même la liste cumulée
des révocations (côté application Django, c'est `CRLService` qui joue ce rôle
en s'appuyant directement sur la base de données).

Utilisation typique :

    from cheetahpki import revokeCert
    crl_pem_path, crl_der_bytes = revokeCert(
        ca_cert_path="tmp/certs/inter_ca.pem",
        ca_private_key_path="tmp/keys/inter_private_key.pem",
        serial_number=0x1A2B3C,
        crl_number=8,                       # strictement > crl_number précédent
        existing_crl_path="tmp/crl/inter_ca_crl.pem",   # None au 1er appel
        reason="key_compromise",
        ca_key_password=None,
    )

Ajouté en cheetahpki 0.0.21.
"""

import datetime
from typing import Optional, Tuple

from cryptography import x509

from .exceptions import CertificateFileNotFoundError, CertificateLoadError
from .generateCRL import _REASON_MAP, CRLRevocationEntry, generateCRL

__all__ = ("revokeCert",)

# Mapping inverse x509.ReasonFlags -> str, pour reconstruire les entrées d'une
# CRL existante (où la raison est encodée dans l'extension CRLReason).
_REASON_TO_STR = {flag: name for name, flag in _REASON_MAP.items()}


def _load_existing_crl(crl_path: str) -> x509.CertificateRevocationList:
    """Charge une CRL PEM ou DER depuis le disque (auto-détection du format)."""
    try:
        with open(crl_path, "rb") as f:
            data = f.read()
    except FileNotFoundError:
        raise CertificateFileNotFoundError(f"CRL existante introuvable : {crl_path}")

    try:
        if data.lstrip().startswith(b"-----"):
            return x509.load_pem_x509_crl(data)
        return x509.load_der_x509_crl(data)
    except Exception as e:
        raise CertificateLoadError(f"Impossible de charger la CRL ({crl_path}) : {e}")


def _entries_from_crl(crl: x509.CertificateRevocationList) -> list:
    """Reconstruit une liste de CRLRevocationEntry à partir d'une CRL chargée."""
    entries = []
    for revoked in crl:
        reason_str = "unspecified"
        try:
            crl_reason = revoked.extensions.get_extension_for_class(x509.CRLReason)
            reason_str = _REASON_TO_STR.get(crl_reason.value.reason, "unspecified")
        except x509.ExtensionNotFound:
            pass

        # cryptography ≥ 43 expose `revocation_date_utc` (timezone-aware) ;
        # fallback sur l'attribut naïf legacy considéré UTC.
        revocation_date = getattr(revoked, "revocation_date_utc", None)
        if revocation_date is None:
            legacy = revoked.revocation_date
            revocation_date = legacy.replace(tzinfo=datetime.timezone.utc) \
                if legacy.tzinfo is None else legacy

        entries.append(
            CRLRevocationEntry(
                serial_number=revoked.serial_number,
                revocation_date=revocation_date,
                reason=reason_str,
            )
        )
    return entries


def revokeCert(
    ca_cert_path: str,
    ca_private_key_path: str,
    serial_number: int,
    crl_number: int,
    existing_crl_path: Optional[str] = None,
    reason: str = "unspecified",
    revocation_date: Optional[datetime.datetime] = None,
    ca_key_password: Optional[str] = None,
    next_update_days: int = 7,
    output_folder: str = "crl",
    output_filename: Optional[str] = None,
) -> Tuple[str, bytes]:
    """
    Révoque un certificat en publiant une nouvelle CRL signée par la CA.

    Charge la CRL existante (si fournie), y ajoute l'entrée du certificat à
    révoquer, puis re-signe une CRL complète via `generateCRL`.

    Args:
        ca_cert_path (str): Chemin du certificat PEM de la CA émettrice.
        ca_private_key_path (str): Chemin de la clé privée PEM de la CA.
        serial_number (int): Numéro de série (décimal) du certificat à révoquer.
        crl_number (int): Numéro de la nouvelle CRL (extension CRLNumber). Doit
            être strictement supérieur à celui de la CRL précédente.
        existing_crl_path (str, optional): Chemin de la CRL courante à étendre.
            `None` (défaut) pour une première CRL ne contenant que cette entrée.
        reason (str, optional): Raison RFC 5280 (clé de `_REASON_MAP`).
            Défaut : "unspecified".
        revocation_date (datetime, optional): Date de révocation. Défaut : maintenant (UTC).
        ca_key_password (str, optional): Mot de passe de la clé privée de la CA.
        next_update_days (int, optional): Validité de la CRL en jours. Défaut : 7.
        output_folder (str, optional): Dossier de sortie. Défaut : "crl".
        output_filename (str, optional): Nom du fichier sans extension.

    Returns:
        tuple: (crl_pem_path: str, crl_der_bytes: bytes) — identique à `generateCRL`.

    Raises:
        CertificateFileNotFoundError: CRL existante ou certificat CA introuvable.
        CertificateLoadError: CRL existante illisible.
        (et toutes les exceptions propagées par `generateCRL`).

    Note:
        Si `serial_number` figure déjà dans la CRL existante, son entrée d'origine
        est conservée (la date/raison initiales priment — une révocation est
        définitive en RFC 5280, sauf `remove_from_crl`). Aucun doublon n'est créé.
    """
    if revocation_date is None:
        revocation_date = datetime.datetime.now(datetime.timezone.utc)

    entries = []
    existing_serials = set()
    if existing_crl_path is not None:
        crl = _load_existing_crl(existing_crl_path)
        entries = _entries_from_crl(crl)
        existing_serials = {e.serial_number for e in entries}

    if serial_number not in existing_serials:
        entries.append(
            CRLRevocationEntry(
                serial_number=serial_number,
                revocation_date=revocation_date,
                reason=reason,
            )
        )

    return generateCRL(
        ca_cert_path=ca_cert_path,
        ca_private_key_path=ca_private_key_path,
        revoked_entries=entries,
        crl_number=crl_number,
        next_update_days=next_update_days,
        ca_key_password=ca_key_password,
        output_folder=output_folder,
        output_filename=output_filename,
    )
