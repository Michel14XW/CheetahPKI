"""
Client OCSP léger conforme RFC 6960.

Expose `checkOCSPStatus(cert_pem, ca_cert_pem, ocsp_url)` qui interroge un
répondeur OCSP via HTTP POST et retourne le statut de révocation d'un
certificat émis par `ca_cert_pem`.

Utilisation typique depuis l'application Django (intégration vXtend-PKI) :

    from cheetahpki import checkOCSPStatus, OCSPCheckError
    try:
        status, reason, this_update = checkOCSPStatus(
            cert_pem=user_cert_pem,
            ca_cert_pem=inter_ca_pem,
            ocsp_url="http://pki.example.org/ocsp/",
            timeout=10,
        )
        if status == "REVOKED":
            ...
    except OCSPCheckError as exc:
        ...

Cette implémentation n'utilise que `cryptography` et `urllib` (stdlib) ; aucun
dépendance HTTP tierce, ce qui simplifie le packaging.

Ajouté en cheetahpki 0.0.16 — chantier 1 todo.md.
"""

from __future__ import annotations

import datetime
import urllib.error
import urllib.request
from typing import Optional, Tuple

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.x509 import ocsp
from cryptography.x509.ocsp import OCSPResponseStatus, OCSPCertStatus

from .exceptions import OCSPCheckError

__all__ = ("checkOCSPStatus",)


# Mapping x509.ReasonFlags -> chaîne utilisée par l'application Django.
# On reprend exactement les valeurs supportées par cheetahpki côté CRL pour
# rester homogène (cf. generateCRL._REASON_MAP).
_REVOCATION_REASON_NAMES = {
    x509.ReasonFlags.unspecified: "unspecified",
    x509.ReasonFlags.key_compromise: "key_compromise",
    x509.ReasonFlags.ca_compromise: "ca_compromise",
    x509.ReasonFlags.affiliation_changed: "affiliation_changed",
    x509.ReasonFlags.superseded: "superseded",
    x509.ReasonFlags.cessation_of_operation: "cessation_of_operation",
    x509.ReasonFlags.certificate_hold: "certificate_hold",
    x509.ReasonFlags.privilege_withdrawn: "privilege_withdrawn",
    x509.ReasonFlags.aa_compromise: "aa_compromise",
    x509.ReasonFlags.remove_from_crl: "remove_from_crl",
}


def _normalize_status(response_status: OCSPCertStatus) -> str:
    if response_status == OCSPCertStatus.GOOD:
        return "GOOD"
    if response_status == OCSPCertStatus.REVOKED:
        return "REVOKED"
    return "UNKNOWN"


def checkOCSPStatus(
    cert_pem: bytes,
    ca_cert_pem: bytes,
    ocsp_url: str,
    timeout: int = 10,
) -> Tuple[str, Optional[str], datetime.datetime]:
    """
    Interroge un répondeur OCSP (RFC 6960) et retourne le statut de révocation
    d'un certificat.

    Args:
        cert_pem (bytes): Certificat à vérifier, format PEM.
        ca_cert_pem (bytes): Certificat de l'autorité émettrice (CA intermédiaire
            ou root), format PEM. Utilisé pour calculer issuerNameHash /
            issuerKeyHash de la requête OCSP.
        ocsp_url (str): URL HTTP/HTTPS du répondeur OCSP.
        timeout (int, optionnel): Timeout (secondes) de la requête HTTP. Défaut : 10.

    Returns:
        tuple[str, str | None, datetime.datetime]:
            - status (str)            : "GOOD" | "REVOKED" | "UNKNOWN".
            - revocation_reason (str) : raison RFC 5280 si REVOKED, sinon None.
            - this_update (datetime)  : `thisUpdate` de la réponse OCSP (UTC).

    Raises:
        OCSPCheckError: Pour toute erreur réseau, réponse OCSP malformée, ou
            statut non `SUCCESSFUL`.
    """
    if not ocsp_url:
        raise OCSPCheckError("URL OCSP manquante.")

    try:
        cert = x509.load_pem_x509_certificate(cert_pem)
    except Exception as exc:
        raise OCSPCheckError(f"Certificat à vérifier illisible : {exc}") from exc

    try:
        issuer = x509.load_pem_x509_certificate(ca_cert_pem)
    except Exception as exc:
        raise OCSPCheckError(f"Certificat CA émetteur illisible : {exc}") from exc

    try:
        builder = ocsp.OCSPRequestBuilder().add_certificate(cert, issuer, hashes.SHA256())
        ocsp_request = builder.build()
        request_der = ocsp_request.public_bytes(serialization.Encoding.DER)
    except Exception as exc:
        raise OCSPCheckError(f"Construction de la requête OCSP impossible : {exc}") from exc

    http_request = urllib.request.Request(
        url=ocsp_url,
        data=request_der,
        method="POST",
        headers={
            "Content-Type": "application/ocsp-request",
            "Accept": "application/ocsp-response",
        },
    )

    try:
        with urllib.request.urlopen(http_request, timeout=timeout) as response:
            response_der = response.read()
    except urllib.error.URLError as exc:
        raise OCSPCheckError(f"Échec réseau OCSP ({ocsp_url}) : {exc}") from exc
    except Exception as exc:
        raise OCSPCheckError(f"Erreur HTTP OCSP ({ocsp_url}) : {exc}") from exc

    try:
        ocsp_response = ocsp.load_der_ocsp_response(response_der)
    except Exception as exc:
        raise OCSPCheckError(f"Réponse OCSP non parsable : {exc}") from exc

    if ocsp_response.response_status != OCSPResponseStatus.SUCCESSFUL:
        raise OCSPCheckError(
            f"Réponse OCSP non SUCCESSFUL : {ocsp_response.response_status.name}"
        )

    status = _normalize_status(ocsp_response.certificate_status)

    revocation_reason: Optional[str] = None
    if status == "REVOKED":
        reason = ocsp_response.revocation_reason
        if reason is None:
            revocation_reason = "unspecified"
        else:
            revocation_reason = _REVOCATION_REASON_NAMES.get(reason, "unspecified")

    # `this_update` est UTC d'après la RFC ; on s'aligne sur l'API moderne de
    # cryptography (>= 43) qui expose `this_update_utc`.
    this_update = getattr(ocsp_response, "this_update_utc", None)
    if this_update is None:
        # Fallback compatible cryptography 42.x — naive datetime considéré UTC.
        legacy = ocsp_response.this_update
        if legacy is None:
            this_update = datetime.datetime.now(datetime.timezone.utc)
        elif legacy.tzinfo is None:
            this_update = legacy.replace(tzinfo=datetime.timezone.utc)
        else:
            this_update = legacy

    return status, revocation_reason, this_update
