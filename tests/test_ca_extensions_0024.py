"""Tests cheetahpki 0.0.24 — extensions RFC 5280 du certificat de CA intermédiaire.

Depuis 0.0.24, une CA intermédiaire porte BasicConstraints et KeyUsage
critiques et aucun ExtendedKeyUsage par défaut. Un certificat émis en dessous
pour un usage quelconque (signature X-Road sans EKU, répondeur OCSP, TSA) doit
donc se valider avec un vérificateur qui impose l'imbrication des EKU.

Lancer : ``python -m pytest tests/``
"""
import datetime

import pytest
from cryptography import x509
from cryptography.x509.oid import ExtendedKeyUsageOID
from cryptography.x509.verification import PolicyBuilder, Store

from cheetahpki import (
    certificate_profile_kwargs,
    createSelfSignedRootCertFromBytes,
    createSignedCertFromBytes,
    createSignedInterCertFromBytes,
    generateKeyPairBytes,
)


@pytest.fixture(scope="module")
def chain():
    """Racine RSA + intermédiaire RSA émise avec les défauts de la bibliothèque."""
    root_priv, _ = generateKeyPairBytes(key_size=2048, algorithm="RSA")
    root_pem = createSelfSignedRootCertFromBytes(
        pseudo="Test Root", company="Lab", city="", region="",
        country_code="TG", email="", valid_days=30, private_key_pem=root_priv,
    )
    inter_priv, inter_pub = generateKeyPairBytes(key_size=2048, algorithm="RSA")
    inter_pem = createSignedInterCertFromBytes(
        public_key_pem=inter_pub, pseudo="Test Issuing CA", company="Lab",
        department="External", city="", region="", country_code="TG", email="",
        valid_days=30, ca_private_key_pem=root_priv, ca_cert_pem=root_pem,
        ocsp_url="http://ocsp.lab.test/", crl_url="http://crl.lab.test/ca.crl",
    )
    return root_pem, inter_priv, inter_pem


def _inter(chain):
    return x509.load_pem_x509_certificate(chain[2])


def test_intermediate_has_no_eku_by_default(chain):
    with pytest.raises(x509.ExtensionNotFound):
        _inter(chain).extensions.get_extension_for_class(x509.ExtendedKeyUsage)


def test_intermediate_basic_constraints_and_key_usage_critical(chain):
    cert = _inter(chain)
    bc = cert.extensions.get_extension_for_class(x509.BasicConstraints)
    assert bc.critical and bc.value.ca and bc.value.path_length == 0
    ku = cert.extensions.get_extension_for_class(x509.KeyUsage)
    assert ku.critical and ku.value.key_cert_sign and ku.value.crl_sign


def test_intermediate_keeps_aia_and_crldp(chain):
    cert = _inter(chain)
    cert.extensions.get_extension_for_class(x509.AuthorityInformationAccess)
    cert.extensions.get_extension_for_class(x509.CRLDistributionPoints)


def test_intermediate_eku_can_still_be_set_explicitly(chain):
    root_priv, _ = generateKeyPairBytes(key_size=2048, algorithm="RSA")
    root_pem = createSelfSignedRootCertFromBytes(
        pseudo="Root 2", company="Lab", city="", region="",
        country_code="TG", email="", valid_days=30, private_key_pem=root_priv,
    )
    _p, pub = generateKeyPairBytes(key_size=2048, algorithm="RSA")
    eku = x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH])
    pem = createSignedInterCertFromBytes(
        public_key_pem=pub, pseudo="TLS only CA", company="Lab", department="",
        city="", region="", country_code="TG", email="", valid_days=30,
        ca_private_key_pem=root_priv, ca_cert_pem=root_pem,
        extra_extensions=[eku],
    )
    cert = x509.load_pem_x509_certificate(pem)
    assert list(cert.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value) \
        == [ExtendedKeyUsageOID.SERVER_AUTH]


def _leaf(chain, profile):
    _root, inter_priv, inter_pem = chain
    _p, pub = generateKeyPairBytes(key_size=2048, algorithm="RSA")
    pem = createSignedCertFromBytes(
        public_key_pem=pub, pseudo="ss1.lab.test", company="Member", department="",
        city="", region="", country_code="TG", email="", valid_days=10,
        ca_private_key_pem=inter_priv, ca_cert_pem=inter_pem,
        alt_names=["ss1.lab.test"],
        **certificate_profile_kwargs(profile),
    )
    return x509.load_pem_x509_certificate(pem)


def test_xroad_auth_chain_validates_rfc5280(chain):
    """Chaîne racine -> intermédiaire -> certificat d'authentification X-Road
    validée par le vérificateur strict de `cryptography` (BasicConstraints
    critique, KeyUsage keyCertSign, AKI/SKI, SAN)."""
    root_pem, _inter_priv, inter_pem = chain
    leaf = _leaf(chain, "xroad_auth")
    verifier = (
        PolicyBuilder()
        .store(Store([x509.load_pem_x509_certificate(root_pem)]))
        .time(datetime.datetime.now(datetime.timezone.utc))
        .build_client_verifier()
    )
    verifier.verify(leaf, [x509.load_pem_x509_certificate(inter_pem)])


@pytest.mark.parametrize("profile", ["xroad_sign", "ocsp_signing", "timestamping"])
def test_leaf_usage_not_restricted_by_issuer(chain, profile):
    """Sans EKU sur l'émetteur, aucun usage de la feuille n'est hors de son périmètre."""
    leaf = _leaf(chain, profile)
    try:
        leaf_eku = set(leaf.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value)
    except x509.ExtensionNotFound:
        leaf_eku = set()
    try:
        issuer_eku = set(_inter(chain).extensions.get_extension_for_class(x509.ExtendedKeyUsage).value)
    except x509.ExtensionNotFound:
        issuer_eku = None  # pas de restriction
    assert issuer_eku is None or leaf_eku <= issuer_eku
