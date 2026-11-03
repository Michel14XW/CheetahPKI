"""Tests cheetahpki 0.0.22 — KeyUsage/EKU par profil, fusion des extensions,
reprise du sujet d'un CSR (interopérabilité X-Road, chantier 55 vXtend).

Lancer : ``python -m pytest tests/``
"""
import warnings

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, ExtensionOID, NameOID

import cheetahpki
from cheetahpki import (
    DEFAULT_EXTENSIONS_BY_PROFILE,
    certificate_profile_kwargs,
    createSelfSignedRootCertFromBytes,
    createSignedCert,
    createSignedCertFromBytes,
    createSignedCertHybrid,
    createSignedInterCertFromBytes,
    generateKeyPairBytes,
    merge_extensions,
)

pytestmark = pytest.mark.filterwarnings(
    "ignore:Attribute's length must be:UserWarning"  # C non standard volontaire (X-Road)
)

OCSP_NOCHECK_OID = x509.ObjectIdentifier("1.3.6.1.5.5.7.48.1.5")


# ── Fixtures ────────────────────────────────────────────────────────────────

@pytest.fixture(scope="module")
def ca():
    """CA racine RSA 2048 (rapide) — clé + certificat PEM."""
    priv, _pub = generateKeyPairBytes(key_size=2048, algorithm="RSA")
    cert = createSelfSignedRootCertFromBytes(
        pseudo="Test Root", company="vXtend", city="Lome", region="Maritime",
        country_code="TG", email="", valid_days=30, private_key_pem=priv,
    )
    return priv, cert


@pytest.fixture(scope="module")
def subject_key():
    priv, pub = generateKeyPairBytes(key_size=2048, algorithm="RSA")
    return priv, pub


def _issue(ca, subject_key, **kwargs):
    ca_priv, ca_cert = ca
    _priv, pub = subject_key
    params = dict(
        public_key_pem=pub, pseudo="ss1.example", company="Member Org",
        department="", city="", region="", country_code="TG", email="",
        valid_days=30, ca_private_key_pem=ca_priv, ca_cert_pem=ca_cert,
    )
    params.update(kwargs)
    return x509.load_pem_x509_certificate(createSignedCertFromBytes(**params))


def _issue_hybrid(ca, subject_key, **kwargs):
    ca_priv, ca_cert = ca
    _priv, pub = subject_key
    params = dict(
        subject_public_key_pem=pub, pseudo="ss1.example", company="Member Org",
        department="", city="", region="", country_code="TG", email="",
        valid_days=30, ca_private_key_pem=ca_priv, ca_cert_pem=ca_cert,
    )
    params.update(kwargs)
    return x509.load_pem_x509_certificate(createSignedCertHybrid(**params))


def _ku(cert):
    return cert.extensions.get_extension_for_class(x509.KeyUsage)


def _eku_or_none(cert):
    try:
        return cert.extensions.get_extension_for_class(x509.ExtendedKeyUsage)
    except x509.ExtensionNotFound:
        return None


def _oids(cert):
    return [e.oid.dotted_string for e in cert.extensions]


def _assert_no_duplicate_oids(cert):
    oids = _oids(cert)
    assert len(oids) == len(set(oids)), oids


def _verify_signature(cert, ca):
    from cryptography.hazmat.primitives.asymmetric import padding
    ca_cert = x509.load_pem_x509_certificate(ca[1])
    ca_cert.public_key().verify(
        cert.signature, cert.tbs_certificate_bytes,
        padding.PKCS1v15(), cert.signature_hash_algorithm,
    )


# ── Version / exports ───────────────────────────────────────────────────────

def test_version():
    assert tuple(int(x) for x in cheetahpki.__version__.split(".")) >= (0, 0, 22)
    for name in ("xroad_sign", "xroad_auth", "ocsp_signing", "timestamping"):
        assert name in cheetahpki.SUPPORTED_CERTIFICATE_PROFILES
        assert name in DEFAULT_EXTENSIONS_BY_PROFILE


# ── Rétrocompatibilité (appel 0.0.21 inchangé) ──────────────────────────────

def test_backward_compatible_defaults(ca, subject_key):
    cert = _issue(ca, subject_key)
    ku = _ku(cert)
    assert ku.critical
    assert ku.value.digital_signature and ku.value.key_encipherment
    assert ku.value.data_encipherment
    assert not ku.value.content_commitment
    eku = _eku_or_none(cert)
    assert eku is not None and not eku.critical
    assert list(eku.value) == [ExtendedKeyUsageOID.SERVER_AUTH, ExtendedKeyUsageOID.CLIENT_AUTH]
    assert cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value == "ss1.example"
    assert cert.subject.get_attributes_for_oid(NameOID.COUNTRY_NAME)[0].value == "TG"
    _verify_signature(cert, ca)


# ── Profils via extra_extensions (DEFAULT_EXTENSIONS_BY_PROFILE) ────────────

@pytest.mark.parametrize("issue", [_issue, _issue_hybrid], ids=["bytes", "hybrid"])
def test_profile_xroad_sign(ca, subject_key, issue):
    cert = issue(ca, subject_key, extra_extensions=DEFAULT_EXTENSIONS_BY_PROFILE["xroad_sign"])
    ku = _ku(cert)
    assert ku.critical
    assert ku.value.content_commitment
    assert not ku.value.digital_signature
    assert not ku.value.key_encipherment
    assert not ku.value.data_encipherment
    assert not ku.value.key_agreement
    assert _eku_or_none(cert) is None
    _assert_no_duplicate_oids(cert)
    _verify_signature(cert, ca)


@pytest.mark.parametrize("issue", [_issue, _issue_hybrid], ids=["bytes", "hybrid"])
def test_profile_xroad_auth(ca, subject_key, issue):
    cert = issue(ca, subject_key, extra_extensions=DEFAULT_EXTENSIONS_BY_PROFILE["xroad_auth"])
    ku = _ku(cert)
    assert ku.critical
    assert ku.value.digital_signature and ku.value.key_encipherment
    assert not ku.value.content_commitment
    assert not ku.value.data_encipherment
    eku = _eku_or_none(cert)
    assert set(eku.value) == {ExtendedKeyUsageOID.CLIENT_AUTH, ExtendedKeyUsageOID.SERVER_AUTH}
    _assert_no_duplicate_oids(cert)


@pytest.mark.parametrize("issue", [_issue, _issue_hybrid], ids=["bytes", "hybrid"])
def test_profile_ocsp_signing(ca, subject_key, issue):
    cert = issue(ca, subject_key, extra_extensions=DEFAULT_EXTENSIONS_BY_PROFILE["ocsp_signing"])
    ku = _ku(cert)
    assert ku.critical and ku.value.digital_signature
    assert not ku.value.key_encipherment and not ku.value.content_commitment
    assert list(_eku_or_none(cert).value) == [ExtendedKeyUsageOID.OCSP_SIGNING]
    nocheck = cert.extensions.get_extension_for_oid(OCSP_NOCHECK_OID)
    assert isinstance(nocheck.value, x509.OCSPNoCheck)
    _assert_no_duplicate_oids(cert)


@pytest.mark.parametrize("issue", [_issue, _issue_hybrid], ids=["bytes", "hybrid"])
def test_profile_timestamping(ca, subject_key, issue):
    cert = issue(ca, subject_key, extra_extensions=DEFAULT_EXTENSIONS_BY_PROFILE["timestamping"])
    ku = _ku(cert)
    assert ku.value.digital_signature and ku.value.content_commitment
    eku = _eku_or_none(cert)
    assert eku.critical, "RFC 3161 §2.3 : EKU timeStamping critique"
    assert list(eku.value) == [ExtendedKeyUsageOID.TIME_STAMPING]
    _assert_no_duplicate_oids(cert)


# ── Profils via paramètres explicites (certificate_profile_kwargs) ──────────

@pytest.mark.parametrize("profile", ["xroad_sign", "xroad_auth", "ocsp_signing", "timestamping"])
def test_profile_kwargs_equivalent_to_extra_extensions(ca, subject_key, profile):
    a = _issue(ca, subject_key, **certificate_profile_kwargs(profile))
    b = _issue(ca, subject_key, extra_extensions=DEFAULT_EXTENSIONS_BY_PROFILE[profile])
    assert _ku(a).value == _ku(b).value
    ea, eb = _eku_or_none(a), _eku_or_none(b)
    assert (ea is None) == (eb is None)
    if ea is not None:
        assert list(ea.value) == list(eb.value)
        assert ea.critical == eb.critical
    assert sorted(_oids(a)) == sorted(_oids(b))


def test_certificate_profile_kwargs_unknown():
    with pytest.raises(KeyError):
        certificate_profile_kwargs("nope")


def test_explicit_key_usage_and_empty_eku(ca, subject_key):
    ku = x509.KeyUsage(
        digital_signature=False, content_commitment=True, key_encipherment=False,
        data_encipherment=False, key_agreement=False, key_cert_sign=False,
        crl_sign=False, encipher_only=False, decipher_only=False,
    )
    cert = _issue(ca, subject_key, key_usage=ku, extended_key_usage=[])
    assert _ku(cert).value == ku and _ku(cert).critical
    assert _eku_or_none(cert) is None


def test_explicit_eku_list(ca, subject_key):
    cert = _issue(ca, subject_key, extended_key_usage=[ExtendedKeyUsageOID.CLIENT_AUTH])
    assert list(_eku_or_none(cert).value) == [ExtendedKeyUsageOID.CLIENT_AUTH]


def test_explicit_params_win_over_extra_extensions(ca, subject_key):
    cert = _issue(
        ca, subject_key,
        extra_extensions=DEFAULT_EXTENSIONS_BY_PROFILE["tls_server"],
        extended_key_usage=[ExtendedKeyUsageOID.CODE_SIGNING],
    )
    assert list(_eku_or_none(cert).value) == [ExtendedKeyUsageOID.CODE_SIGNING]


def test_bad_types_rejected(ca, subject_key):
    with pytest.raises(TypeError):
        _issue(ca, subject_key, key_usage="nonRepudiation")
    with pytest.raises(TypeError):
        _issue(ca, subject_key, extended_key_usage=["1.3.6.1.5.5.7.3.1"])
    with pytest.raises(TypeError):
        _issue(ca, subject_key, subject="CN=x")


# ── extra_extensions : remplacement au lieu de « already set » ─────────────

def test_extra_extensions_replace_default_instead_of_raising(ca, subject_key):
    # En 0.0.21, un 2ᵉ EKU / SAN levait « This extension has already been set ».
    cert = _issue(
        ca, subject_key, alt_names=["a.example"],
        extra_extensions=[
            (x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), False),
            x509.SubjectAlternativeName([x509.DNSName("b.example")]),
        ],
    )
    assert list(_eku_or_none(cert).value) == [ExtendedKeyUsageOID.SERVER_AUTH]
    san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
    assert san.get_values_for_type(x509.DNSName) == ["b.example"]
    _assert_no_duplicate_oids(cert)


def test_extra_extensions_new_oid_appended(ca, subject_key):
    policies = x509.CertificatePolicies([
        x509.PolicyInformation(x509.ObjectIdentifier("1.3.6.1.4.1.99999.1"), None)
    ])
    cert = _issue(ca, subject_key, extra_extensions=[policies])
    assert cert.extensions.get_extension_for_class(x509.CertificatePolicies).value == policies


def test_intermediate_extra_extensions_replace(ca, subject_key):
    ca_priv, ca_cert = ca
    _p, pub = subject_key
    pem = createSignedInterCertFromBytes(
        public_key_pem=pub, pseudo="Inter", company="vXtend", department="IT",
        city="", region="", country_code="TG", email="", valid_days=30,
        ca_private_key_pem=ca_priv, ca_cert_pem=ca_cert,
        extra_extensions=[(x509.BasicConstraints(ca=True, path_length=0), True)],
    )
    cert = x509.load_pem_x509_certificate(pem)
    bc = cert.extensions.get_extension_for_class(x509.BasicConstraints)
    assert bc.critical and bc.value.ca
    _assert_no_duplicate_oids(cert)


def test_merge_extensions_unit():
    eku_a = x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH])
    eku_b = x509.ExtendedKeyUsage([ExtendedKeyUsageOID.CLIENT_AUTH])
    bc = x509.BasicConstraints(ca=False, path_length=None)
    merged = merge_extensions([(bc, True), (eku_a, False)], [eku_b])
    assert merged == [(bc, True), (eku_b, False)]
    assert merge_extensions([(bc, True), (eku_a, False)], [x509.ExtendedKeyUsage([])]) == [(bc, True)]


# ── Reprise du sujet d'un CSR ───────────────────────────────────────────────

def _csr_with_subject(attrs):
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    csr = (
        x509.CertificateSigningRequestBuilder()
        .subject_name(x509.Name(attrs))
        .sign(key, hashes.SHA256())
    )
    pub = key.public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    # Recharge depuis le PEM comme le ferait un serveur (EST/ACME/RA).
    csr = x509.load_pem_x509_csr(csr.public_bytes(serialization.Encoding.PEM))
    return csr, pub


with warnings.catch_warnings():
    warnings.simplefilter("ignore", UserWarning)
    XROAD_ATTRS = [
        # C non standard (identifiant d'instance X-Road), refusé par la
        # validation cryptography par défaut : _validate=False.
        x509.NameAttribute(NameOID.COUNTRY_NAME, "XROAD-DEV", _validate=False),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Member Org"),
        x509.NameAttribute(NameOID.SERIAL_NUMBER, "GOV/12345/SS1"),
        x509.NameAttribute(NameOID.COMMON_NAME, "12345"),
    ]


@pytest.mark.parametrize("issue", [_issue, _issue_hybrid], ids=["bytes", "hybrid"])
def test_subject_taken_verbatim_from_csr(ca, issue):
    csr, pub = _csr_with_subject(XROAD_ATTRS)
    cert = issue(
        ca, (None, pub), subject=csr.subject, pseudo="", company="",
        **certificate_profile_kwargs("xroad_sign"),
    )
    assert cert.subject.public_bytes() == csr.subject.public_bytes()
    assert cert.subject.get_attributes_for_oid(NameOID.SERIAL_NUMBER)[0].value == "GOV/12345/SS1"
    assert cert.subject.get_attributes_for_oid(NameOID.COUNTRY_NAME)[0].value == "XROAD-DEV"
    _verify_signature(cert, ca)


def test_without_subject_pseudo_company_still_required(ca, subject_key):
    with pytest.raises(ValueError):
        _issue(ca, subject_key, pseudo="", company="")


def test_filesystem_variant_forwards_new_params(ca, subject_key, tmp_path):
    ca_priv, ca_cert = ca
    _p, pub = subject_key
    (tmp_path / "pub.pem").write_bytes(pub)
    (tmp_path / "ca.key").write_bytes(ca_priv)
    (tmp_path / "ca.pem").write_bytes(ca_cert)
    csr, _ = _csr_with_subject(XROAD_ATTRS)
    path = createSignedCert(
        public_key_path=str(tmp_path / "pub.pem"), pseudo="ss1", company="Org",
        department="", city="", region="", country_code="TG", email="",
        valid_days=10, ca_private_key_path=str(tmp_path / "ca.key"),
        ca_cert_path=str(tmp_path / "ca.pem"), output_folder=str(tmp_path / "out"),
        subject=csr.subject, **certificate_profile_kwargs("xroad_auth"),
    )
    cert = x509.load_pem_x509_certificate(open(path, "rb").read())
    assert cert.subject == csr.subject
    assert _ku(cert).value.key_encipherment
