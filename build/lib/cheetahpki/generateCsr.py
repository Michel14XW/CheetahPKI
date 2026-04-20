from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import serialization
import ipaddress

def generateCsr(
    private_key: rsa.RSAPrivateKey,
    country: str,
    state: str,
    city: str,
    org: str,
    common_name: str,
    alt_names: list[str] = None,
    ip_addresses: list[str] = None,
    critical_extensions: bool = False
) -> bytes:
    """
    Génère une CSR (Certificate Signing Request) au format PEM.

    Args:
        private_key (RSAPrivateKey): Clé privée utilisée pour signer la CSR.
        country (str): Code pays à 2 lettres (ex. "TG").
        state (str): État ou région (ex. "Maritime").
        city (str): Ville de l'organisation (ex. "Lomé").
        org (str): Nom de l'organisation (ex. "UCAO").
        common_name (str): FQDN (Fully Qualified Domain Name) ou nom principal (ex. "www.ucao.local").
        alt_names (list[str], optional): Noms DNS alternatifs (ex. ["ucao.com", "www.ucao.org"]).
        ip_addresses (list[str], optional): Adresses IP alternatives pour le certificat (ex. ["192.168.1.1"]).
        critical_extensions (bool, optional): Définit si les extensions doivent être critiques.

    Returns:
        bytes: CSR généré au format PEM.
    """
    # Construire les informations du sujet
    subject = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, country),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, state),
        x509.NameAttribute(NameOID.LOCALITY_NAME, city),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, org),
        x509.NameAttribute(NameOID.COMMON_NAME, common_name),
    ])

    # Liste des extensions (subjectAltName)
    alt_name_list = []
    if alt_names:
        alt_name_list.extend(x509.DNSName(name) for name in alt_names)
    if ip_addresses:
        alt_name_list.extend(x509.IPAddress(ip) for ip in map(lambda ip: ipaddress.ip_address(ip), ip_addresses))

    # Construire les extensions
    extensions = [
        x509.SubjectAlternativeName(alt_name_list),
        x509.BasicConstraints(ca=False, path_length=None),
        x509.KeyUsage(
            digital_signature=True,
            key_encipherment=True,
            content_commitment=False,
            data_encipherment=True,
            key_agreement=False,
            encipher_only=False,
            decipher_only=False,
            key_cert_sign=False,
            crl_sign=False
        )
    ]

    # Construction du CSR
    csr_builder = x509.CertificateSigningRequestBuilder().subject_name(subject)

    # Ajouter les extensions au CSR
    for ext in extensions:
        csr_builder = csr_builder.add_extension(ext, critical=critical_extensions)

    # Signer la CSR avec la clé privée
    csr = csr_builder.sign(private_key, hashes.SHA256())

    # Retourner la CSR en bytes au format PEM
    return csr.public_bytes(encoding=serialization.Encoding.PEM)


"""

if __name__ == "__main__":
    from cryptography.hazmat.primitives.asymmetric import rsa
    import ipaddress

    # Générer une clé privée pour l'exemple
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=4096,
    )

    # Spécifier les informations pour le CSR
    country = "TG"
    state = "Maritime"
    city = "Lomé"
    org = "UCAO-IT"
    common_name = "www.ucao.local"
    alt_names = ["ucao.com", "lab.ucao.local"]
    ip_addresses = ["192.168.1.1", "192.168.2.1"]

    # Générer le CSR
    csr = generate_csr(private_key, country, state, city, org, common_name, alt_names, ip_addresses)

    # Sauvegarder le CSR dans un fichier
    with open("csr.pem", "wb") as csr_file:
        csr_file.write(csr)

    print("CSR généré et enregistré dans csr.pem")
"""