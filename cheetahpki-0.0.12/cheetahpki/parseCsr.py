from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.x509.oid import NameOID
import ipaddress

def parseCsr(csr_file_path: str) -> dict:
    """
    Analyse un fichier CSR au format PEM et extrait les informations nécessaires pour createSignedCert.

    Args:
        csr_file_path (str): Chemin du fichier CSR.

    Returns:
        dict: Dictionnaire contenant les informations du CSR.
    """
    with open(csr_file_path, "rb") as csr_file:
        csr = x509.load_pem_x509_csr(csr_file.read())

    # Récupérer les informations du sujet
    subject_info = {attr.oid._name: attr.value for attr in csr.subject}

    # Récupérer les SANs (noms DNS et IP)
    alt_names = []
    ip_addresses = []

    try:
        san_ext = csr.extensions.get_extension_for_oid(x509.ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
        for name in san_ext.value:
            if isinstance(name, x509.DNSName):
                alt_names.append(name.value)
            elif isinstance(name, x509.IPAddress):
                ip_addresses.append(str(name))
    except x509.ExtensionNotFound:
        pass

    # Préparer le dictionnaire de sortie
    csr_data = {
        "pseudo": subject_info.get("commonName"),
        "company": subject_info.get("organizationName"),
        "city": subject_info.get("localityName"),
        "region": subject_info.get("stateOrProvinceName"),
        "country_code": subject_info.get("countryName"),
        "email": subject_info.get("emailAddress"),
        "alt_names": alt_names,
        "ip_addresses": ip_addresses
    }

    return csr_data


"""
# Exemple d'utilisation
if __name__ == "__main__":
    csr_path = "tmp/csr.pem"  # Chemin vers ton fichier CSR
    csr_info = parseCsr(csr_path)
    print("Informations extraites du CSR :", csr_info)
"""