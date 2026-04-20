from cryptography.hazmat.primitives import hashes
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.serialization import load_pem_public_key

def getPublicKeyFingerprint(public_key_pem_path: str) -> str:
    """
    Calcule l'empreinte SHA-256 d'une clé publique au format PEM.

    Args:
        public_key_pem_path (str): Chemin de la clé publique au format PEM.

    Returns:
        str: Empreinte SHA-256 de la clé publique.
    """
    # Lire le fichier contenant la clé publique
    with open(public_key_pem_path, "rb") as file:
        public_key_pem = file.read()

    # Charger la clé publique à partir des données PEM
    public_key = load_pem_public_key(public_key_pem)

    # Obtenir la version DER de la clé publique
    public_key_der = public_key.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    # Calculer le hachage SHA-256
    digest = hashes.Hash(hashes.SHA256())
    digest.update(public_key_der)
    fingerprint = digest.finalize()

    # Retourner l'empreinte sous forme lisible
    return ":".join(f"{byte:02X}" for byte in fingerprint)


"""
# Exemple d'utilisation
fingerprint = getPublicKeyFingerprint("tmp/keys/root/ca_root_public_key.pem")
print(f"Empreinte SHA-256 de la clé publique : {fingerprint}")
"""



def getCertificateFingerprint(certificate_pem_path: str) -> str:
    """
    Calcule l'empreinte SHA-256 d'un certificat au format PEM.

    Args:
        certificate_pem_path (str): Chemin du certificat au format PEM.

    Returns:
        str: Empreinte SHA-256 du certificat.
    """
    # Lire le fichier contenant le certificat
    with open(certificate_pem_path, "rb") as file:
        certificate_pem = file.read()

    # Charger le certificat à partir des données PEM
    certificate = x509.load_pem_x509_certificate(certificate_pem)

    # Calculer l'empreinte SHA-256
    fingerprint = certificate.fingerprint(hashes.SHA256())

    # Retourner l'empreinte sous forme lisible
    return ":".join(f"{byte:02X}" for byte in fingerprint)


"""
# Exemple d'utilisation
fingerprint = getCertificateFingerprint("tmp/certificate/root/root_ca_certificate_e80f80d1-c761-48a6-b1a9-db5729f49923.pem")
print(f"Empreinte SHA-256 du certificat : {fingerprint}")
"""