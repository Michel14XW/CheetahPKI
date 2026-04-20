import os
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.asymmetric.ed448 import Ed448PrivateKey
import datetime
import uuid
import re

from .exceptions import (
    PrivateKeyFileNotFoundError,
    PrivateKeyLoadError,
    CertificateSaveError
)

def _signing_hash(private_key):
    """Retourne l'algorithme de hachage adapté au type de clé privée."""
    if isinstance(private_key, (Ed25519PrivateKey, Ed448PrivateKey)):
        return None  # Ed25519/Ed448 gèrent le hachage en interne
    return hashes.SHA256()

def is_valid_email(email):
    """ Vérifie si l'email a un format valide. """
    return re.match(r"[^@]+@[^@]+\.[^@]+", email)

def createSelfSignedRootCert(pseudo:str, company:str, city:str, region:str, country_code:str, email:str, 
                             valid_days:int, private_key_path:str, key_password:str=None, 
                             output_folder:str=None, output_filename:str=None):
    """
    Crée un certificat auto-signé pour une CA root sans champ département.

    Args:
        pseudo (str): Nom commun ou pseudo de la CA root.
        company (str): Compagnie à laquelle appartient la CA root.
        city (str): Ville de résidence de la CA root.
        region (str): Région de la CA root.
        country_code (str): Code pays ISO à deux lettres.
        email (str): Adresse email de contact pour la CA root.
        valid_days (int): Durée de validité du certificat en jours.
        private_key_path (str): Chemin vers la clé privée de la CA root.
        key_password (str, optional): Mot de passe pour déchiffrer la clé privée de la CA root (si nécessaire).
        output_folder (str, optional): Dossier de destination du certificat. Par défaut "certificate".
        output_filename (str, optional): Nom du fichier de sortie sans extension. Par défaut "root_ca_certificate_<UID>".

    Returns:
        str: Chemin du fichier où le certificat auto-signé est enregistré.

    Raises:
        PrivateKeyFileNotFoundError: Si le fichier de clé privée est introuvable.
        PrivateKeyLoadError: Si le chargement de la clé privée échoue.
        CertificateSaveError: Si l'enregistrement du certificat échoue.
    """

    # Valider les paramètres d'entrée
    if not pseudo or not company:
        raise ValueError("Les champs 'pseudo' et 'company' sont obligatoires.")
    
    if not is_valid_email(email):
        raise ValueError("Adresse email invalide.")

    if valid_days <= 0:
        raise ValueError("La durée de validité doit être positive.")

    # Résoudre le chemin complet du fichier de la clé privée
    private_key_path = os.path.abspath(private_key_path)
    
    # Charger la clé privée de la CA root
    try:
        with open(private_key_path, "rb") as private_key_file:
            private_key = serialization.load_pem_private_key(
                private_key_file.read(),
                password=key_password.encode() if key_password else None,
                backend=default_backend()
            )
    except FileNotFoundError:
        raise PrivateKeyFileNotFoundError(f"Le fichier de clé privée est introuvable au chemin spécifié : {private_key_path}")
    except (ValueError, TypeError) as e:
        raise PrivateKeyLoadError(f"Échec du chargement de la clé privée ({private_key_path}) : {e}")

    # Créer les informations du sujet (la CA root elle-même)
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, country_code),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, region),
        x509.NameAttribute(NameOID.LOCALITY_NAME, city),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, company),
        x509.NameAttribute(NameOID.COMMON_NAME, pseudo),
        x509.NameAttribute(NameOID.EMAIL_ADDRESS, email),
    ])

    # Définir la période de validité du certificat
    valid_from = datetime.datetime.now(datetime.UTC)
    valid_to = valid_from + datetime.timedelta(days=valid_days)

    # Générer un numéro de série unique pour le certificat
    serial_number = x509.random_serial_number()

    # Créer le certificat auto-signé
    certificate = x509.CertificateBuilder().subject_name(
        subject
    ).issuer_name(
        issuer
    ).public_key(
        private_key.public_key()
    ).serial_number(
        serial_number
    ).not_valid_before(
        valid_from
    ).not_valid_after(
        valid_to
    ).add_extension(
        x509.BasicConstraints(ca=True, path_length=None),  # Indique que c'est un certificat CA
        critical=True
    ).add_extension(
        x509.KeyUsage(
            digital_signature=True,
            key_cert_sign=True,
            crl_sign=True,
            key_encipherment=False,
            data_encipherment=False,
            content_commitment=False,
            key_agreement=False,
            encipher_only=False,
            decipher_only=False
        ),
        critical=True
    ).add_extension(
        x509.SubjectKeyIdentifier.from_public_key(private_key.public_key()),
        critical=False
    ).sign(
        private_key=private_key,
        algorithm=_signing_hash(private_key),
        backend=default_backend()
    )

    # Définir le dossier de destination
    output_folder = output_folder or 'certificate'
    os.makedirs(output_folder, exist_ok=True)

    # Définir le nom du fichier de sortie avec UID par défaut si aucun nom n'est spécifié
    if not output_filename:
        uid = uuid.uuid4()
        output_filename = f"root_ca_certificate_{uid}"
    
    # Ajouter l'extension .pem si elle n'est pas déjà incluse
    if not output_filename.endswith('.pem'):
        output_filename += '.pem'

    cert_filename = os.path.join(output_folder, output_filename)

    # Enregistrer le certificat dans le fichier spécifié
    try:
        with open(cert_filename, "wb") as cert_file:
            cert_file.write(certificate.public_bytes(serialization.Encoding.PEM))
    except OSError as e:
        raise CertificateSaveError(f"Échec de l'enregistrement du certificat : {e}")

    return cert_filename




"""
# Exemple d'utilisation
if __name__ == "__main__":
    pseudo = input("Entrez le nom ou pseudo de la CA root : ")
    company = input("Entrez la compagnie de la CA root : ")
    city = input("Entrez la ville de résidence de la CA root : ")
    region = input("Entrez la région de résidence de la CA root : ")
    country_code = input("Entrez le code pays (2 lettres) : ")
    email = input("Entrez l'email de la CA root : ")
    valid_days = int(input("Entrez la durée de validité du certificat (en jours) : "))

    # Informations pour la CA root
    private_key_path = input("Entrez le chemin vers la clé privée de la CA root : ")
    key_password = input("Entrez le mot de passe de la clé privée de la CA root (laisser vide si aucun) : ") or None
    output_folder = input("Entrez le dossier de destination du certificat (laisser vide pour 'certificate') : ") or None
    output_filename = input("Entrez le nom du fichier de sortie (sans extension, laisser vide pour générer un nom par défaut) : ") or None

    try:
        cert_file = createSelfSignedRootCert(pseudo, company, city, region, country_code, email, valid_days, private_key_path, key_password, output_folder, output_filename)
        print(f"Certificat CA root auto-signé enregistré sous: {cert_file}")
    except Exception as e:
        print(e)
"""

"keys/root/root_CA_private_key.pem"

"""
# Exemple d'utilisation
if __name__ == "__main__":
    pseudo = "ca_root"
    company = "UCAO"
    city = "Lomé"
    region = "Maritime"
    country_code = "TG"
    email = "caroot@ucao.tg"
    valid_days = 3650
    private_key_path = "tmp/keys/root/ca_root_private_key.pem"
    key_password = None
    output_folder = "tmp/certificate/root"
    output_filename = None
    
    try:
        cert_file = createSelfSignedRootCert(pseudo, company, city, region, country_code, email, valid_days, private_key_path, key_password, output_folder, output_filename)
        print(f"Certificat CA root auto-signé enregistré sous: {cert_file}")
    except Exception as e:
        print(e)
"""