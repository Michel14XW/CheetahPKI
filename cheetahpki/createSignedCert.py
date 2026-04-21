import os
from cryptography import x509
from cryptography.x509.oid import NameOID, AuthorityInformationAccessOID
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey
from cryptography.hazmat.primitives.asymmetric.ec import EllipticCurvePublicKey
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives.asymmetric.ed448 import Ed448PrivateKey, Ed448PublicKey
import datetime
import re

from .exceptions import (
    PublicKeyFileNotFoundError,
    PublicKeyLoadError,
    PrivateKeyFileNotFoundError,
    PrivateKeyLoadError,
    CertificateLoadError,
    CertificateSaveError
)

def _signing_hash(private_key):
    """Retourne l'algorithme de hachage adapté au type de clé privée."""
    if isinstance(private_key, (Ed25519PrivateKey, Ed448PrivateKey)):
        return None
    return hashes.SHA256()

def _end_entity_key_usage(public_key):
    """Retourne les paramètres KeyUsage adaptés au type de clé publique."""
    if isinstance(public_key, RSAPublicKey):
        return x509.KeyUsage(
            digital_signature=True, key_cert_sign=False, crl_sign=False,
            key_encipherment=True, data_encipherment=True,
            content_commitment=False, key_agreement=False,
            encipher_only=False, decipher_only=False
        )
    elif isinstance(public_key, EllipticCurvePublicKey):
        return x509.KeyUsage(
            digital_signature=True, key_cert_sign=False, crl_sign=False,
            key_encipherment=False, data_encipherment=False,
            content_commitment=False, key_agreement=True,
            encipher_only=False, decipher_only=False
        )
    else:
        # Ed25519 / Ed448 : signature uniquement
        return x509.KeyUsage(
            digital_signature=True, key_cert_sign=False, crl_sign=False,
            key_encipherment=False, data_encipherment=False,
            content_commitment=False, key_agreement=False,
            encipher_only=False, decipher_only=False
        )

def is_valid_email(email):
    """ Vérifie si l'email a un format valide. """
    return re.match(r"[^@]+@[^@]+\.[^@]+", email)

def createSignedCert(public_key_path:str, pseudo:str, company:str, department:str, city:str, region:str, country_code:str, email:str,
                     valid_days:int, ca_private_key_path:str, ca_cert_path:str, ca_key_password:str=None, alt_names: list[str] = None,
                     ip_addresses: list[str] = None, output_folder:str="certificate", output_filename:str=None,
                     ocsp_url: str = None, ca_issuers_url: str = None, crl_url: str = None):
    """
    Crée un certificat utilisateur et le signe avec la clé privée de la CA intermédiaire.

    Args:
        public_key_path (str): Chemin vers la clé publique de l'utilisateur à certifier.
        pseudo (str): Nom commun (Common Name) de l'utilisateur ou du serveur.
        company (str): Nom de l'organisation à laquelle l'utilisateur est rattaché.
        department (str): Nom du département ou de l'unité organisationnelle.
        city (str): Ville de résidence ou d'enregistrement de l'utilisateur.
        region (str): Région de résidence ou d'enregistrement de l'utilisateur.
        country_code (str): Code pays ISO à deux lettres (ex. "TG" pour Togo).
        email (str): Adresse email associée à l'utilisateur ou au certificat.
        valid_days (int): Durée de validité du certificat en jours à partir de la date actuelle.
        ca_private_key_path (str): Chemin vers la clé privée de la CA intermédiaire utilisée pour la signature.
        ca_cert_path (str): Chemin vers le certificat de la CA intermédiaire qui signe le certificat utilisateur.
        ca_key_password (str, optional): Mot de passe pour accéder à la clé privée de la CA intermédiaire (laisser vide si aucun).
        alt_names (list[str], optional): Liste des noms DNS alternatifs (SAN) associés au certificat au format ["cainter.test.org", "lab.test.local"].
        ip_addresses (list[str], optional): Liste des adresses IP associées au certificat au format ["192.168.1.1"].
        output_folder (str, optional): Dossier de destination pour enregistrer le certificat. Par défaut "certificate".
        output_filename (str, optional): Nom du fichier de sortie (sans extension). Par défaut "<pseudo>_certificate".
        ocsp_url (str, optional): URL publique du répondeur OCSP. Si fourni, l'extension
            AuthorityInformationAccess (AIA) avec l'OID OCSP sera injectée dans le certificat
            (ex: "http://pki.monentreprise.tg/ocsp/").
        ca_issuers_url (str, optional): URL publique pour télécharger le certificat de la CA
            émettrice. Si fourni, l'extension AIA avec l'OID CA_ISSUERS sera injectée
            (ex: "http://pki.monentreprise.tg/ca.pem").
        crl_url (str, optional): URL publique de la CRL. Si fourni, l'extension
            CRLDistributionPoints sera injectée dans le certificat
            (ex: "http://pki.monentreprise.tg/crl/latest/").

    Returns:
        str: Chemin du fichier où le certificat est enregistré.

    Raises:
        PublicKeyFileNotFoundError: Si le fichier de clé publique de l'utilisateur est introuvable.
        PublicKeyLoadError: Si le chargement de la clé publique échoue.
        CertificateLoadError: Si le chargement du certificat de la CA échoue.
        PrivateKeyFileNotFoundError: Si le fichier de clé privée de la CA intermédiaire est introuvable.
        PrivateKeyLoadError: Si le chargement de la clé privée de la CA échoue.
        CertificateSaveError: Si l'enregistrement du certificat échoue.
    """

    # Convertir les chemins en chemins absolus
    public_key_path = os.path.abspath(public_key_path)
    ca_private_key_path = os.path.abspath(ca_private_key_path)
    ca_cert_path = os.path.abspath(ca_cert_path)
    output_folder = os.path.abspath(output_folder)

    # Valider les paramètres d'entrée
    if not pseudo or not company:
        raise ValueError("Les champs 'pseudo' et 'company' sont obligatoires.")
    
    if not is_valid_email(email):
        raise ValueError("Adresse email invalide.")
    
    if valid_days <= 0:
        raise ValueError("La durée de validité doit être positive.")
    
    import ipaddress  # Gestion des adresses IP dans les SAN
    
    # Charger la clé publique de l'utilisateur
    try:
        with open(public_key_path, "rb") as public_key_file:
            public_key = serialization.load_pem_public_key(
                public_key_file.read(),
                backend=default_backend()
            )
    except FileNotFoundError:
        raise PublicKeyFileNotFoundError(f"Le fichier de clé publique est introuvable : {public_key_path}")
    except Exception as e:
        raise PublicKeyLoadError(f"Erreur lors du chargement de la clé publique ({public_key_path}) : {e}")

    # Charger le certificat de la CA intermédiaire
    try:
        with open(ca_cert_path, "rb") as ca_cert_file:
            ca_cert = x509.load_pem_x509_certificate(
                ca_cert_file.read(),
                backend=default_backend()
            )
    except FileNotFoundError:
        raise CertificateLoadError(f"Le fichier de certificat de la CA intermédiaire est introuvable : {ca_cert_path}")
    except Exception as e:
        raise CertificateLoadError(f"Erreur lors du chargement du certificat de la CA ({ca_cert_path}) : {e}")

    # Charger la clé privée de la CA intermédiaire
    try:
        with open(ca_private_key_path, "rb") as ca_private_key_file:
            ca_private_key = serialization.load_pem_private_key(
                ca_private_key_file.read(),
                password=ca_key_password.encode() if ca_key_password else None,
                backend=default_backend()
            )
    except FileNotFoundError:
        raise PrivateKeyFileNotFoundError(f"Le fichier de clé privée de la CA intermédiaire est introuvable : {ca_private_key_path}")
    except Exception as e:
        raise PrivateKeyLoadError(f"Erreur lors du chargement de la clé privée de la CA ({ca_private_key_path}) : {e}")

    # Créer les informations du sujet (utilisateur)
    subject = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, country_code),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, region),
        x509.NameAttribute(NameOID.LOCALITY_NAME, city),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, company),
        x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, department),
        x509.NameAttribute(NameOID.COMMON_NAME, pseudo),
        x509.NameAttribute(NameOID.EMAIL_ADDRESS, email),
    ])

    # Définir la période de validité du certificat
    valid_from = datetime.datetime.now(datetime.UTC)
    valid_to = valid_from + datetime.timedelta(days=valid_days)

    # Générer un numéro de série unique pour le certificat
    serial_number = x509.random_serial_number()

    # Préparer les extensions
    extensions = [
        (x509.BasicConstraints(ca=False, path_length=None), True),
        (_end_entity_key_usage(public_key), True),
        (x509.ExtendedKeyUsage([
            x509.oid.ExtendedKeyUsageOID.SERVER_AUTH,
            x509.oid.ExtendedKeyUsageOID.CLIENT_AUTH
        ]), False),
        (x509.SubjectAlternativeName(
            [x509.RFC822Name(email)] +
            [x509.DNSName(name) for name in alt_names or []] +
            [x509.IPAddress(ipaddress.ip_address(ip)) for ip in ip_addresses or []]
        ), False),
        (x509.SubjectKeyIdentifier.from_public_key(public_key), False),
        (x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_private_key.public_key()), False),
    ]

    # AuthorityInformationAccess (OCSP + CA issuers) — injectée uniquement si au moins une URL fournie
    aia_descriptions = []
    if ocsp_url:
        aia_descriptions.append(x509.AccessDescription(
            AuthorityInformationAccessOID.OCSP,
            x509.UniformResourceIdentifier(ocsp_url)
        ))
    if ca_issuers_url:
        aia_descriptions.append(x509.AccessDescription(
            AuthorityInformationAccessOID.CA_ISSUERS,
            x509.UniformResourceIdentifier(ca_issuers_url)
        ))
    if aia_descriptions:
        extensions.append((x509.AuthorityInformationAccess(aia_descriptions), False))

    # CRLDistributionPoints — injectée si l'URL de la CRL est fournie
    if crl_url:
        extensions.append((
            x509.CRLDistributionPoints([
                x509.DistributionPoint(
                    full_name=[x509.UniformResourceIdentifier(crl_url)],
                    relative_name=None, reasons=None, crl_issuer=None
                )
            ]),
            False
        ))

    # Construction du certificat utilisateur
    certificate_builder = x509.CertificateBuilder().subject_name(
        subject
    ).issuer_name(
        ca_cert.subject     # Utiliser le sujet de la CA intermédiaire comme émetteur
    ).public_key(
        public_key
    ).serial_number(
        serial_number
    ).not_valid_before(
        valid_from
    ).not_valid_after(
        valid_to
    )

    # Ajouter les extensions
    for ext, critical in extensions:
        certificate_builder = certificate_builder.add_extension(ext, critical=critical)

    # Signer le certificat avec la clé privée de la CA
    certificate = certificate_builder.sign(
        private_key=ca_private_key,
        algorithm=_signing_hash(ca_private_key),
        backend=default_backend()
    )


    # Définir le nom et l'emplacement de sauvegarde du certificat
    output_filename = output_filename or f"{pseudo}_certificate.pem"
    # Ajouter l'extension .pem si elle n'est pas déjà incluse
    if not output_filename.endswith('.pem'):
        output_filename += '.pem'
    output_path = os.path.join(output_folder, output_filename)
    
    # Enregistrer le certificat dans le fichier spécifié
    try:
        os.makedirs(output_folder, exist_ok=True)  # Crée le dossier s'il n'existe pas
        with open(output_path, "wb") as cert_file:
            cert_file.write(certificate.public_bytes(serialization.Encoding.PEM))
    except Exception as e:
        raise CertificateSaveError(f"Erreur lors de l'enregistrement du certificat ({output_path}) : {e}")
    
    return output_path



"""
# Exemple d'utilisation
if __name__ == "__main__":
    public_key_path = input("Chemin de la clé publique : ")
    pseudo = input("Nom ou pseudo de l'utilisateur : ")
    company = input("Nom de la compagnie : ")
    department = input("Département : ")
    city = input("Ville : ")
    region = input("Région : ")
    country_code = input("Code pays (2 lettres) : ")
    email = input("Adresse email : ")
    valid_days = int(input("Durée de validité (jours) : "))
    ca_private_key_path = input("Chemin de la clé privée de la CA intermédiaire : ")
    ca_cert_path = input("Chemin du certificat de la CA intermédiaire : ")
    ca_key_password = input("Mot de passe pour la clé privée de la CA (laisser vide si aucun) : ") or None

    cert_file = createSignedCert(
        public_key_path, pseudo, company, department, city, region, country_code, email,
        valid_days, ca_private_key_path, ca_cert_path, ca_key_password
    )
    print(f"Certificat généré et enregistré à : {cert_file}")
"""

"""
if __name__ == "__main__":
    public_key_path = "tmp/keys/client2_public_key.pem"
    pseudo = "Client2"
    company = "UCAO"
    department = "Juridique"
    city = "Notsè"
    region = "Maritime"
    country_code = "TG"
    email = "client2@ucao.tg"
    valid_days = 90
    ca_private_key_path = "tmp/keys/ca_inter2_private_key.pem"
    ca_cert_path = "tmp/certificate/02caInter.pem"
    ca_key_password = None
    alt_names = ["cainter.ucao.tg", "lab.ucao.local"]
    ip_addresses = ["192.168.1.10"]
    output_folder="tmp/certificate"
    output_filename = "client2_certificate"
    
    

    cert_file = createSignedCert(
        public_key_path, pseudo, company, department, city, region, country_code, email,
        valid_days, ca_private_key_path, ca_cert_path, ca_key_password, alt_names, ip_addresses, output_folder, output_filename
    )
    print(f"Certificat généré et enregistré à : {cert_file}")
"""