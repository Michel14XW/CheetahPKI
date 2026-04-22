from cryptography.x509 import load_pem_x509_certificate
from cryptography.hazmat.backends import default_backend
from datetime import datetime, timezone
from .exceptions import (
    CertificateFileNotFoundError,
    CertificateFileEmptyError,
    CertificateLoadError
)

def checkCertValidity(cert_file:str):
    """
    Vérifie la validité d'un certificat en fonction de sa date d'expiration.

    Cette fonction charge un certificat au format PEM, puis vérifie s'il est encore valide
    en comparant sa date d'expiration avec la date et l'heure actuelles.

    Args:
        cert_file (str): Le chemin du fichier PEM contenant le certificat.

    Returns:
        int ou None: Renvoie le nombre de jours restants avant l'expiration du certificat si celui-ci est valide.
                     Renvoie None si le certificat est expiré.

    Raises:
        CertificateFileNotFoundError: Si le fichier de certificat est introuvable.
        CertificateFileEmptyError: Si le fichier de certificat est vide.
        CertificateLoadError: Si le chargement du certificat échoue.
    """
    try:
        # Vérifier si le fichier existe et n'est pas vide
        with open(cert_file, 'rb') as f:
            cert_data = f.read()
            if not cert_data:
                raise CertificateFileEmptyError("Le fichier de certificat est vide.")

        # Charger le certificat
        try:
            cert = load_pem_x509_certificate(cert_data, default_backend())
        except Exception as e:
            raise CertificateLoadError(f"Échec du chargement du certificat : {e}")

        # Obtenir la date actuelle en UTC et la date d'expiration UTC du certificat
        now = datetime.now(timezone.utc)
        not_after = cert.not_valid_after_utc  # Utilisation de not_valid_after_utc directement

        # Calculer le temps restant avant l'expiration
        time_remaining = not_after - now

        # Retourner le nombre de jours restants ou None si expiré
        return time_remaining.days if time_remaining.total_seconds() > 0 else None

    except FileNotFoundError:
        raise CertificateFileNotFoundError("Le fichier de certificat spécifié est introuvable.")
    except Exception as e:
        # Capture toutes autres erreurs inattendues
        raise Exception(f"Une erreur inattendue est survenue : {e}")


"""
# Exemple d'utilisation
try:
    time_left = checkCertValidity("H:/Other computers/HP Victus 16/Cours/M2/Memoire/Dev_vXtend_PKI/Modules_cybersecu/certificate/test1_certificate.pem")
    print(f"Jours avant expiration : {time_left}" if time_left is not None else "Le certificat est expiré.")
except Exception as e:
    print(e)


time_left = checkCertValidity("certificate/test1_certificate.pem")
print(time_left)

"""