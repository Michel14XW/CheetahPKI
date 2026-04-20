from cryptography import x509
from cryptography.hazmat.backends import default_backend


def get_owner(cert_pem_path:str):
    """
    Prend en entrée un chemin vers un fichier .pem de certificat et retourne le propriétaire du certificat (CN - Common Name).
    
    :param cert_pem_path: Chemin vers le fichier .pem du certificat
    :return: Le nom du propriétaire du certificat (Common Name)
    """
    # Charger le certificat depuis le fichier PEM
    with open(cert_pem_path, 'rb') as cert_file:
        cert_data = cert_file.read()
    
    # Charger le certificat en utilisant la bibliothèque cryptography
    cert = x509.load_pem_x509_certificate(cert_data, default_backend())
    
    # Extraire les informations du sujet (le propriétaire)
    subject = cert.subject
    
    # Rechercher le champ "Common Name" (CN) dans le sujet
    owner_name = subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)[0].value
    
    return owner_name



"""
# Exemple d'utilisation
cert_path = "certificate/test1_certificate.pem"
owner = get_owner(cert_path)
print(f"Le propriétaire du certificat est : {owner}")
"""




def get_serial_number(cert_pem_path:str):
    """
    Prend en entrée un chemin vers un fichier .pem de certificat et retourne le numéro de série du certificat.
    
    :param cert_pem_path: Chemin vers le fichier .pem du certificat
    :return: Le numéro de série du certificat
    """
    # Charger le certificat depuis le fichier PEM
    with open(cert_pem_path, 'rb') as cert_file:
        cert_data = cert_file.read()
    
    # Charger le certificat en utilisant la bibliothèque cryptography
    cert = x509.load_pem_x509_certificate(cert_data, default_backend())
    
    # Extraire le numéro de série du certificat
    serial_number = cert.serial_number
    
    return serial_number


"""
# Exemple d'utilisation
cert_path = "certificate/test1_certificate.pem"
serial_number = get_serial_number(cert_path)
print(f"Le numéro de série du certificat est : {serial_number}")
"""




def get_validity_end(cert_pem_path:str):
    """
    Prend en entrée un chemin vers un fichier .pem de certificat et retourne la date de fin de validité du certificat.
    
    :param cert_pem_path: Chemin vers le fichier .pem du certificat
    :return: Date de fin de validité du certificat (format datetime)
    """
    # Charger le certificat depuis le fichier PEM
    with open(cert_pem_path, 'rb') as cert_file:
        cert_data = cert_file.read()
    
    # Charger le certificat en utilisant la bibliothèque cryptography
    cert = x509.load_pem_x509_certificate(cert_data, default_backend())
    
    # Extraire la date de fin de validité du certificat
    validity_end = cert.not_valid_after_utc
    
    return validity_end


"""
# Exemple d'utilisation
cert_path = "certificate/test1_certificate.pem"
validity_end = get_validity_end(cert_path)
print(f"Le certificat expire le : {validity_end}")
"""





def get_validity_start(cert_pem_path:str):
    """
    Prend en entrée un chemin vers un fichier .pem de certificat et retourne la date de début de validité du certificat.
    
    :param cert_pem_path: Chemin vers le fichier .pem du certificat
    :return: Date de début de validité du certificat (format datetime)
    """
    # Charger le certificat depuis le fichier PEM
    with open(cert_pem_path, 'rb') as cert_file:
        cert_data = cert_file.read()
    
    # Charger le certificat en utilisant la bibliothèque cryptography
    cert = x509.load_pem_x509_certificate(cert_data, default_backend())
    
    # Extraire la date de début de validité du certificat
    validity_start = cert.not_valid_before_utc
    
    return validity_start



"""
# Exemple d'utilisation
cert_path = "certificate/test1_certificate.pem"
validity_start = get_validity_start(cert_path)
print(f"Le certificat est valide à partir de : {validity_start}")
"""
