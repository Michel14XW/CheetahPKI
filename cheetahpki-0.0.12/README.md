# CheetahPKI


**Version**: 0.0.11  
**Description**: Package pour la génération de paires de clés et de certificats numériques.  

CheetahPKI est un package Python permettant de générer des paires de clés RSA, de créer des certificats auto-signés, des certificats signés par une autorité de certification (CA), et de récupérer des informations sur les certificats.

## Fonctionnalités

- **Génération de paires de clés RSA** : Crée et enregistre des paires de clés avec un identifiant unique.
- **Création de certificats auto-signés** : Génère des certificats pour des autorités racine.
- **Création de certificats signés** : Permet de signer un certificat utilisateur via une clé privée CA.
- **Vérification de validité** : Vérifie la date d'expiration d'un certificat pour confirmer sa validité.
- **Extraction d'informations sur les certificats** : Obtenez des informations telles que le nom du propriétaire, le numéro de série, et les dates de validité.
- **Calculer l'empreinte d'une clé publique et d'un certificat** : Obtenez l'empreinte SHA256 de fichiers comme la clé publique et le certificat.

## Installation

Installez le package via pip (non disponible actuellement sur PyPI) :

```bash
pip install git+https://github.com/Michel14XW/cheetahpki.git
```

## Arborescence du projet

```bash
cheetahpki/
├── generateKeyPair.py
├── exceptions.py
├── fingerprint.py
├── createSelfSignedRootCert.py
├── createSignedCert.py
├── checkCertValidity.py
└── getCertInfo.py
    ├── get_owner
    ├── get_serial_number
    ├── get_validity_end
    └── get_validity_start
```

## Utilisation 

**1. Génération d'une paire de clés**

Fichier : generateKeyPair.py

Fonction : generateKeyPair

```bash

"""
    Génère une paire de clés RSA et les enregistre dans un sous-dossier avec l'UID du propriétaire.
    
    Args:
        uid (str): Identifiant unique pour le propriétaire des clés.
        key_size (int): Taille des clés RSA à générer (par défaut 2048 bits).
        key_directory (str): Nom du sous-dossier où les clés seront enregistrées (par défaut 'keys').
        private_key_password (str, optional): Mot de passe pour chiffrer la clé privée. Si None, pas de chiffrement.
    
    Returns:
        tuple: Chemins des fichiers pour la clé privée et la clé publique.
"""

from cheetahpki.generateKeyPair import generateKeyPair

# Exemple
private_key_path, public_key_path = generateKeyPair(uid='user123')
```

**2. Création d'un certificat auto-signé**

Fichier : createSelfSignedRootCert.py

Fonction : createSelfSignedRootCert

```bash
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
        output_filename (str, optional): Nom du fichier de sortie sans extension. Par défaut 'root_ca_certificate_<UID>'.
    
    Returns:
        str: Chemin du fichier où le certificat auto-signé est enregistré.
"""

from cheetahpki.createSelfSignedRootCert import createSelfSignedRootCert

# Exemple
cert_path = createSelfSignedRootCert(
    pseudo='RootCA',
    company='MyCompany',
    city='Lome',
    country_code='TG',
    valid_days=365,
    private_key_path='path/to/private_key.pem'
)
```

**3. Création d'un certificat signé par la CA Intermediaire**

Fichier : createSignedCert.py

Fonction : createSignedCert

```bash
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
        output_filename (str, optional): Nom du fichier de sortie (sans extension). Par défaut '<pseudo>_certificate'.

    Returns:
        str: Chemin du fichier où le certificat est enregistré.
"""

from cheetahpki.createSignedCert import createSignedCert

# Exemple
cert_path = createSignedCert(
    public_key_path='path/to/public_key.pem',
    uid='user123',
    pseudo='User123',
    company='MyCompany',
    department='IT',
    city='Lome',
    region='Maritime',
    country_code='TG',
    email='user@mycompany.tg',
    valid_days=365,
    ca_private_key_path='path/to/ca_private_key.pem',
    ca_cert_path='path/to/ca_cert.pem'
)

```

**4. Vérification de la validité d'un certificat**

Fichier : checkCertValidity.py

Fonction : checkCertValidity

```bash

"""
    Vérifie la validité d'un certificat en fonction de sa date d'expiration.

    Cette fonction charge un certificat au format PEM, puis vérifie s'il est encore valide
    en comparant sa date d'expiration avec la date et l'heure actuelles.

    Args:
        cert_file (str): Le chemin du fichier PEM contenant le certificat.

    Returns:
        int ou None: Renvoie le nombre de jours restants avant l'expiration du certificat si celui-ci est valide.
                     Renvoie None si le certificat est expiré.
"""

from cheetahpki.checkCertValidity import checkCertValidity

# Exemple
days_remaining = checkCertValidity(cert_file='path/to/cert.pem')
```

**5. Création de certificat Intermediaire signé par une CA Root**

Fichier : createSignedInterCert.py

Fonction : createSignedInterCert

```bash
"""
    Crée un certificat de CA Intermédiaire et le signe avec la clé privée de la CA root.

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
        output_filename (str, optional): Nom du fichier de sortie (sans extension). Par défaut '<pseudo>_certificate'.

    Returns:
        str: Chemin du fichier où le certificat est enregistré.
"""

from cheetahpki.createSignedInterCert import createSignedInterCert

# Exemple
cert_path = createSignedCert(
    public_key_path = "tmp/keys/ca_inter2_public_key.pem",
    pseudo = "CA_inter2",
    company = "MyCompany",
    department = "Juridique",
    city = "Notsè",
    region = "Maritime",
    country_code = "TG",
    email = "cainter2@mycompany.tg",
    valid_days = 365,
    ca_private_key_path = "tmp/keys/root/ca_root_private_key.pem",
    ca_cert_path = "tmp/certificate/root/root_ca_certificate_e80f80d1-c761-48a6-b1a9-db5729f49923.pem",
    ca_key_password = None,
    alt_names = ["cainter.company.tg", "lab.company.local"],
    ip_addresses = ["192.168.1.10"],
    output_folder="tmp/certificate",
    output_filename = "02caInter",
)

```



**6. Extraction d'informations sur le certificat**

Dossier : getCertInfo

**- Obtenir le propriétaire**

Fichier : getOwner.py

```bash

"""
    Prend en entrée un chemin vers un fichier .pem de certificat et retourne le propriétaire du certificat (CN - Common Name).
    
    :param cert_pem_path: Chemin vers le fichier .pem du certificat
    :return: Le nom du propriétaire du certificat (Common Name)
"""

from cheetahpki.getCertInfo.getOwner import getOwner

owner = getOwner(cert_pem_path='path/to/cert.pem')
```

**- Obtenir le numéro de série**

Fichier : getSerialNumber.py

```bash

"""
    Prend en entrée un chemin vers un fichier .pem de certificat et retourne le numéro de série du certificat.
    
    :param cert_pem_path: Chemin vers le fichier .pem du certificat
    :return: Le numéro de série du certificat
"""

from cheetahpki.getCertInfo.getSerialNumber import getSerialNumber

serial_number = getSerialNumber(cert_pem_path='path/to/cert.pem')
```

**- Obtenir la date de début de validité**

Fichier : getValidityStart.py

```bash

"""
    Prend en entrée un chemin vers un fichier .pem de certificat et retourne la date de début de validité du certificat.
    
    :param cert_pem_path: Chemin vers le fichier .pem du certificat
    :return: Date de début de validité du certificat (format datetime)
"""

from cheetahpki.getCertInfo.getValidityStart import getValidityStart

start_date = getValidityStart(cert_pem_path='path/to/cert.pem')
```

**- Obtenir la date de fin de validité**

Fichier : getValidityEnd.py

```bash

"""
    Prend en entrée un chemin vers un fichier .pem de certificat et retourne la date de fin de validité du certificat.
    
    :param cert_pem_path: Chemin vers le fichier .pem du certificat
    :return: Date de fin de validité du certificat (format datetime)
"""

from cheetahpki.getCertInfo.getValidityEnd import getValidityEnd

end_date = getValidityEnd(cert_pem_path='path/to/cert.pem')
```


**7. Générer des fichier CSR**

Fichier : generateCsr.py

Fonction : generateCsr

```bash

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

from cheetahpki.generateCsr import generateCsr

# Exemple
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


```


**8. Générer des fichier CSR**

Fichier : generateCsr.py

Fonction : generateCsr

```bash

"""
    Analyse un fichier CSR au format PEM et extrait les informations nécessaires pour createSignedCert.

    Args:
        csr_file_path (str): Chemin du fichier CSR.

    Returns:
        dict: Dictionnaire contenant les informations du CSR.
"""

from cheetahpki.parseCsr import parseCsr

# Exemple
csr_path = "tmp/csr.pem"  # Chemin vers ton fichier CSR
    csr_info = parseCsr(csr_path)
    print("Informations extraites du CSR :", csr_info)

```


## Licence

Ce projet est sous licence MIT.

Développé pour simplifier la gestion des certificats et de la cryptographie en Python


