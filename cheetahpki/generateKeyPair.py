import os
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa, ec
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.asymmetric.ed448 import Ed448PrivateKey
from .exceptions import (KeySaveError,
                         InvalidKeySizeError, KeyPairGenerationError,
                         DirectoryCreationError, UnsupportedAlgorithmError)

_EC_CURVES = {
    "P-256": ec.SECP256R1(),
    "P-384": ec.SECP384R1(),
    "P-521": ec.SECP521R1(),
}

def generateKeyPair(uid: str, key_size: int = 4096, key_directory: str = "tmp/keys",
                    private_key_password: str = None,
                    algorithm: str = "RSA", curve: str = "P-256"):
    """
    Génère une paire de clés et les enregistre dans un sous-dossier avec l'UID du propriétaire.

    Args:
        uid (str): Identifiant unique pour le propriétaire des clés.
        key_size (int): Taille des clés RSA en bits (ignoré pour EC/Ed25519/Ed448). Défaut : 4096.
        key_directory (str): Chemin où les clés seront enregistrées. Défaut : "tmp/keys".
        private_key_password (str, optional): Mot de passe pour chiffrer la clé privée.
        algorithm (str): Algorithme de clé — "RSA" (défaut), "EC", "Ed25519", "Ed448".
        curve (str): Courbe pour ECDSA — "P-256" (défaut), "P-384", "P-521" (ignoré pour RSA/Ed25519/Ed448).

    Returns:
        tuple: (private_key_filename, public_key_filename)

    Raises:
        DirectoryCreationError: Si le répertoire de destination ne peut pas être créé.
        InvalidKeySizeError: Si la taille de clé RSA est invalide.
        UnsupportedAlgorithmError: Si l'algorithme ou la courbe n'est pas supporté(e).
        KeySaveError: Si une erreur survient lors de l'écriture des fichiers.
        KeyPairGenerationError: Si la génération de la paire de clés échoue.
    """

    try:
        if not os.path.exists(key_directory):
            os.makedirs(key_directory)
    except OSError as e:
        raise DirectoryCreationError(f"Erreur lors de la création du répertoire {key_directory}: {e}")

    try:
        if algorithm == "RSA":
            private_key = rsa.generate_private_key(
                public_exponent=65537,
                key_size=key_size,
                backend=default_backend()
            )
        elif algorithm == "EC":
            if curve not in _EC_CURVES:
                raise UnsupportedAlgorithmError(
                    f"Courbe EC non supportée : '{curve}'. Valeurs acceptées : {list(_EC_CURVES.keys())}"
                )
            private_key = ec.generate_private_key(
                curve=_EC_CURVES[curve],
                backend=default_backend()
            )
        elif algorithm == "Ed25519":
            private_key = Ed25519PrivateKey.generate()
        elif algorithm == "Ed448":
            private_key = Ed448PrivateKey.generate()
        else:
            raise UnsupportedAlgorithmError(
                f"Algorithme non supporté : '{algorithm}'. Valeurs acceptées : RSA, EC, Ed25519, Ed448"
            )
    except UnsupportedAlgorithmError:
        raise
    except ValueError as e:
        raise InvalidKeySizeError(f"Taille de clé invalide : {key_size}. Erreur : {e}")
    except Exception as e:
        raise KeyPairGenerationError(f"Erreur lors de la génération de la paire de clés: {e}")

    if private_key_password and not isinstance(private_key_password, str):
        raise ValueError("Le mot de passe doit être une chaîne de caractères valide.")

    encryption_algorithm = (
        serialization.BestAvailableEncryption(private_key_password.encode())
        if private_key_password else serialization.NoEncryption()
    )

    # RSA keeps TraditionalOpenSSL for backward compatibility; EC/Ed* require PKCS8
    private_format = (
        serialization.PrivateFormat.TraditionalOpenSSL
        if algorithm == "RSA"
        else serialization.PrivateFormat.PKCS8
    )

    private_key_filename = os.path.join(key_directory, f"{uid}_private_key.pem")
    try:
        with open(private_key_filename, "wb") as f:
            f.write(private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=private_format,
                encryption_algorithm=encryption_algorithm
            ))
    except IOError as e:
        raise KeySaveError(f"Erreur lors de l'enregistrement de la clé privée dans {private_key_filename}: {e}")

    public_key = private_key.public_key()
    public_key_filename = os.path.join(key_directory, f"{uid}_public_key.pem")
    try:
        with open(public_key_filename, "wb") as f:
            f.write(public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            ))
    except IOError as e:
        raise KeySaveError(f"Erreur lors de l'enregistrement de la clé publique dans {public_key_filename}: {e}")

    return private_key_filename, public_key_filename


def generateKeyPairBytes(key_size: int = 4096,
                         private_key_password: str = None,
                         algorithm: str = "RSA",
                         curve: str = "P-256") -> tuple:
    """
    Génère une paire de clés **en mémoire** et retourne les PEM sous forme de bytes,
    sans écrire aucun fichier sur le filesystem.

    Conçue pour les backends de stockage sécurisé comme HashiCorp Vault :
    la clé privée n'est jamais persistée sur disque.

    Args:
        key_size (int): Taille des clés RSA en bits (ignoré pour EC/Ed25519/Ed448). Défaut : 4096.
        private_key_password (str, optional): Mot de passe pour chiffrer la clé privée.
        algorithm (str): Algorithme de clé — "RSA" (défaut), "EC", "Ed25519", "Ed448".
        curve (str): Courbe pour ECDSA — "P-256" (défaut), "P-384", "P-521".

    Returns:
        tuple: (private_key_pem: bytes, public_key_pem: bytes)
            - private_key_pem : clé privée au format PEM (chiffrée si private_key_password fourni)
            - public_key_pem  : clé publique au format PEM (SubjectPublicKeyInfo)

    Raises:
        InvalidKeySizeError: Si la taille de clé RSA est invalide.
        UnsupportedAlgorithmError: Si l'algorithme ou la courbe n'est pas supporté(e).
        KeyPairGenerationError: Si la génération de la paire de clés échoue.

    Exemple (intégration Vault) :
        priv_pem, pub_pem = generateKeyPairBytes(algorithm="EC", curve="P-256")
        vault.store_private_key(uid=user_id, pem_bytes=priv_pem)
    """
    try:
        if algorithm == "RSA":
            private_key = rsa.generate_private_key(
                public_exponent=65537,
                key_size=key_size,
                backend=default_backend()
            )
        elif algorithm == "EC":
            if curve not in _EC_CURVES:
                raise UnsupportedAlgorithmError(
                    f"Courbe EC non supportée : '{curve}'. Valeurs acceptées : {list(_EC_CURVES.keys())}"
                )
            private_key = ec.generate_private_key(
                curve=_EC_CURVES[curve],
                backend=default_backend()
            )
        elif algorithm == "Ed25519":
            private_key = Ed25519PrivateKey.generate()
        elif algorithm == "Ed448":
            private_key = Ed448PrivateKey.generate()
        else:
            raise UnsupportedAlgorithmError(
                f"Algorithme non supporté : '{algorithm}'. Valeurs acceptées : RSA, EC, Ed25519, Ed448"
            )
    except UnsupportedAlgorithmError:
        raise
    except ValueError as e:
        raise InvalidKeySizeError(f"Taille de clé invalide : {key_size}. Erreur : {e}")
    except Exception as e:
        raise KeyPairGenerationError(f"Erreur lors de la génération de la paire de clés: {e}")

    if private_key_password and not isinstance(private_key_password, str):
        raise ValueError("Le mot de passe doit être une chaîne de caractères valide.")

    encryption_algorithm = (
        serialization.BestAvailableEncryption(private_key_password.encode())
        if private_key_password else serialization.NoEncryption()
    )

    private_format = (
        serialization.PrivateFormat.TraditionalOpenSSL
        if algorithm == "RSA"
        else serialization.PrivateFormat.PKCS8
    )

    private_key_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=private_format,
        encryption_algorithm=encryption_algorithm,
    )
    public_key_pem = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )

    return private_key_pem, public_key_pem


"""
# Exemples d'utilisation :

# RSA 4096 (comportement par défaut — rétrocompatible)
priv, pub = generateKeyPair("alice")

# ECDSA P-256
priv, pub = generateKeyPair("bob", algorithm="EC", curve="P-256")

# ECDSA P-384
priv, pub = generateKeyPair("carol", algorithm="EC", curve="P-384")

# ECDSA P-521
priv, pub = generateKeyPair("dave", algorithm="EC", curve="P-521")

# Ed25519
priv, pub = generateKeyPair("eve", algorithm="Ed25519")

# Ed448
priv, pub = generateKeyPair("frank", algorithm="Ed448")
"""
