# exceptions.py

class CertificateError(Exception):
    """Classe de base pour les erreurs liées aux certificats."""
    pass

class CertificateFileNotFoundError(CertificateError):
    """Exception levée lorsque le fichier de certificat est introuvable."""
    pass

class CertificateFileEmptyError(CertificateError):
    """Exception levée lorsque le fichier de certificat est vide."""
    pass

class CertificateLoadError(CertificateError):
    """Exception levée lorsque le chargement du certificat échoue."""
    pass

class CertificateSaveError(CertificateError):
    """Exception levée lorsque l'enregistrement du certificat échoue."""
    pass

class CertificateSigningError(CertificateError):
    """Exception levée lorsque la signature du certificat échoue."""
    pass

class InvalidCertificateError(CertificateError):
    """Exception levée lorsque le certificat est invalide ou corrompu."""
    pass

class CertificateDateError(CertificateError):
    """Exception levée lorsque les dates de validité du certificat sont incorrectes."""
    pass


class PrivateKeyFileNotFoundError(CertificateError):
    """Exception levée lorsque le fichier de clé privée est introuvable."""
    pass

class PublicKeyFileNotFoundError(CertificateError):
    """Exception levée lorsque le fichier de clé publique est introuvable."""
    pass

class PrivateKeyLoadError(CertificateError):
    """Exception levée lorsque le chargement de la clé privée échoue."""
    pass

class PublicKeyLoadError(CertificateError):
    """Exception levée lorsque le chargement de la clé publique échoue."""
    pass

class InvalidKeySizeError(CertificateError):
    """Exception levée lorsque la taille de la clé fournie est invalide."""
    pass

class KeyPairGenerationError(CertificateError):
    """Exception levée lorsque la génération de la paire de clés échoue."""
    pass

class KeySaveError(CertificateError):
    """Exception levée lorsque l'enregistrement d'une clé échoue."""
    pass

class DirectoryCreationError(CertificateError):
    """Exception levée lorsqu'il est impossible de créer un répertoire pour stocker les clés ou certificats."""
    pass

class UnsupportedAlgorithmError(CertificateError):
    """Exception levée lorsque l'algorithme ou la courbe cryptographique demandé(e) n'est pas supporté(e)."""
    pass
