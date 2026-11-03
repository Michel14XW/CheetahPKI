from setuptools import setup, find_packages

VERSION = '0.0.23'
DESCRIPTION = 'Package generation de paire de clé et de certificats numeriques'
LONG_DESCRIPTION = 'Un package pour creer une paire de clés, de créer des certificats auto signé, des certificat signé par une autorité et de récuperer certaines informations sur le certificat'

setup(
    name="cheetahpki",
    version=VERSION,
    author="passah michel kpekpassi",
    author_email="kpekpassimichel@gmail.com",
    url="https://github.com/Michel14XW/cheetahpki",
    description=DESCRIPTION,
    long_description=LONG_DESCRIPTION,
    packages=find_packages(),
    readme="README.md",
    # Seule dépendance d'exécution réelle (0.0.23) : `cryptography`, avec un
    # plancher de sécurité (toutes les versions < 50.0.0 ont des avis pip-audit
    # connus, dont PYSEC-2026-3552/3553/3554 et GHSA-537c-gmf6-5ccf).
    # `djangorestframework` (déclaré jusqu'en 0.0.22) n'est importé nulle part
    # dans le paquet : retiré.
    install_requires=["cryptography>=50.0.0"],
    extras_require={
        # Backend post-quantique de production (module `oqs`). Nécessite la
        # bibliothèque C liboqs (variable OQS_INSTALL_PATH). Sans lui, le
        # module `pqc` bascule sur le fallback Python natif (ML-DSA-65, R&D).
        "pqc": ["liboqs-python>=0.14"],
        "test": ["pytest>=8"],
    },
    python_requires=">=3.11",
    classifiers=[
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        "Programming Language :: Python :: 3.13",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent"
    ]
        
)