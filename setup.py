from setuptools import setup, find_packages

VERSION = '0.0.15'
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
    install_requires=["cryptography >= 43.0.3",
                      "djangorestframework >= 3.15.2"],
    python_requires=">=3.11",
    classifiers=[
        "Programming Language :: Python :: 3.11",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent"
    ]
        
)