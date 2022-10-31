#!/usr/bin/env python3

"""
----------------------------------------------------------------------------------------------------
COMP 8505 BTech Network Security & Applications Development
Assignment 2:
    - To become familiar with covert channels and implement a covert channel application.
Student:
    - Hung Yu (Angus) Lin, A01034410, Set 7J
----------------------------------------------------------------------------------------------------
encryption.py
    - Contains the functions for encryption and decryption.
----------------------------------------------------------------------------------------------------
"""

from cryptography.fernet import Fernet
from pathlib import Path


def generate_key():
    """
    Check if key file exists, if not, generates a new .key file.
    :return: None
    """
    my_file = Path("crypto_key.key")
    if not my_file.is_file():
        # key generation and save key to file
        key = Fernet.generate_key()
        with open('crypto_key.key', 'wb') as crypto_key:
            crypto_key.write(key)


def encrypt(data):
    """
    Encrypts binary data with key and returns it.
    :param data: Binary data
    :return: Encrypted data
    """
    # opening the key
    with open('crypto_key.key', 'rb') as crypto_key:
        key = crypto_key.read()

    # using the generated key
    fernet = Fernet(key)
    # encrypting the file
    encrypted_data = fernet.encrypt(data)
    return encrypted_data


def decrypt(encrypted_data):
    """
    Decrypts data with key and returns it.
    :param encrypted_data: Encrypted data
    :return: Binary data
    """
    # opening the key
    with open('crypto_key.key', 'rb') as crypto_key:
        key = crypto_key.read()

    # using the generated key
    fernet = Fernet(key)
    # encrypting the file
    data = fernet.decrypt(encrypted_data)
    return data


