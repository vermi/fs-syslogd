import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from base64 import urlsafe_b64encode, urlsafe_b64decode


def encrypt_log_entry(log_entry: str, key: bytes) -> str:
    """
    Encrypt a log entry using AES-GCM.

    Args:
        log_entry (str): The log message to be encrypted.
        key (bytes): The encryption key.

    Returns:
        str: The encrypted log entry in base64 encoding.
    """
    iv = os.urandom(12)
    encryptor = Cipher(
        algorithms.AES(key), modes.GCM(iv), backend=default_backend()
    ).encryptor()

    ciphertext = encryptor.update(log_entry.encode()) + encryptor.finalize()
    return urlsafe_b64encode(iv + encryptor.tag + ciphertext).decode()


def decrypt_log_entry(encrypted_entry: str, key: bytes) -> str:
    """
    Decrypt a log entry using AES-GCM.

    Args:
        encrypted_entry (str): The encrypted log message in base64 encoding.
        key (bytes): The decryption key.

    Returns:
        str: The decrypted log entry.
    """
    encrypted_data = urlsafe_b64decode(encrypted_entry.encode())
    iv = encrypted_data[:12]
    tag = encrypted_data[12:28]
    ciphertext = encrypted_data[28:]

    decryptor = Cipher(
        algorithms.AES(key), modes.GCM(iv, tag), backend=default_backend()
    ).decryptor()

    return decryptor.update(ciphertext) + decryptor.finalize()
