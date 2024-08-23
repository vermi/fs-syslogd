from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend


def derive_key(secret: bytes, salt: bytes) -> bytes:
    """
    Derive a cryptographic key using HKDF.

    Args:
        secret (bytes): The base secret key material.
        salt (bytes): A unique salt for this derivation.

    Returns:
        bytes: The derived key.
    """
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        info=b"log-encryption",
        backend=default_backend(),
    )
    return hkdf.derive(secret)
