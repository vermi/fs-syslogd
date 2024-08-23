import unittest
from src.utils.encryption import encrypt_log_entry, decrypt_log_entry


class TestEncryption(unittest.TestCase):

    def test_encryption_decryption(self):
        key = b"sixteen byte key"  # Example key
        log_entry = "This is a test log entry."
        encrypted = encrypt_log_entry(log_entry, key)
        decrypted = decrypt_log_entry(encrypted, key)
        self.assertEqual(log_entry, decrypted.decode("utf-8"))

    def test_empty_log_entry(self):
        """Test encryption and decryption of an empty log entry."""
        key = b"sixteen byte key"
        log_entry = ""
        encrypted = encrypt_log_entry(log_entry, key)
        decrypted = decrypt_log_entry(encrypted, key)
        self.assertEqual(log_entry, decrypted.decode("utf-8"))

    def test_invalid_key(self):
        """Test behavior with an incorrect decryption key."""
        key = b"sixteen byte key"
        wrong_key = b"wrong key wrong"
        log_entry = "This is a test log entry."
        encrypted = encrypt_log_entry(log_entry, key)
        with self.assertRaises(Exception):
            decrypt_log_entry(encrypted, wrong_key)


if __name__ == "__main__":
    unittest.main()
