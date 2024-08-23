import unittest
from src.utils.kdf import derive_key


class TestKDF(unittest.TestCase):

    def test_key_derivation(self):
        secret = b"secret_value"
        salt = b"unique_salt"
        key1 = derive_key(secret, salt)
        key2 = derive_key(secret, salt)
        self.assertEqual(key1, key2)

    def test_different_salts(self):
        secret = b"secret_value"
        salt1 = b"unique_salt1"
        salt2 = b"unique_salt2"
        key1 = derive_key(secret, salt1)
        key2 = derive_key(secret, salt2)
        self.assertNotEqual(key1, key2)

    def test_empty_secret(self):
        """Test behavior with an empty secret."""
        secret = b""
        salt = b"unique_salt"
        key = derive_key(secret, salt)
        self.assertIsNotNone(key)

    def test_long_salt(self):
        """Test behavior with a very long salt."""
        secret = b"secret_value"
        salt = b"long" * 1000  # Very long salt
        key = derive_key(secret, salt)
        self.assertIsNotNone(key)


if __name__ == "__main__":
    unittest.main()
