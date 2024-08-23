import unittest
import json
from unittest import mock
from src.utils.config import load_config


class TestConfig(unittest.TestCase):

    def test_load_existing_config(self):
        """Test loading an existing configuration file."""
        mock_config = '{"key": "value"}'
        with mock.patch("builtins.open", mock.mock_open(read_data=mock_config)):
            with mock.patch("os.path.exists", return_value=True):
                config = load_config(
                    "/fake/path/config.json", {"default_key": "default_value"}
                )
                self.assertEqual(config["key"], "value")

    def test_load_missing_config(self):
        """Test loading configuration when the file is missing."""
        with mock.patch("os.path.exists", return_value=False):
            config = load_config(
                "/fake/path/config.json", {"default_key": "default_value"}
            )
            self.assertEqual(config["default_key"], "default_value")

    def test_load_malformed_config(self):
        """Test behavior with a malformed configuration file."""
        malformed_config = '{"key": "value"'  # missing closing brace
        with mock.patch("builtins.open", mock.mock_open(read_data=malformed_config)):
            with mock.patch("os.path.exists", return_value=True):
                with self.assertRaises(json.JSONDecodeError):
                    load_config("/fake/path/config.json", {"default_key": "default_value"})



if __name__ == "__main__":
    unittest.main()
