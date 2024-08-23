import asyncio
import os
import json
import unittest
import base64
from src.fs_syslogd import FSSyslogd, CONFIG_FILE, DEFAULT_CONFIG
from src.utils.kdf import derive_key
from src.utils.encryption import decrypt_log_entry
from src.utils.config import load_config


class TestIntegration(unittest.TestCase):
    def setUp(self):
        self.config = load_config(CONFIG_FILE, DEFAULT_CONFIG)
        self.fs_syslog = FSSyslogd()

    def tearDown(self):
        # Clean up any created log files after tests
        for filename in os.listdir(self.config["log_dir"]):
            file_path = os.path.join(self.config["log_dir"], filename)
            if os.path.isfile(file_path):
                os.unlink(file_path)

    def test_end_to_end(self):
        # Ensure this test runs within an event loop
        asyncio.run(self.run_test())

    async def run_test(self):
        message = "This is an integration test log."
        level = 20  # INFO level
        facility = "test"

        # Log the message
        self.fs_syslog.log_message
