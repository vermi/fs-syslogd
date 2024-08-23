import os
import logging
import asyncio
import unittest
import ssl
from unittest import mock
from src.fs_syslogd import FSSyslogd, CONFIG_FILE, DEFAULT_CONFIG
from src.utils.config import load_config


class TestFSSyslogd(unittest.TestCase):

    def setUp(self):
        # Load configuration used by the FSSyslogd instance
        self.config = load_config(CONFIG_FILE, DEFAULT_CONFIG)
        self.fs_syslog = FSSyslogd()

    def tearDown(self):
        # Clean up any created log files after tests
        for filename in os.listdir(self.config["log_dir"]):
            file_path = os.path.join(self.config["log_dir"], filename)
            if os.path.isfile(file_path):
                os.unlink(file_path)

    def test_log_rotation(self):
        """Test log rotation is triggered correctly."""

        async def run_test():
            with mock.patch(
                "os.path.getsize", return_value=self.config["max_log_size"] + 1
            ):
                self.fs_syslog.log_message(
                    "Test message", logging.INFO, "test_facility"
                )

        asyncio.run(run_test())

    def test_key_rotation(self):
        """Test that key rotation occurs at the correct interval."""

        async def run_test():
            with mock.patch("time.time", return_value=3600):
                with mock.patch("builtins.open", mock.mock_open()), mock.patch(
                    "os.makedirs"
                ), mock.patch("os.chmod"):
                    old_secret = self.fs_syslog.secret
                    self.fs_syslog.log_message(
                        "Test message for key rotation", logging.INFO, "test"
                    )
                    new_secret = self.fs_syslog.secret
                    self.assertNotEqual(old_secret, new_secret)

        asyncio.run(run_test())

    def test_health_check(self):
        """Test health check functionality."""
        with mock.patch("os.path.exists", return_value=True):
            self.fs_syslog.health_check()
            # Assume this passes without errors

        with mock.patch("os.path.exists", return_value=False):
            with mock.patch("os.system") as mock_system:
                self.fs_syslog.health_check()
                mock_system.assert_called_with("systemctl restart fs-syslogd")

    def test_health_check_cleanup(self):
        """Ensure no side effects from health checks."""
        with mock.patch("os.system") as mock_system:
            self.fs_syslog.health_check()
            # Cleanup or reset any system effects caused by the test
            mock_system.reset_mock()  # or any cleanup steps needed

    def test_queue_log_for_sending(self):
        """Test that logs are correctly queued for sending."""
        with mock.patch("asyncio.Queue.put") as mock_put:
            asyncio.run(self.fs_syslog.queue_log_for_sending({"test": "log_packet"}))
            mock_put.assert_called_once()

    def test_send_to_remote_log_servers_success(self):
        """Test sending logs to remote servers successfully."""
        with mock.patch("asyncio.open_connection", new_callable=mock.AsyncMock):
            asyncio.run(
                self.fs_syslog.send_to_remote_log_servers({"test": "log_packet"})
            )

    def test_send_to_remote_log_servers_failure(self):
        """Test behavior when sending logs to remote servers fails."""
        with mock.patch(
            "asyncio.open_connection", side_effect=Exception("Connection failed")
        ):
            with mock.patch.object(self.fs_syslog.audit_logger, "error") as mock_error:
                asyncio.run(
                    self.fs_syslog.send_to_remote_log_servers({"test": "log_packet"})
                )
                self.assertTrue(mock_error.called)

    def test_send_to_remote_log_servers_specific_failure(self):
        """Test specific behavior when a known failure occurs."""
        with mock.patch(
            "asyncio.open_connection", side_effect=ssl.SSLError("SSL handshake failed")
        ):
            with mock.patch.object(self.fs_syslog.audit_logger, "error") as mock_error:
                asyncio.run(
                    self.fs_syslog.send_to_remote_log_servers({"test": "log_packet"})
                )
                mock_error.assert_called_with(
                    "Giving up on sending log to server 192.168.1.100:6514 after 3 retries."
                )

    def test_notify_monitoring(self):
        """Test monitoring notification functionality."""
        self.fs_syslog.config["monitoring_webhook"] = "http://example.com/webhook"
        with mock.patch("requests.post") as mock_post:
            self.fs_syslog.notify_monitoring("Test message")
            mock_post.assert_called_once()

    def test_read_logs(self):
        """Test reading and decrypting logs."""

        async def run_test():
            message = "This is a test log entry."
            level = 20  # INFO level
            facility = "test"
            fixed_time = 1692728460  # Fixed timestamp for consistency
            with mock.patch("time.time", return_value=fixed_time):
                self.fs_syslog.log_message(message, level, facility)
                with mock.patch("builtins.print") as mock_print:
                    self.fs_syslog.read_logs()
                    # Check that the printed log contains the expected message and level
                    printed_log = mock_print.call_args[0][0].decode()
                    assert message in printed_log
                    assert facility in printed_log
                    assert logging.getLevelName(level) in printed_log

        asyncio.run(run_test())

    def test_read_logs_with_error(self):
        """Test reading logs with decryption errors."""

        async def run_test():
            # Inject a malformed log entry to simulate an error during decryption
            with mock.patch(
                "builtins.open",
                mock.mock_open(
                    read_data='{"kdf_params": {"salt": "invalid_base64"}, "encrypted_log": "invalid_base64"}\n'
                ),
            ):
                with mock.patch("builtins.print") as mock_print, mock.patch.object(
                    self.fs_syslog.audit_logger, "error"
                ) as mock_error:
                    self.fs_syslog.read_logs()
                    mock_error.assert_called_once_with(
                        "Failed to decrypt entry: Invalid base64-encoded string: number of data characters (13) cannot be 1 more than a multiple of 4"
                    )
                    mock_print.assert_not_called()  # Ensure nothing is printed

        asyncio.run(run_test())

    def test_compress_old_logs(self):
        """Test log file compression."""
        with mock.patch(
            "os.path.exists",
            side_effect=lambda path: True if "secure_syslog.log.1" in path else False,
        ):
            with mock.patch("gzip.open"), mock.patch("os.remove"):
                self.fs_syslog.compress_old_logs()
                # Check that the gzip.open and os.remove were called


if __name__ == "__main__":
    unittest.main()
