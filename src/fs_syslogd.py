import os
import time
import threading
import ssl
import gzip
import json
import sys
import signal
import asyncio
import base64
import logging
from logging.handlers import RotatingFileHandler
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from base64 import urlsafe_b64encode, urlsafe_b64decode
from ratelimit import limits, sleep_and_retry
from utils.encryption import decrypt_log_entry, encrypt_log_entry
from utils.kdf import derive_key
from utils.config import load_config

# Constants and Configuration
CONFIG_FILE = "/etc/fs-syslogd/fs_syslogd_config.json"
DEFAULT_CONFIG = {
    "log_dir": "/var/log/fs-syslogd/",
    "key_file": "/etc/fs-syslogd/encryption_key.bin",
    "salt_size": 16,  # Size of salt in bytes
    "initial_secret": "initial_secret_value",
    "key_rotation_interval": 3600,
    "max_log_size": 10 * 1024 * 1024,
    "backup_count": 5,
    "remote_log_servers": [
        {
            "address": "192.168.1.100",
            "port": 6514,
            "tls_cert_file": "/etc/fs-syslogd/client.crt",
            "tls_key_file": "/etc/fs-syslogd/client.key",
            "tls_ca_cert_file": "/etc/fs-syslogd/ca.crt",
        }
    ],
    "rate_limit": {"calls": 100, "period": 60},
    "health_check_interval": 300,
    "log_format": "plain",  # Options: plain, json
    "monitoring_webhook": "",
    "max_retries": 3,
    "retry_delay": 5,
}


def reload_config(signum, frame):
    """
    Reload the configuration on receiving SIGHUP.

    Args:
        signum (int): The signal number.
        frame (frame object): The current stack frame.
    """
    global config
    config = load_config(CONFIG_FILE, DEFAULT_CONFIG)
    fs_syslog.audit_logger.info("Configuration reloaded")


config = load_config(CONFIG_FILE, DEFAULT_CONFIG)

# Ensure log directory exists with secure permissions
os.makedirs(config["log_dir"], exist_ok=True)
os.chmod(config["log_dir"], 0o750)


def save_secret(secret: bytes):
    """
    Save the secret to a file with secure permissions.

    Args:
        secret (bytes): The secret key material to save.
    """
    with open(config["key_file"], "wb") as f:
        f.write(secret)
    os.chmod(config["key_file"], 0o600)


def load_secret() -> bytes:
    """
    Load the secret from a file.

    Returns:
        bytes: The loaded secret key material.
    """
    if os.path.exists(config["key_file"]):
        with open(config["key_file"], "rb") as f:
            return f.read()
    else:
        return config["initial_secret"].encode()


class FSSyslogd:
    """
    The main class for the fs-syslogd daemon, responsible for logging messages
    with forward security, encrypting them, and sending them to remote log servers.
    """

    def __init__(self):
        """Initialize the FSSyslogd instance and set up logging."""
        self.config = load_config(CONFIG_FILE, DEFAULT_CONFIG)  # Assign to self.config
        self.secret = load_secret()
        self.lock = threading.Lock()
        self.queue = asyncio.Queue()

        # Set up logging handlers
        self.logger = logging.getLogger("FSSyslogd")
        self.logger.setLevel(logging.DEBUG)

        # File handler for writing logs to disk with rotation
        log_file = os.path.join(self.config["log_dir"], "secure_syslog.log")
        file_handler = RotatingFileHandler(
            log_file,
            maxBytes=self.config["max_log_size"],
            backupCount=self.config["backup_count"],
        )
        self.logger.addHandler(file_handler)

        # Audit log setup
        audit_log_file = os.path.join(self.config["log_dir"], "audit.log")
        self.audit_logger = logging.getLogger("AuditLogger")
        self.audit_logger.setLevel(logging.INFO)
        audit_file_handler = logging.handlers.RotatingFileHandler(
            audit_log_file,
            maxBytes=self.config["max_log_size"],
            backupCount=self.config["backup_count"],
        )
        self.audit_logger.addHandler(audit_file_handler)

    def log_message(self, message: str, level: int, facility: str):
        """
        Log a message with a derived key using a unique salt.

        Args:
            message (str): The log message to be encrypted and logged.
            level (int): The logging level (e.g., logging.INFO).
            facility (str): The log facility (e.g., "auth", "cron").
        """

        @sleep_and_retry
        @limits(
            calls=self.config["rate_limit"]["calls"],
            period=self.config["rate_limit"]["period"],
        )
        def rate_limited_log():
            with self.lock:
                current_time = int(time.time())

                # Rotate key if needed
                if current_time % self.config["key_rotation_interval"] == 0:
                    self.secret = os.urandom(32)  # Rotate to a new random secret
                    save_secret(self.secret)
                    self.audit_logger.info(
                        f"Key rotated at {time.strftime('%Y-%m-%d %H:%M:%S')}"
                    )

                # Generate a unique salt for this log entry
                salt = os.urandom(self.config["salt_size"])

                # Derive the encryption key using the unique salt
                key = derive_key(self.secret, salt)

                # Formatting log entry based on the specified format
                if self.config["log_format"] == "json":
                    log_entry = json.dumps(
                        {
                            "timestamp": time.strftime(
                                "%Y-%m-%dT%H:%M:%SZ", time.gmtime(current_time)
                            ),
                            "facility": facility,
                            "level": logging.getLevelName(level),
                            "message": message,
                        }
                    )
                else:
                    log_entry = f"{time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime(current_time))} {facility} {logging.getLevelName(level)}: {message}"

                # Encrypt the log entry
                encrypted_entry = encrypt_log_entry(log_entry, key)

                # Package the encrypted log entry with the salt
                log_packet = {
                    "kdf_params": {"salt": base64.b64encode(salt).decode("utf-8")},
                    "encrypted_log": encrypted_entry,
                }

                # Log to file
                self.logger.log(level, json.dumps(log_packet))

                # Queue the log for asynchronous sending
                asyncio.create_task(self.queue_log_for_sending(log_packet))

        rate_limited_log()

    async def queue_log_for_sending(self, log_packet: dict):
        """
        Queue log entry for sending to remote log servers.

        Args:
            log_packet (dict): The log packet containing the encrypted log and KDF parameters.
        """
        await self.queue.put(log_packet)

    async def send_queued_logs(self):
        """
        Process the log queue and send logs to remote servers.
        """
        while True:
            log_packet = await self.queue.get()
            await self.send_to_remote_log_servers(log_packet)
            self.queue.task_done()

    async def send_to_remote_log_servers(self, log_packet: dict):
        """
        Send the log entry to remote syslog servers using TLS.

        Args:
            log_packet (dict): The log packet containing the encrypted log and KDF parameters.
        """
        for server in self.config["remote_log_servers"]:
            retries = 0
            while retries < self.config["max_retries"]:
                try:
                    context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
                    context.load_cert_chain(
                        certfile=server["tls_cert_file"], keyfile=server["tls_key_file"]
                    )
                    context.load_verify_locations(cafile=server["tls_ca_cert_file"])
                    context.check_hostname = False

                    reader, writer = await asyncio.open_connection(
                        server["address"], server["port"], ssl=context
                    )
                    writer.write((json.dumps(log_packet) + "\n").encode())
                    await writer.drain()
                    writer.close()
                    await writer.wait_closed()
                    break
                except Exception as e:
                    retries += 1
                    self.audit_logger.error(
                        f"Failed to send log to remote server {server['address']}:{server['port']} (Attempt {retries}): {e}"
                    )
                    self.notify_monitoring(
                        f"Failed to send log to remote server {server['address']}:{server['port']} (Attempt {retries}): {e}"
                    )
                    await asyncio.sleep(self.config["retry_delay"])
            if retries >= self.config["max_retries"]:
                self.audit_logger.error(
                    f"Giving up on sending log to server {server['address']}:{server['port']} after {self.config['max_retries']} retries."
                )

    def notify_monitoring(self, message: str):
        """
        Send error notifications to a monitoring system.

        Args:
            message (str): The error message to send.
        """
        if self.config["monitoring_webhook"]:
            try:
                import requests

                requests.post(self.config["monitoring_webhook"], json={"text": message})
            except Exception as e:
                self.audit_logger.error(f"Failed to send monitoring notification: {e}")

    def read_logs(self):
        """
        Read and decrypt all log entries from the log file.
        """
        log_file = os.path.join(self.config["log_dir"], "secure_syslog.log")
        with open(log_file, "r") as f:
            for line in f:
                try:
                    log_packet = json.loads(line.strip())
                    salt = base64.b64decode(log_packet["kdf_params"]["salt"])
                    key = derive_key(self.secret, salt)
                    decrypted_entry = decrypt_log_entry(
                        log_packet["encrypted_log"], key
                    )
                    print(decrypted_entry)
                except Exception as e:
                    self.audit_logger.error(f"Failed to decrypt entry: {e}")

    def compress_old_logs(self):
        """
        Compress old log files to save disk space.
        """
        for i in range(1, self.config["backup_count"] + 1):
            log_file = os.path.join(self.config["log_dir"], f"secure_syslog.log.{i}")
            if os.path.exists(log_file) and not os.path.exists(f"{log_file}.gz"):
                with open(log_file, "rb") as f_in:
                    with gzip.open(f"{log_file}.gz", "wb") as f_out:
                        f_out.writelines(f_in)
                os.remove(log_file)
                self.audit_logger.info(
                    f"Compressed and removed old log file {log_file}"
                )

    def health_check(self):
        """
        Perform health checks and self-healing operations.
        """
        try:
            # Example health check: Ensure logs are being written correctly
            log_file = os.path.join(self.config["log_dir"], "secure_syslog.log")
            if not os.path.exists(log_file):
                raise Exception("Log file missing")

            # Additional health checks can be added here

        except Exception as e:
            self.audit_logger.error(f"Health check failed: {e}")
            # Self-healing logic: Restart daemon, alert admin, etc.
            os.system("systemctl restart fs-syslogd")
            self.notify_monitoring(
                f"fs-syslogd restarted due to health check failure: {e}"
            )

    def run(self):
        """
        Run the logging service and process log entries.
        """
        loop = asyncio.get_event_loop()
        asyncio.ensure_future(self.send_queued_logs())
        loop.run_forever()


# Daemonize the script
if __name__ == "__main__":

    def display_help():
        """Display help information for the fs-syslogd daemon."""
        print("fs-syslogd: Forward Secure Syslog Daemon")
        print("Usage: fs-syslogd [start|stop|status|help]")
        print("  start  : Start the fs-syslogd service")
        print("  stop   : Stop the fs-syslogd service")
        print("  status : Check the status of the fs-syslogd service")
        print("  help   : Display this help message")

    if len(sys.argv) < 2:
        display_help()
        sys.exit(1)

    command = sys.argv[1].lower()

    if command == "start":
        import daemon

        signal.signal(signal.SIGHUP, reload_config)

        def shutdown_handler(signum, frame):
            """Handle shutdown signals."""
            fs_syslog.audit_logger.info("Shutting down fs-syslogd.")
            sys.exit(0)

        fs_syslog = FSSyslogd()

        with daemon.DaemonContext(
            signal_map={
                signal.SIGTERM: shutdown_handler,
                signal.SIGINT: shutdown_handler,
            }
        ):
            fs_syslog.run()

    elif command == "stop":
        os.system("systemctl stop fs-syslogd")

    elif command == "status":
        os.system("systemctl status fs-syslogd")

    elif command == "help":
        display_help()

    else:
        display_help()
