import asyncio
import os
import ssl
import json
import base64
import grp
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import logging
import logging.handlers
from utils.encryption import decrypt_log_entry
from utils.kdf import derive_key

# Receiver Configuration
RECEIVER_CONFIG = {
    "host": "0.0.0.0",
    "port": 6514,
    "tls_cert_file": "/etc/fs-syslogd/receiver.crt",
    "tls_key_file": "/etc/fs-syslogd/receiver.key",
    "tls_ca_cert_file": "/etc/fs-syslogd/ca.crt",
    "output_dir": "/var/log/fs-syslogd-received/",
    "salt_size": 16,  # Size of salt in bytes
    "log_group": "fslogreaders",
    "rotation_size": 10 * 1024 * 1024,  # 10 MB
    "backup_count": 5,
    "shared_secret": "shared_secret_value",
}

# Ensure output directory exists
os.makedirs(RECEIVER_CONFIG["output_dir"], exist_ok=True)

# Set up logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("LogReceiver")

handler = logging.handlers.RotatingFileHandler(
    os.path.join(RECEIVER_CONFIG["output_dir"], "received_logs.log"),
    maxBytes=RECEIVER_CONFIG["rotation_size"],
    backupCount=RECEIVER_CONFIG["backup_count"],
)
logger.addHandler(handler)

# Ensure proper permissions for log files
try:
    os.chown(
        RECEIVER_CONFIG["output_dir"],
        os.getuid(),
        grp.getgrnam(RECEIVER_CONFIG["log_group"]).gr_gid,
    )
    os.chmod(RECEIVER_CONFIG["output_dir"], 0o750)
except Exception as e:
    logger.error(f"Failed to set file permissions: {e}")


async def handle_client(reader, writer):
    """
    Handle incoming client connections and process log entries.

    Args:
        reader (StreamReader): The reader stream for incoming data.
        writer (StreamWriter): The writer stream for outgoing data.
    """
    try:
        data = await reader.readuntil(b"\n")
        log_packet = json.loads(data.decode().strip())

        # Extract the salt from the log packet
        salt = base64.b64decode(log_packet["kdf_params"]["salt"])

        # Derive the key using the shared secret and the extracted salt
        key = derive_key(RECEIVER_CONFIG["shared_secret"].encode(), salt)

        # Decrypt the log entry
        decrypted_entry = decrypt_log_entry(log_packet["encrypted_log"], key)

        # Write the decrypted log entry to a file
        logger.info(decrypted_entry)

        writer.write(b"OK\n")
        await writer.drain()
    except Exception as e:
        logger.error(f"Error handling client: {e}")
    finally:
        writer.close()
        await writer.wait_closed()


async def start_receiver_server():
    """
    Start the log receiver server, accepting and processing log entries.
    """
    context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
    context.load_cert_chain(
        RECEIVER_CONFIG["tls_cert_file"], RECEIVER_CONFIG["tls_key_file"]
    )
    context.load_verify_locations(cafile=RECEIVER_CONFIG["tls_ca_cert_file"])

    server = await asyncio.start_server(
        handle_client, RECEIVER_CONFIG["host"], RECEIVER_CONFIG["port"], ssl=context
    )

    async with server:
        logger.info(
            f"Log Receiver started on {RECEIVER_CONFIG['host']}:{RECEIVER_CONFIG['port']}"
        )
        await server.serve_forever()


if __name__ == "__main__":
    asyncio.run(start_receiver_server())
