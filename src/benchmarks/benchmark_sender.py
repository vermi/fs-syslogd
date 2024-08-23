import time
import random
import string
import logging
from src.fs_syslogd import FSSyslogd


def generate_log_message(length=100):
    """
    Generate a random log message of specified length.

    Args:
        length (int): The length of the generated log message.

    Returns:
        str: The generated random log message.
    """
    return "".join(random.choices(string.ascii_letters + string.digits, k=length))


def run_load_test(syslogd_instance, num_logs=1000):
    """
    Run a load test by sending a number of log messages.

    Args:
        syslogd_instance (FSSyslogd): The fs-syslogd instance.
        num_logs (int): Number of log messages to generate and send.
    """
    for i in range(num_logs):
        message = generate_log_message()
        syslogd_instance.log_message(message, logging.INFO, "test")
        time.sleep(0.01)  # Optional sleep to simulate some delay between logs


if __name__ == "__main__":
    fs_syslog = FSSyslogd()
    run_load_test(fs_syslog, num_logs=1000)
