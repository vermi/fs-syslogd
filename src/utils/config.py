import json
import os


def load_config(config_file: str, default_config: dict) -> dict:
    """
    Load configuration from a JSON file.

    Args:
        config_file (str): Path to the configuration file.
        default_config (dict): Default configuration values.

    Returns:
        dict: The loaded configuration dictionary.
    """
    if os.path.exists(config_file):
        with open(config_file, "r") as f:
            return json.load(f)
    else:
        return default_config
