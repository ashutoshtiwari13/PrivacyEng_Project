"""
Utility functions for the privacy-preserving digital credential system.
"""

import os
import json
import time
import uuid
from pathlib import Path


def generate_id():
    """Generate a unique ID for credentials, issuers, or holders."""
    return str(uuid.uuid4())


def current_timestamp():
    """Get the current Unix timestamp."""
    return int(time.time())


def create_directory_if_not_exists(directory):
    """Create a directory if it doesn't exist."""
    Path(directory).mkdir(parents=True, exist_ok=True)


def save_json(data, filepath):
    """Save data as JSON to the specified filepath."""
    # Ensure the parent directory exists
    create_directory_if_not_exists(os.path.dirname(filepath))
    
    # Write the JSON data
    with open(filepath, 'w') as f:
        json.dump(data, f, indent=2)


def load_json(filepath, default=None):
    """Load JSON data from the specified filepath."""
    try:
        with open(filepath, 'r') as f:
            return json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        return default


def get_data_dir():
    """Get the data directory path."""
    # Get the directory of the current file
    current_dir = os.path.dirname(os.path.abspath(__file__))
    # Go up one level to get to the project root
    project_root = os.path.dirname(os.path.dirname(current_dir))
    # Return the data directory path
    return os.path.join(project_root, 'data')


def get_credentials_dir():
    """Get the credentials directory path."""
    return os.path.join(get_data_dir(), 'credentials')


def get_wallets_dir():
    """Get the wallets directory path."""
    return os.path.join(get_data_dir(), 'wallets')


def get_revocation_dir():
    """Get the revocation directory path."""
    return os.path.join(get_data_dir(), 'revocation')