"""
Common module for shared functionality across the system.
"""

# Create required directories
from .utils import (
    create_directory_if_not_exists,
    get_credentials_dir,
    get_wallets_dir,
    get_revocation_dir
)

# Ensure directories exist
create_directory_if_not_exists(get_credentials_dir())
create_directory_if_not_exists(get_wallets_dir())
create_directory_if_not_exists(get_revocation_dir())