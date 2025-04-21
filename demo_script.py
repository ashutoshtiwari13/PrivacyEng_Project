#!/usr/bin/env python
"""
Demonstration script for the privacy-preserving digital credential system.
This script sets up a complete workflow of the system.
"""

import os
import sys
import json
import time
import shutil
from pathlib import Path

# Add the current directory to the Python path
current_dir = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, current_dir)

# Import the system components
from issuer.issuer import create_issuer
from holder.wallet import Wallet
from verifier.verifier import Verifier
from common.utils import create_directory_if_not_exists, get_data_dir, get_credentials_dir, get_wallets_dir, get_revocation_dir


def setup_directories():
    """Set up the necessary directories."""
    print("Setting up directories...")
    data_dir = get_data_dir()
    
    # Clear existing data if any
    if os.path.exists(data_dir):
        shutil.rmtree(data_dir)
    
    # Create directories
    create_directory_if_not_exists(get_credentials_dir())
    create_directory_if_not_exists(get_wallets_dir())
    create_directory_if_not_exists(get_revocation_dir())
    
    print("Directories set up successfully.")


def create_sample_issuer():
    """Create a sample issuer."""
    print("\nCreating issuer...")
    issuer = create_issuer(name="California DMV")
    print(f"Created issuer: {issuer.name} (ID: {issuer.issuer_id})")
    return issuer


def create_sample_wallet():
    """Create a sample wallet."""
    print("\nCreating wallet...")
    wallet = Wallet(name="Alice Johnson")
    print(f"Created wallet for: {wallet.name} (ID: {wallet.holder_id})")
    return wallet


def issue_sample_credential(issuer, wallet):
    """Issue a sample credential from the issuer to the wallet."""
    print("\nIssuing credential...")
    
    # Attributes for a driver's license
    attributes = {
        "name": "Alice Johnson",
        "DOB": "1990-05-15",
        "license_class": "C",
        "state": "California",
        "address": "123 Main St, San Francisco, CA"
    }
    
    # Issue the credential
    credential = issuer.issue_credential(
        holder_id=wallet.holder_id,
        credential_type="driver_license",
        attributes=attributes,
        expiration_date=int(time.time()) + (365 * 86400)  # Valid for 1 year
    )
    
    # Add the credential to the wallet
    wallet.add_credential(credential)
    
    print(f"Issued credential: {credential.id}")
    print(f"Type: {credential.type}")
    print("Attributes:")
    for key, value in credential.attributes.items():
        print(f"  {key}: {value}")
    
    return credential


def create_presentation(wallet, credential):
    """Create a presentation of the credential with selective disclosure."""
    print("\nCreating presentation...")
    
    # Only disclose name and DOB
    selective_disclosure = ["name", "DOB"]
    presentation = wallet.create_presentation(credential.id, selective_disclosure)
    
    print("Created presentation with selective disclosure:")
    print(f"  Included attributes: {', '.join(selective_disclosure)}")
    
    # Save the presentation to a file
    presentation_file = os.path.join(get_data_dir(), "presentation.json")
    with open(presentation_file, 'w') as f:
        json.dump(presentation, f, indent=2)
    
    print(f"Saved presentation to: {presentation_file}")
    
    return presentation


def verify_credential(credential, presentation=None):
    """Verify a credential or presentation."""
    print("\nVerifying credential...")
    verifier = Verifier()
    
    if presentation:
        is_valid, details = verifier.verify_credential(presentation)
        print(f"Verifying presentation for credential: {presentation['credential_id']}")
    else:
        is_valid, details = verifier.verify_credential(credential)
        print(f"Verifying credential: {credential.id}")
    
    if is_valid:
        print("✅ Credential is valid.")
    else:
        print(f"❌ Credential is invalid: {details.get('error', 'Unknown error')}")
    
    return is_valid


def revoke_credential(issuer, credential):
    """Revoke a credential."""
    print("\nRevoking credential...")
    success = issuer.revoke_credential(credential)
    
    if success:
        print(f"✅ Credential {credential.id} has been revoked.")
    else:
        print(f"❌ Failed to revoke credential {credential.id}.")
    
    return success


def run_demo():
    """Run the complete demonstration workflow."""
    print("=" * 80)
    print("Privacy-Preserving Digital Credential System Demo")
    print("=" * 80)
    
    # Setup
    setup_directories()
    
    # Create issuer and wallet
    issuer = create_sample_issuer()
    wallet = create_sample_wallet()
    
    # Issue credential
    credential = issue_sample_credential(issuer, wallet)
    
    # Create presentation
    presentation = create_presentation(wallet, credential)
    
    # Verify credential
    verify_credential(credential)
    
    # Verify presentation
    verify_credential(credential, presentation)
    
    # Revoke credential
    revoke_credential(issuer, credential)
    
    # Verify again (should fail)
    verify_credential(credential)
    
    # Verify presentation again (should fail)
    verify_credential(credential, presentation)
    
    print("\n" + "=" * 80)
    print("Demo completed successfully!")
    print("=" * 80)


if __name__ == "__main__":
    run_demo()