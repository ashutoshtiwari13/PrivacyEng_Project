"""
Issuer module for the privacy-preserving digital credential system.
"""

import os
import json
import time
from typing import Dict, Any, Optional, List, Tuple
from dataclasses import asdict

from common.crypto import CryptoManager
from common.models import Credential, RevocationList
from common.utils import (
    generate_id, current_timestamp, save_json, load_json,
    get_credentials_dir, get_revocation_dir
)
from .revocation import RevocationManager


class Issuer:
    """
    Issuer class responsible for creating and signing credentials.
    """
    
    def __init__(self, issuer_id=None, name=None):
        """
        Initialize an issuer with a unique ID and keys.
        
        Args:
            issuer_id (str, optional): Unique identifier for the issuer.
                If not provided, a new one will be generated.
            name (str, optional): Name of the issuer.
        """
        self.issuer_id = issuer_id or generate_id()
        self.name = name or f"Issuer-{self.issuer_id[:8]}"
        self.credentials_counter = 0
        
        # Load or generate keys
        self._load_or_generate_keys()
        
        # Initialize revocation manager
        self.revocation_manager = RevocationManager(self.issuer_id)
    
    def _load_or_generate_keys(self):
        """Load existing keys or generate new ones."""
        issuer_file = self._get_issuer_file_path()
        
        if os.path.exists(issuer_file):
            # Load existing issuer data
            issuer_data = load_json(issuer_file)
            self.issuer_id = issuer_data.get('issuer_id', self.issuer_id)
            self.name = issuer_data.get('name', self.name)
            self.private_key = issuer_data.get('private_key')
            self.public_key = issuer_data.get('public_key')
            self.credentials_counter = issuer_data.get('credentials_counter', 0)
        else:
            # Generate new keys
            keypair = CryptoManager.generate_keypair()
            self.private_key = keypair['private_key']
            self.public_key = keypair['public_key']
            
            # Save issuer data
            self._save_issuer_data()
    
    def _get_issuer_file_path(self):
        """Get the file path for the issuer data."""
        return os.path.join(get_credentials_dir(), f"issuer_{self.issuer_id}.json")
    
    def _save_issuer_data(self):
        """Save the issuer data to disk."""
        issuer_data = {
            'issuer_id': self.issuer_id,
            'name': self.name,
            'private_key': self.private_key,
            'public_key': self.public_key,
            'credentials_counter': self.credentials_counter
        }
        save_json(issuer_data, self._get_issuer_file_path())
    
    def issue_credential(
        self, 
        holder_id: str, 
        credential_type: str, 
        attributes: Dict[str, Any], 
        expiration_date: Optional[int] = None
    ) -> Credential:
        """
        Issue a new credential to a holder.
        
        Args:
            holder_id (str): ID of the credential holder
            credential_type (str): Type of credential (e.g., "driver_license")
            attributes (dict): Attributes to include in the credential
            expiration_date (int, optional): Unix timestamp for expiration
            
        Returns:
            Credential: The issued credential
        """
        # Generate a unique credential ID
        credential_id = generate_id()
        
        # Get the next index for revocation
        index = self.credentials_counter
        self.credentials_counter += 1
        
        # Create the credential
        credential = Credential(
            id=credential_id,
            holder_id=holder_id,
            issuer_id=self.issuer_id,
            issuer_name=self.name,
            type=credential_type,
            attributes=attributes,
            issuance_date=current_timestamp(),
            expiration_date=expiration_date,
            index=index
        )
        
        # Sign the credential
        signable_data = credential.to_signable_json()
        signature = CryptoManager.sign(self.private_key, signable_data)
        credential.signature = signature
        
        # Save the credential
        credential_path = os.path.join(
            get_credentials_dir(), 
            f"credential_{credential_id}.json"
        )
        save_json(asdict(credential), credential_path)
        
        # Update issuer data to reflect new credential counter
        self._save_issuer_data()
        
        return credential
    
    def revoke_credential(self, credential_or_id) -> bool:
        """
        Revoke a credential.
        
        Args:
            credential_or_id: Either a Credential object or a credential ID
            
        Returns:
            bool: True if the revocation was successful, False otherwise
        """
        # Get the credential
        if isinstance(credential_or_id, Credential):
            credential = credential_or_id
        else:
            credential_path = os.path.join(
                get_credentials_dir(), 
                f"credential_{credential_or_id}.json"
            )
            credential_data = load_json(credential_path)
            if not credential_data:
                return False
            credential = Credential.from_json(json.dumps(credential_data))
        
        # Revoke the credential using the revocation manager
        return self.revocation_manager.revoke(credential.index)
    
    def get_public_info(self) -> Dict[str, Any]:
        """
        Get the public information about the issuer.
        
        Returns:
            dict: Public information
        """
        return {
            'issuer_id': self.issuer_id,
            'name': self.name,
            'public_key': self.public_key
        }


def create_issuer(name=None):
    """
    Create a new issuer.
    
    Args:
        name (str, optional): Name of the issuer
        
    Returns:
        Issuer: A new issuer instance
    """
    return Issuer(name=name)


def load_issuer(issuer_id):
    """
    Load an existing issuer by ID.
    
    Args:
        issuer_id (str): ID of the issuer to load
        
    Returns:
        Issuer: The loaded issuer, or None if not found
    """
    return Issuer(issuer_id=issuer_id)