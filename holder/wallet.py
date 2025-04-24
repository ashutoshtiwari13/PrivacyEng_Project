"""
Wallet module for the privacy-preserving digital credential system.
"""

import os
import json
from typing import Dict, List, Any, Optional

from common.models import Credential
from common.utils import (
    generate_id, save_json, load_json, get_wallets_dir, get_credentials_dir
)


class Wallet:
    """
    Digital wallet for storing and presenting credentials.
    """
    
    def __init__(self, holder_id=None, name=None):
        """
        Initialize a wallet for a holder.
        
        Args:
            holder_id (str, optional): ID of the holder.
                If not provided, a new one will be generated.
            name (str, optional): Name of the holder.
        """
        self.holder_id = holder_id or generate_id()
        self.name = name or f"Holder-{self.holder_id[:8]}"
        self.credentials = {}  # Map of credential ID to credential
        
        # Load existing wallet if it exists
        self._load_wallet()
    
    def _get_wallet_file_path(self):
        """Get the file path for the wallet data."""
        return os.path.join(get_wallets_dir(), f"wallet_{self.holder_id}.json")
    
    def _load_wallet(self):
        """Load the wallet data from disk."""
        wallet_file = self._get_wallet_file_path()
        
        if os.path.exists(wallet_file):
            wallet_data = load_json(wallet_file)
            self.holder_id = wallet_data.get('holder_id', self.holder_id)
            self.name = wallet_data.get('name', self.name)
            
            # Load credentials
            credential_ids = wallet_data.get('credential_ids', [])
            for cred_id in credential_ids:
                credential = self._load_credential(cred_id)
                if credential:
                    self.credentials[cred_id] = credential
    
    def _save_wallet(self):
        """Save the wallet data to disk."""
        wallet_data = {
            'holder_id': self.holder_id,
            'name': self.name,
            'credential_ids': list(self.credentials.keys())
        }
        save_json(wallet_data, self._get_wallet_file_path())
    
    def _load_credential(self, credential_id):
        """
        Load a credential from disk.
        
        Args:
            credential_id (str): ID of the credential to load
            
        Returns:
            Credential: The loaded credential, or None if not found
        """
        credential_path = os.path.join(
            get_credentials_dir(), 
            f"credential_{credential_id}.json"
        )
        
        if os.path.exists(credential_path):
            credential_data = load_json(credential_path)
            return Credential(**credential_data)
        
        return None
    
    def add_credential(self, credential):
        """
        Add a credential to the wallet.
        
        Args:
            credential (Credential): The credential to add
        """
        if not isinstance(credential, Credential):
            raise ValueError("Credential should be of type Credential")
        
        # Check if the credential is meant for this holder
        if credential.holder_id != self.holder_id:
            raise ValueError("Credential's holder_id does not match that of the wallet.")
        
        # Add the credential to the wallet
        self.credentials[credential.id] = credential
        
        # Save the wallet
        self._save_wallet()
        
    def get_credential(self, credential_id) -> Optional[Credential]:
        """
        Get a credential from the wallet.
        
        Args:
            credential_id (str): ID of the credential to get
            
        Returns:
            Credential: The credential, or None if not found
        """
        return self.credentials.get(credential_id)

    def list_credentials(self):
        """
        List all credentials in the wallet.
        
        Returns:
            list: List of credentials
        """
        return list(self.credentials.values())
    
    def create_presentation(self, credential_id, selective_disclosure=None):
        """
        Create a presentation of a credential.
        For simplicity, this implementation doesn't actually implement
        selective disclosure or zero-knowledge proofs, but it simulates
        the structure that would be used.
        
        Args:
            credential_id (str): ID of the credential to present
            selective_disclosure (list, optional): List of attributes to disclose
            
        Returns:
            dict: The presentation data
        """
        credential = self.get_credential(credential_id)
        if not credential:
            return None
        
        # This is a simplified presentation without actual ZKPs
        # In a real implementation, this would generate ZKPs for selective disclosure
        presentation = {
            'credential_id': credential.id,
            'issuer_id': credential.issuer_id,
            'holder_id': self.holder_id,
            'type': credential.type,
            'revocation_uuid': credential.revocation_uuid,  # Include for revocation checking
            'proof': credential.non_revoked_proof,
            'signature': credential.signature,
            'attributes': {}
        }
        
        # If selective disclosure is requested, only include those attributes
        if selective_disclosure and isinstance(selective_disclosure, list):
            for attr in selective_disclosure:
                if attr in credential.attributes:
                    presentation['attributes'][attr] = credential.attributes[attr]
        else:
            # Include all attributes
            presentation['attributes'] = credential.attributes.copy()
        
        return presentation
    
    def remove_credential(self, credential_id):
        """
        Remove a credential from the wallet.
        
        Args:
            credential_id (str): ID of the credential to remove
        """
        if credential_id not in self.credentials:
            raise ValueError("Credential does not belong to one of my crednetials!")

        del self.credentials[credential_id]
        self._save_wallet()
        return True
        
