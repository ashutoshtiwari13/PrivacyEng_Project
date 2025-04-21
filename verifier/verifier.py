"""
Verifier module for the privacy-preserving digital credential system.
"""

import os
import json
from typing import Dict, Any, Optional, List, Tuple

from common.crypto import CryptoManager
from common.models import Credential, RevocationList
from common.utils import (
    current_timestamp, load_json, get_credentials_dir, get_revocation_dir
)


class Verifier:
    """
    Verifier class for validating credentials.
    """
    
    def __init__(self, name=None):
        """
        Initialize a verifier.
        
        Args:
            name (str, optional): Name of the verifier.
        """
        self.name = name or "Verifier"
        self.issuer_cache = {}  # Cache of issuer public keys
        self.revocation_cache = {}  # Cache of revocation lists
    
    def _get_issuer_public_key(self, issuer_id):
        """
        Get the public key of an issuer.
        
        Args:
            issuer_id (str): ID of the issuer
            
        Returns:
            str: The public key, or None if not found
        """
        # Check cache first
        if issuer_id in self.issuer_cache:
            return self.issuer_cache[issuer_id]
        
        # Look for the issuer file
        issuer_file = os.path.join(
            get_credentials_dir(), 
            f"issuer_{issuer_id}.json"
        )
        
        if os.path.exists(issuer_file):
            issuer_data = load_json(issuer_file)
            public_key = issuer_data.get('public_key')
            if public_key:
                self.issuer_cache[issuer_id] = public_key
                return public_key
        
        return None
    
    def _get_revocation_list(self, issuer_id):
        """
        Get the revocation list of an issuer.
        
        Args:
            issuer_id (str): ID of the issuer
            
        Returns:
            RevocationList: The revocation list, or None if not found
        """
        # Check cache first
        if issuer_id in self.revocation_cache:
            # In a real implementation, we'd check if the cache is still valid
            return self.revocation_cache[issuer_id]
        
        # Look for the revocation list file
        revocation_file = os.path.join(
            get_revocation_dir(), 
            f"revocation_list_{issuer_id}.json"
        )
        
        if os.path.exists(revocation_file):
            data = load_json(revocation_file)
            if data:
                revocation_list = RevocationList(**data)
                self.revocation_cache[issuer_id] = revocation_list
                return revocation_list
        
        return None
    
    def verify_credential(self, credential_or_presentation):
        """
        Verify a credential or presentation.
        
        Args:
            credential_or_presentation: Either a Credential object or a presentation dict
            
        Returns:
            tuple: (is_valid, details)
                is_valid (bool): True if the credential is valid
                details (dict): Details about the validation
        """
        # Handle presentation format
        if isinstance(credential_or_presentation, dict):
            # This is a presentation
            presentation = credential_or_presentation
            
            # Get the necessary information
            issuer_id = presentation.get('issuer_id')
            signature = presentation.get('signature')
            index = presentation.get('index')
            
            # For actual verification, we'd need to reconstruct the original credential
            # or verify the ZKPs. This is simplified.
            
            # In this simplified implementation, we just verify the signature
            # and check if the credential is revoked.
            # In a real ZKP implementation, the holder would provide a proof
            # that the credential is valid without revealing its contents.
        else:
            # This is a credential
            credential = credential_or_presentation
            issuer_id = credential.issuer_id
            signature = credential.signature
            index = credential.index
            
            # Prepare the signable data
            # We need to recreate a credential without the signature
            temp_credential = Credential(
                id=credential.id,
                holder_id=credential.holder_id,
                issuer_id=credential.issuer_id,
                issuer_name=credential.issuer_name,
                type=credential.type,
                attributes=credential.attributes,
                issuance_date=credential.issuance_date,
                expiration_date=credential.expiration_date,
                index=credential.index
            )
            signable_data = temp_credential.to_signable_json()
        
        # Get the issuer's public key
        public_key = self._get_issuer_public_key(issuer_id)
        if not public_key:
            return (False, {"error": "Issuer not found"})
        
        # Verify the signature
        if isinstance(credential_or_presentation, dict):
            # For presentation, we can't verify the signature directly
            # In a real implementation, this would involve ZKP verification
            signature_valid = True  # Placeholder for actual verification
        else:
            # Verify the signature directly
            signature_valid = CryptoManager.verify(
                public_key, signable_data, signature
            )
        
        if not signature_valid:
            return (False, {"error": "Invalid signature"})
        
        # Check if the credential is revoked
        revocation_list = self._get_revocation_list(issuer_id)
        if revocation_list and revocation_list.is_revoked(index):
            return (False, {"error": "Credential has been revoked"})
        
        # Check expiration if applicable
        if isinstance(credential_or_presentation, Credential):
            if credential.expiration_date and credential.expiration_date < current_timestamp():
                return (False, {"error": "Credential has expired"})
        
        # All checks passed
        return (True, {"message": "Credential is valid"})