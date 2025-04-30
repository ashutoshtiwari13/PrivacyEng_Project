"""
Verifier module for the privacy-preserving digital credential system.
"""

import os
import json

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
    
    def _get_issuer_public_key(self, issuer_id):
        """
        Get the public key of an issuer.
        
        Args:
            issuer_id (str): ID of the issuer
            
        Returns:
            str: The public key, or None if not found
        """
        # Look for the issuer file
        issuer_file = os.path.join(
            get_credentials_dir(), 
            f"issuer_{issuer_id}.json"
        )
        
        if os.path.exists(issuer_file):
            issuer_data = load_json(issuer_file)
            public_key = issuer_data.get('public_key')
            if public_key:
                return public_key
        
        return None
    
    def _get_root_hash(self, issuer_id) -> str:
        """
        Get the revocation list of an issuer.
        
        Args:
            issuer_id (str): ID of the issuer
            
        Returns:
            The value at the root of the hash tree.
        """
        # Look for the revocation list file
        revocation_file = os.path.join(
            get_revocation_dir(), 
            f"revocation_list_{issuer_id}_public.json"
        )
        
        if os.path.exists(revocation_file):
            data = load_json(revocation_file)
            if data:
                return data["root_hash"]
        
        raise ValueError("Revocation entry not found.")
    
    def verify_credential(self, credential: Credential):
        """
        Verify a credential or presentation.
        
        Args:
            credential_or_presentation: Either a Credential object or a presentation dict
            
        Returns:
            tuple: (is_valid, details)
                is_valid (bool): True if the credential is valid
                details (dict): Details about the validation
        """ 
        issuer_id = credential.issuer_id
        signature = credential.signature
        revocation_uuid = credential.revocation_uuid

        signable_data = credential.to_signable_json()
        
        # Get the issuer's public key
        public_key = self._get_issuer_public_key(issuer_id)
        if not public_key:
            return (False, {"error": "Issuer not found"})
        
       # Verify the signature directly
        signature_valid = CryptoManager.verify(
            public_key, signable_data, signature
        )
        
        if not signature_valid:
            return (False, {"error": "Invalid signature"})
        
        # Check if the credential is revoked
        true_root_value = self._get_root_hash(issuer_id)
        if not CryptoManager.check_proof(credential.non_revoked_proof, revocation_uuid, true_root_value):
            return (False, {"error": "Credential was revoked"})
        
        # Check expiration if applicable
        if credential.expiration_date and credential.expiration_date < current_timestamp():
            return (False, {"error": "Credential has expired"})
        
        # All checks passed
        return (True, {"message": "Credential is valid"})