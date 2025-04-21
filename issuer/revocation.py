"""
Revocation management for the privacy-preserving digital credential system.
"""

import os
import json
from typing import List, Optional

from common.models import RevocationList
from common.utils import (
    current_timestamp, save_json, load_json, get_revocation_dir
)


class RevocationManager:
    """
    Manages the revocation of credentials using a bitstring approach.
    The bitstring is stored as a list of booleans for simplicity.
    """
    
    def __init__(self, issuer_id: str):
        """
        Initialize the revocation manager for a specific issuer.
        
        Args:
            issuer_id (str): ID of the issuer
        """
        self.issuer_id = issuer_id
        self.revocation_list = self._load_or_create_revocation_list()
    
    def _get_revocation_file_path(self) -> str:
        """Get the file path for the revocation list."""
        return os.path.join(
            get_revocation_dir(), 
            f"revocation_list_{self.issuer_id}.json"
        )
    
    def _load_or_create_revocation_list(self) -> RevocationList:
        """Load the existing revocation list or create a new one."""
        revocation_file = self._get_revocation_file_path()
        
        if os.path.exists(revocation_file):
            # Load existing revocation list
            data = load_json(revocation_file)
            return RevocationList(**data)
        else:
            # Create a new revocation list
            revocation_list = RevocationList(
                issuer_id=self.issuer_id,
                revoked=[],
                last_updated=current_timestamp()
            )
            self._save_revocation_list(revocation_list)
            return revocation_list
    
    def _save_revocation_list(self, revocation_list: Optional[RevocationList] = None) -> None:
        """Save the revocation list to disk."""
        if revocation_list is None:
            revocation_list = self.revocation_list
        
        save_json(
            json.loads(revocation_list.to_json()),
            self._get_revocation_file_path()
        )
    
    def revoke(self, index: int) -> bool:
        """
        Revoke a credential by its index.
        
        Args:
            index (int): Index of the credential to revoke
            
        Returns:
            bool: True if the revocation was successful, False otherwise
        """
        if self.revocation_list.revoke(index):
            self._save_revocation_list()
            return True
        return False
    
    def unrevoke(self, index: int) -> bool:
        """
        Unrevoke a previously revoked credential.
        
        Args:
            index (int): Index of the credential to unrevoke
            
        Returns:
            bool: True if the unrevocation was successful, False otherwise
        """
        if self.revocation_list.unrevoke(index):
            self._save_revocation_list()
            return True
        return False
    
    def is_revoked(self, index: int) -> bool:
        """
        Check if a credential is revoked.
        
        Args:
            index (int): Index of the credential to check
            
        Returns:
            bool: True if the credential is revoked, False otherwise
        """
        return self.revocation_list.is_revoked(index)
    
    def get_public_revocation_list(self) -> dict:
        """
        Get the public revocation list.
        
        Returns:
            dict: The revocation list as a JSON-serializable dictionary
        """
        return json.loads(self.revocation_list.to_json())