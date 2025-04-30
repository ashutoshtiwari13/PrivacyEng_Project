"""
Revocation management for the privacy-preserving digital credential system.
"""

import os
import json
from typing import List, Optional, Tuple

from common.models import RevocationList
from common.crypto import CryptoManager
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
    
    def _get_public_revocation_file_path(self) -> str:
        """Get the file path for the hash-tree root hash (public)."""
        return os.path.join(
            get_revocation_dir(), 
            f"revocation_list_{self.issuer_id}_public.json"
        )
    
    def _get_private_revocation_file_path(self) -> str:
        """Get the file path of the revoked credentials and other metadata."""
        return os.path.join(
            get_revocation_dir(), 
            f"revocation_list_{self.issuer_id}_private.json"
        )
    
    def _load_or_create_revocation_list(self) -> RevocationList:
        """Load the existing revocation list or create a new one."""
        public_revocation_file = self._get_public_revocation_file_path()
        private_revocation_file = self._get_private_revocation_file_path()
        
        if os.path.exists(public_revocation_file):
            # Load existing revocation list
            pub_data = load_json(public_revocation_file)
            priv_data = load_json(private_revocation_file)
            return RevocationList(
                issuer_id=priv_data["issuer_id"],
                non_revoked=priv_data["non_revoked"],
                root_hash=pub_data["root_hash"],
                last_updated=priv_data["last_updated"]
            )
        else:
            # Create a new revocation list
            revocation_list = RevocationList(
                issuer_id=self.issuer_id,
                non_revoked=[],
                root_hash="",
                last_updated=current_timestamp(),
            )
            self._save_revocation_list(revocation_list)
            return revocation_list
    
    def _save_revocation_list(self, revocation_list: Optional[RevocationList] = None) -> None:
        """Save the revocation list to disk."""
        if revocation_list is None:
            revocation_list = self.revocation_list
        
        save_json(
            {"root_hash": revocation_list.root_hash},
            self._get_public_revocation_file_path()
        )

        save_json(
            {
                "issuer_id": revocation_list.issuer_id,
                "non_revoked": revocation_list.non_revoked,
                "last_updated": revocation_list.last_updated,
            },
            self._get_private_revocation_file_path()
        )
    
    def revoke(self, cred_uuid: str):
        """
        Revoke a credential by its index.
        
        Args:
            cred_uuid (string): Revocation UUID of the credential to be revoked
            
        """
        self.revocation_list.revoke(cred_uuid)
        self._save_revocation_list()
    
    def unrevoke(self, cred_uuid: str):
        """
        Unrevoke a previously revoked credential.
        
        Args:
            cred_uuid (string): Revocation UUID of the credential to be revoked
            
        """
        self.revocation_list.unrevoke(cred_uuid)
        self._save_revocation_list()
    
    def is_revoked(self, cred_uuid: str) -> bool:
        """
        Check if a credential is revoked.
        
        Args:
            cred_uuid (string): Revocation UUID of the credential to be revoked
            
        Returns:
            bool: True if the credential is revoked, False otherwise
        """
        return self.revocation_list.is_revoked(cred_uuid)
    
    def get_public_revocation_list(self) -> dict:
        """
        Get the public revocation list.
        
        Returns:
            dict: The revocation list as a JSON-serializable dictionary
        """
        return json.loads(self.revocation_list.to_json())

    def add_credential(self, cred_uuid) -> List[Tuple[str, bool]]:
        """
        Adds the credential uuid to the list of non-revoked credentials, and returns
        a proof of non-revocation.
        
        Returns:
            Proof of non-revocation.
        """
        self.revocation_list.add_credential(cred_uuid)
        self._save_revocation_list()

        return CryptoManager.generate_proof(self.revocation_list.non_revoked, cred_uuid)
