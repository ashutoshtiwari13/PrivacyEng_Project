"""
Data models for the privacy-preserving digital credential system.
"""

import json
import time
from dataclasses import dataclass, asdict
from typing import Dict, Any, Optional, List, Tuple
import warnings
from common.crypto import CryptoManager

@dataclass
class Credential:
    """
    Represents a digital credential with all necessary attributes.
    """
    id: str
    holder_id: str
    issuer_id: str
    issuer_name: str
    type: str
    attributes: Dict[str, Any]
    issuance_date: int
    revocation_uuid: str          # For revocation purposes
    non_revoked_proof: List[Tuple[str, bool]]
    expiration_date: Optional[int] = None
    signature: Optional[str] = None
    
    def to_json(self):
        """Convert credential to JSON string."""
        return json.dumps(asdict(self))
    
    @classmethod
    def from_json(cls, json_str):
        """Create a Credential from a JSON string."""
        data = json.loads(json_str)
        return cls(**data)
    
    def to_signable_json(self):
        """
        Convert credential to a JSON string that can be signed.
        Excludes the signature field itself.
        """
        data = asdict(self)
        if 'signature' in data:
            del data['signature']
        return json.dumps(data, sort_keys=True)


@dataclass
class RevocationList:
    """
    Represents a revocation list using the hash-tree approach.
    """
    issuer_id: str
    non_revoked: List[str]  # List of un-revoked credential UUIDs
    root_hash: str
    last_updated: int
    
    def to_json(self):
        """Convert revocation list to JSON string."""
        return json.dumps(asdict(self))
    
    @classmethod
    def from_json(cls, json_str):
        """Create a RevocationList from a JSON string."""
        data = json.loads(json_str)
        return cls(**data)
    
    def is_revoked(self, cred_uuid: str):
        """Check if a credential with the given index is revoked."""
        return cred_uuid in self.non_revoked
    
    def revoke(self, cred_uuid: str):
        """Revoke a credential by its index."""
        try:
            self.non_revoked.remove(cred_uuid)
            self.root_hash = CryptoManager.generate_root_hash(self.non_revoked)
        except ValueError:
            warnings.warn("Credential either does not exist or has already been revoked.")

        self.last_updated = int(time.time())
    
    def unrevoke(self, cred_uuid: str):
        """Unrevoke a credential."""
        if cred_uuid in self.non_revoked:
            warnings.warn("Credential has not been revoked.")
        else:
            self.non_revoked.append(cred_uuid)
            self.root_hash = CryptoManager.generate_root_hash(self.non_revoked)
            
        self.last_updated = int(time.time())   

    def add_credential(self, cred_uuid: str):
        """Add a credential."""
        if cred_uuid in self.non_revoked:
            warnings.warn("Credential already exists.")
        else:
            self.non_revoked.append(cred_uuid)
            self.root_hash = CryptoManager.generate_root_hash(self.non_revoked)
            
        self.last_updated = int(time.time())   
