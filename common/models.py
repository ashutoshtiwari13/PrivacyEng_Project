"""
Data models for the privacy-preserving digital credential system.
"""

import json
import time
from dataclasses import dataclass, asdict
from typing import Dict, Any, Optional, List


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
    expiration_date: Optional[int] = None
    index: int = -1  # For revocation purposes
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
    Represents a revocation list using a bitstring approach.
    """
    issuer_id: str
    revoked: List[bool]  # List of booleans, True if revoked
    last_updated: int
    
    def to_json(self):
        """Convert revocation list to JSON string."""
        return json.dumps(asdict(self))
    
    @classmethod
    def from_json(cls, json_str):
        """Create a RevocationList from a JSON string."""
        data = json.loads(json_str)
        return cls(**data)
    
    def is_revoked(self, index):
        """Check if a credential with the given index is revoked."""
        if index < 0 or index >= len(self.revoked):
            return False
        return self.revoked[index]
    
    def revoke(self, index):
        """Revoke a credential by its index."""
        if index < 0:
            return False
        
        # Extend the list if needed
        while len(self.revoked) <= index:
            self.revoked.append(False)
        
        self.revoked[index] = True
        self.last_updated = int(time.time())
        return True
    
    def unrevoke(self, index):
        """Unrevoke a credential by its index."""
        if index < 0 or index >= len(self.revoked):
            return False
        
        self.revoked[index] = False
        self.last_updated = int(time.time())
        return True