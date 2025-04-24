"""
Cryptographic utilities for the privacy-preserving digital credential system.
"""

import base64
from typing import List, Tuple
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives import serialization
from hashlib import sha256

class CryptoManager:
    """
    Manages cryptographic operations for digital credentials.
    Uses Ed25519 for digital signatures due to its security and efficiency.
    """
    
    @staticmethod
    def generate_keypair():
        """Generate an Ed25519 keypair."""
        private_key = ed25519.Ed25519PrivateKey.generate()
        public_key = private_key.public_key()
        
        # Serialize keys for storage
        private_bytes = private_key.private_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PrivateFormat.Raw,
            encryption_algorithm=serialization.NoEncryption()
        )
        
        public_bytes = public_key.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw
        )
        
        return {
            'private_key': base64.b64encode(private_bytes).decode('utf-8'),
            'public_key': base64.b64encode(public_bytes).decode('utf-8')
        }
    
    @staticmethod
    def sign(private_key_b64, message):
        """
        Sign a message using the private key.
        
        Args:
            private_key_b64 (str): Base64-encoded private key
            message (str): Message to sign
            
        Returns:
            str: Base64-encoded signature
        """
        # Decode private key from base64
        private_bytes = base64.b64decode(private_key_b64)
        private_key = ed25519.Ed25519PrivateKey.from_private_bytes(private_bytes)
        
        # Sign the message
        signature = private_key.sign(message.encode('utf-8'))
        
        # Return base64-encoded signature
        return base64.b64encode(signature).decode('utf-8')
    
    @staticmethod
    def verify(public_key_b64, message, signature_b64):
        """
        Verify a signature using the public key.
        
        Args:
            public_key_b64 (str): Base64-encoded public key
            message (str): Original message
            signature_b64 (str): Base64-encoded signature
            
        Returns:
            bool: True if the signature is valid, False otherwise
        """
        # Decode public key and signature from base64
        public_bytes = base64.b64decode(public_key_b64)
        public_key = ed25519.Ed25519PublicKey.from_public_bytes(public_bytes)
        
        signature = base64.b64decode(signature_b64)
        
        try:
            # Verify the signature
            public_key.verify(signature, message.encode('utf-8'))
            return True
        except Exception:
            return False

    
    @staticmethod
    def hash_sha256(data: str) -> str:
        return sha256(data.encode("utf-8")).hexdigest()
    
    @staticmethod
    def generate_root_hash(leaves: List[str]):
        """Generates a Merkle Tree and returns the root hash"""
        if len(leaves) == 0:
            return CryptoManager.hash_sha256("")

        # Hash the leaves to create the first level of the tree
        layer = [CryptoManager.hash_sha256(leaf) for leaf in leaves]

        # Build the tree upwards
        while len(layer) > 1:
            if len(layer) % 2 != 0:  # If there's an odd number, duplicate the last element
                layer.append(layer[-1])
            
            # Hash each pair of nodes
            layer = [CryptoManager.hash_sha256(layer[i] + layer[i + 1]) for i in range(0, len(layer), 2)]

        assert len(layer) == 1, f"Expected length 1 but was length {len(layer)}"
        return layer[0]  # The root of the Merkle tree

    @staticmethod
    def generate_proof(leaves: List[str], cred_uuid: str) -> List[Tuple[str, bool]]:
        if cred_uuid not in leaves:
            raise ValueError("Cannot generate a proof for a revoked credential.")
        
        proof = []

        # Hash the leaves to create the first level of the tree
        layer = [CryptoManager.hash_sha256(leaf) for leaf in leaves]
        cred_index = leaves.index(cred_uuid)

        # Build the tree upwards
        while len(layer) > 1:
            if len(layer) % 2 != 0:  # If there's an odd number, duplicate the last element
                layer.append(layer[-1])
            
            proof.append((layer[(cred_index // 2 * 2) + ((cred_index + 1) % 2)], bool((cred_index + 1) % 2)))
            cred_index = cred_index // 2

            # Hash each pair of nodes
            layer = [CryptoManager.hash_sha256(layer[i] + layer[i + 1]) for i in range(0, len(layer), 2)]

        return proof

    @staticmethod
    def check_proof(proof: List[Tuple[str, bool]], cred_uuid: str, root_hash: str) -> bool:
        running_hash = CryptoManager.hash_sha256(cred_uuid)
        for sibling, is_right in proof:
            if is_right:
                running_hash = CryptoManager.hash_sha256(running_hash + sibling)
            else:
                running_hash = CryptoManager.hash_sha256(sibling + running_hash)

        return running_hash == root_hash
