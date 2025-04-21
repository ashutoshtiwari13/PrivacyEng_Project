"""
Cryptographic utilities for the privacy-preserving digital credential system.
"""

import base64
import os
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives import serialization


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