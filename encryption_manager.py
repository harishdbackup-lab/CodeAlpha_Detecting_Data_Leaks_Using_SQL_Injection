"""
AES-256 Encryption Module for Secure Data Storage
Handles encryption and decryption of sensitive credentials and data
"""

import os
import base64
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2


class EncryptionManager:
    """Manages AES-256 encryption for sensitive data"""
    
    def __init__(self, master_key: str = None):
        """
        Initialize encryption manager with a master key
        
        Args:
            master_key: The master encryption key (uses env var if not provided)
        """
        if master_key is None:
            master_key = os.getenv('ENCRYPTION_KEY', 'default_secure_key_change_in_production')
        
        self.master_key = self._derive_key(master_key)
        self.cipher = Fernet(self.master_key)
    
    @staticmethod
    def _derive_key(password: str) -> bytes:
        """
        Derive a Fernet-compatible key from a password using PBKDF2
        
        Args:
            password: The password to derive the key from
            
        Returns:
            bytes: Fernet-compatible key encoded in base64
        """
        # Use PBKDF2 to derive a key from password
        kdf = PBKDF2(
            algorithm=hashes.SHA256(),
            length=32,  # 256 bits for AES-256
            salt=b'codealpha_salt_v1',  # Fixed salt for consistency
            iterations=100000,
        )
        
        key_bytes = kdf.derive(password.encode())
        # Encode to base64 to make it Fernet-compatible
        key_b64 = base64.urlsafe_b64encode(key_bytes)
        
        return key_b64
    
    def encrypt(self, plaintext: str) -> str:
        """
        Encrypt plaintext data using AES-256
        
        Args:
            plaintext: The data to encrypt
            
        Returns:
            str: Encrypted data as base64 string
        """
        if isinstance(plaintext, str):
            plaintext = plaintext.encode()
        
        encrypted = self.cipher.encrypt(plaintext)
        return base64.b64encode(encrypted).decode('utf-8')
    
    def decrypt(self, ciphertext: str) -> str:
        """
        Decrypt AES-256 encrypted data
        
        Args:
            ciphertext: The encrypted data (base64 string)
            
        Returns:
            str: Decrypted plaintext
        """
        try:
            ciphertext_bytes = base64.b64decode(ciphertext.encode())
            decrypted = self.cipher.decrypt(ciphertext_bytes)
            return decrypted.decode('utf-8')
        except Exception as e:
            raise ValueError(f"Decryption failed: {str(e)}")
    
    def hash_password(self, password: str, salt: str = None) -> tuple:
        """
        Create a secure hash of a password
        
        Args:
            password: The password to hash
            salt: Optional salt (generated if not provided)
            
        Returns:
            tuple: (hashed_password, salt)
        """
        if salt is None:
            salt = os.urandom(32).hex()
        
        # Use PBKDF2 for password hashing
        kdf = PBKDF2(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt.encode(),
            iterations=100000,
        )
        
        hash_bytes = kdf.derive(password.encode())
        hashed = base64.b64encode(hash_bytes).decode()
        
        return hashed, salt
    
    def verify_password(self, password: str, hashed: str, salt: str) -> bool:
        """
        Verify a password against its hash
        
        Args:
            password: The password to verify
            hashed: The hashed password
            salt: The salt used for hashing
            
        Returns:
            bool: True if password matches, False otherwise
        """
        new_hash, _ = self.hash_password(password, salt)
        return new_hash == hashed
