"""
Capability Code Access Control System
Implements secure access control for SQL operations using capability codes
"""

import os
import hmac
import hashlib
import time
from datetime import datetime, timedelta
from typing import Dict, List, Optional


class CapabilityCode:
    """Represents a capability code for access control"""
    
    def __init__(self, code_id: str, user_id: str, permissions: List[str], 
                 expiry_hours: int = 24):
        """
        Initialize a capability code
        
        Args:
            code_id: Unique identifier for the capability code
            user_id: The user this code belongs to
            permissions: List of permissions (read, write, execute_stored_proc, etc.)
            expiry_hours: Hours until code expires (default 24)
        """
        self.code_id = code_id
        self.user_id = user_id
        self.permissions = permissions
        self.created_at = datetime.now()
        self.expiry_time = datetime.now() + timedelta(hours=expiry_hours)
        self.is_active = True
        self.signature = self._generate_signature()
    
    def _generate_signature(self) -> str:
        """
        Generate HMAC signature for code verification
        
        Returns:
            str: HMAC-SHA256 signature
        """
        secret = os.getenv('CAPABILITY_SECRET', 'change_me_in_production')
        message = f"{self.code_id}:{self.user_id}:{':'.join(self.permissions)}"
        signature = hmac.new(
            secret.encode(),
            message.encode(),
            hashlib.sha256
        ).hexdigest()
        return signature
    
    def is_valid(self) -> bool:
        """Check if capability code is still valid"""
        return self.is_active and datetime.now() < self.expiry_time
    
    def has_permission(self, permission: str) -> bool:
        """
        Check if this capability code has a specific permission
        
        Args:
            permission: The permission to check
            
        Returns:
            bool: True if permission exists, False otherwise
        """
        return self.is_valid() and permission in self.permissions
    
    def to_dict(self) -> Dict:
        """Convert capability code to dictionary"""
        return {
            'code_id': self.code_id,
            'user_id': self.user_id,
            'permissions': self.permissions,
            'created_at': self.created_at.isoformat(),
            'expiry_time': self.expiry_time.isoformat(),
            'is_active': self.is_active,
            'signature': self.signature
        }


class CapabilityManager:
    """Manages capability codes for access control"""
    
    def __init__(self):
        """Initialize capability manager"""
        self.capability_store: Dict[str, CapabilityCode] = {}
    
    def issue_capability_code(self, user_id: str, permissions: List[str],
                             expiry_hours: int = 24) -> CapabilityCode:
        """
        Issue a new capability code
        
        Args:
            user_id: The user to issue the code to
            permissions: List of permissions to grant
            expiry_hours: Hours until code expires
            
        Returns:
            CapabilityCode: The issued capability code
        """
        code_id = f"CAP_{user_id}_{int(time.time())}"
        capability = CapabilityCode(code_id, user_id, permissions, expiry_hours)
        self.capability_store[code_id] = capability
        return capability
    
    def verify_capability_code(self, code_id: str, signature: str) -> bool:
        """
        Verify a capability code and its signature
        
        Args:
            code_id: The capability code ID
            signature: The signature to verify
            
        Returns:
            bool: True if code is valid and signature matches
        """
        if code_id not in self.capability_store:
            return False
        
        capability = self.capability_store[code_id]
        
        # Check if code is still valid
        if not capability.is_valid():
            return False
        
        # Verify signature
        if capability.signature != signature:
            return False
        
        return True
    
    def check_permission(self, code_id: str, permission: str) -> bool:
        """
        Check if a capability code has a specific permission
        
        Args:
            code_id: The capability code ID
            permission: The permission to check
            
        Returns:
            bool: True if code has permission
        """
        if code_id not in self.capability_store:
            return False
        
        capability = self.capability_store[code_id]
        return capability.has_permission(permission)
    
    def revoke_capability_code(self, code_id: str) -> bool:
        """
        Revoke a capability code
        
        Args:
            code_id: The capability code ID to revoke
            
        Returns:
            bool: True if revoked successfully
        """
        if code_id in self.capability_store:
            self.capability_store[code_id].is_active = False
            return True
        return False
    
    def get_user_capabilities(self, user_id: str) -> List[Dict]:
        """
        Get all active capability codes for a user
        
        Args:
            user_id: The user ID
            
        Returns:
            List[Dict]: List of active capability codes
        """
        user_capabilities = []
        for code_id, capability in self.capability_store.items():
            if capability.user_id == user_id and capability.is_valid():
                user_capabilities.append(capability.to_dict())
        return user_capabilities
    
    def cleanup_expired_codes(self):
        """Remove expired capability codes from store"""
        expired_codes = [
            code_id for code_id, capability in self.capability_store.items()
            if not capability.is_valid()
        ]
        for code_id in expired_codes:
            del self.capability_store[code_id]
