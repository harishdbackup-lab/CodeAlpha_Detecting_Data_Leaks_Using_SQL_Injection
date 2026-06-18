"""
SQL Injection Detection and Prevention Module
Implements double-layer security: input validation + parameterized queries
"""

import re
from typing import List, Tuple, Any, Dict
from enum import Enum


class ThreatLevel(Enum):
    """Threat severity levels"""
    SAFE = "safe"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class SQLInjectionDetector:
    """Detects potential SQL injection attacks"""
    
    # Common SQL injection patterns
    SQL_INJECTION_PATTERNS = [
        # Classic SQL injection
        r"(\bunion\b.*\bselect\b)",
        r"(\bor\b\s*['\"]?\d*['\"]?\s*=\s*['\"]?\d*['\"]?)",
        r"(\bor\b\s*['\"]?\s*=\s*['\"]?)",
        # Stacked queries
        r"(;\s*drop\b)",
        r"(;\s*delete\b)",
        r"(;\s*update\b)",
        # Comment-based injection
        r"(--\s*$)",
        r"(/\*.*\*/)",
        # Time-based blind injection
        r"(sleep\s*\()",
        r"(benchmark\s*\()",
        # Boolean-based blind injection
        r"(and\s+['\"]?[\w]+['\"]?\s*=\s*['\"]?[\w]+['\"]?)",
        # Encoding bypass attempts
        r"(%27|%23|%2D%2D|0x)",
        # UNION-based
        r"(union.*select)",
        r"(union.*from)",
        # Hex encoding
        r"(0x[0-9a-f]+)",
        # Command execution
        r"(exec\s*\(|execute\s*\()",
    ]
    
    # Dangerous keywords that should be monitored
    DANGEROUS_KEYWORDS = [
        'union', 'select', 'insert', 'update', 'delete', 'drop',
        'create', 'alter', 'execute', 'exec', 'script', 'javascript',
        'xp_', 'sp_', 'cast', 'convert', 'syscolumns', 'sysobjects'
    ]
    
    def __init__(self):
        """Initialize SQL injection detector"""
        self.compiled_patterns = [re.compile(pattern, re.IGNORECASE) 
                                 for pattern in self.SQL_INJECTION_PATTERNS]
    
    def detect_injection_attempt(self, user_input: str) -> Tuple[bool, ThreatLevel, List[str]]:
        """
        Detect potential SQL injection attempts in user input
        
        Args:
            user_input: The user input to check
            
        Returns:
            Tuple[bool, ThreatLevel, List[str]]: (is_injection, threat_level, matched_patterns)
        """
        if not user_input:
            return False, ThreatLevel.SAFE, []
        
        matched_patterns = []
        threat_score = 0
        
        # Check against known patterns
        for pattern in self.compiled_patterns:
            if pattern.search(user_input):
                matched_patterns.append(pattern.pattern)
                threat_score += 2
        
        # Check for dangerous keywords
        words = user_input.lower().split()
        for keyword in self.DANGEROUS_KEYWORDS:
            if keyword in words:
                threat_score += 1
        
        # Check for suspicious characters
        suspicious_chars = ['%', '0x', '--', '/*', '*/', ';', '|', '&']
        for char in suspicious_chars:
            if char in user_input:
                threat_score += 0.5
        
        # Determine threat level
        if threat_score == 0:
            threat_level = ThreatLevel.SAFE
        elif threat_score < 2:
            threat_level = ThreatLevel.LOW
        elif threat_score < 4:
            threat_level = ThreatLevel.MEDIUM
        elif threat_score < 6:
            threat_level = ThreatLevel.HIGH
        else:
            threat_level = ThreatLevel.CRITICAL
        
        is_injection = threat_level in [ThreatLevel.MEDIUM, ThreatLevel.HIGH, ThreatLevel.CRITICAL]
        
        return is_injection, threat_level, matched_patterns
    
    def get_threat_details(self, user_input: str) -> Dict:
        """
        Get detailed threat analysis for user input
        
        Args:
            user_input: The input to analyze
            
        Returns:
            Dict: Detailed threat information
        """
        is_injection, threat_level, matched_patterns = self.detect_injection_attempt(user_input)
        
        return {
            'input': user_input[:50],  # Truncate for logging
            'is_injection_attempt': is_injection,
            'threat_level': threat_level.value,
            'matched_patterns': len(matched_patterns),
            'dangerous_keywords_found': self._find_dangerous_keywords(user_input),
            'special_characters': self._find_special_chars(user_input)
        }
    
    @staticmethod
    def _find_dangerous_keywords(user_input: str) -> List[str]:
        """Find dangerous keywords in input"""
        found = []
        for keyword in SQLInjectionDetector.DANGEROUS_KEYWORDS:
            if re.search(r'\b' + keyword + r'\b', user_input, re.IGNORECASE):
                found.append(keyword)
        return found
    
    @staticmethod
    def _find_special_chars(user_input: str) -> List[str]:
        """Find special characters that might indicate SQL injection"""
        special_chars = re.findall(r"['\";--/\\*()]", user_input)
        return list(set(special_chars))


class SQLInjectionPrevention:
    """Prevents SQL injection using parameterized queries and input validation"""
    
    @staticmethod
    def sanitize_input(user_input: str, allow_wildcards: bool = False) -> str:
        """
        Sanitize user input by removing dangerous characters
        
        Args:
            user_input: The input to sanitize
            allow_wildcards: Whether to allow SQL wildcard characters (%, _)
            
        Returns:
            str: Sanitized input
        """
        if not isinstance(user_input, str):
            user_input = str(user_input)
        
        # Remove null bytes
        user_input = user_input.replace('\x00', '')
        
        # Remove or escape dangerous characters
        dangerous = ["'", '"', ';', '--', '/*', '*/', 'xp_', 'sp_']
        for char in dangerous:
            user_input = user_input.replace(char, '')
        
        # If wildcards not allowed, remove them
        if not allow_wildcards:
            user_input = user_input.replace('%', '').replace('_', '')
        
        return user_input.strip()
    
    @staticmethod
    def validate_input(user_input: str, input_type: str = 'string',
                      max_length: int = 255) -> Tuple[bool, str]:
        """
        Validate user input based on expected type
        
        Args:
            user_input: The input to validate
            input_type: Expected type (string, email, number, phone, etc.)
            max_length: Maximum allowed length
            
        Returns:
            Tuple[bool, str]: (is_valid, error_message)
        """
        if not user_input:
            return False, "Input cannot be empty"
        
        if len(str(user_input)) > max_length:
            return False, f"Input exceeds maximum length of {max_length}"
        
        # Type-specific validation
        if input_type == 'email':
            email_pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
            if not re.match(email_pattern, user_input):
                return False, "Invalid email format"
        
        elif input_type == 'number':
            if not re.match(r'^-?\d+(\.\d+)?$', str(user_input)):
                return False, "Input must be a valid number"
        
        elif input_type == 'phone':
            phone_pattern = r'^\+?1?\d{9,15}$'
            if not re.match(phone_pattern, str(user_input).replace('-', '')):
                return False, "Invalid phone number format"
        
        elif input_type == 'username':
            username_pattern = r'^[a-zA-Z0-9_]{3,32}$'
            if not re.match(username_pattern, user_input):
                return False, "Username must be 3-32 characters, alphanumeric with underscore"
        
        return True, "Valid"
    
    @staticmethod
    def use_parameterized_query(query_template: str, params: List[Any]) -> Dict:
        """
        Prepare a parameterized query (implementation example)
        
        Args:
            query_template: SQL query with placeholders (e.g., "SELECT * FROM users WHERE id = ?")
            params: Parameters to bind to placeholders
            
        Returns:
            Dict: Parameterized query information
        """
        # Count placeholders
        placeholders = query_template.count('?')
        
        if len(params) != placeholders:
            return {
                'valid': False,
                'error': f"Expected {placeholders} parameters, got {len(params)}"
            }
        
        return {
            'valid': True,
            'query_template': query_template,
            'param_count': len(params),
            'message': 'Query is properly parameterized and safe to execute'
        }
