"""
Test script to demonstrate security features
Tests encryption, capability codes, and SQL injection detection
"""

import requests
import json
from typing import Dict

BASE_URL = 'http://localhost:5000'


class TestClient:
    """Client for testing the security API"""
    
    def __init__(self, base_url: str = BASE_URL):
        self.base_url = base_url
        self.session = requests.Session()
        self.capability_code = None
        self.signature = None
    
    def register_user(self, username: str, email: str, password: str) -> Dict:
        """Register a new user"""
        url = f'{self.base_url}/api/register'
        payload = {
            'username': username,
            'email': email,
            'password': password
        }
        response = self.session.post(url, json=payload)
        return response.json(), response.status_code
    
    def login_user(self, username: str, password: str) -> Dict:
        """Login and get capability code"""
        url = f'{self.base_url}/api/login'
        payload = {
            'username': username,
            'password': password
        }
        response = self.session.post(url, json=payload)
        result = response.json()
        
        if response.status_code == 200:
            self.capability_code = result.get('capability_code')
            self.signature = result.get('signature')
        
        return result, response.status_code
    
    def detect_sql_injection(self, query: str) -> Dict:
        """Detect SQL injection in a query"""
        url = f'{self.base_url}/api/detect-injection'
        payload = {
            'capability_code': self.capability_code,
            'signature': self.signature,
            'query': query
        }
        response = self.session.post(url, json=payload)
        return response.json(), response.status_code
    
    def sanitize_input(self, user_input: str) -> Dict:
        """Sanitize user input"""
        url = f'{self.base_url}/api/sanitize-input'
        payload = {
            'capability_code': self.capability_code,
            'signature': self.signature,
            'input': user_input
        }
        response = self.session.post(url, json=payload)
        return response.json(), response.status_code
    
    def validate_input(self, user_input: str, input_type: str) -> Dict:
        """Validate user input"""
        url = f'{self.base_url}/api/validate-input'
        payload = {
            'capability_code': self.capability_code,
            'signature': self.signature,
            'input': user_input,
            'input_type': input_type
        }
        response = self.session.post(url, json=payload)
        return response.json(), response.status_code
    
    def get_audit_log(self) -> Dict:
        """Get audit log"""
        url = f'{self.base_url}/api/audit-log'
        headers = {
            'X-Capability-Code': self.capability_code,
            'X-Signature': self.signature
        }
        response = self.session.get(url, headers=headers)
        return response.json(), response.status_code


def run_tests():
    """Run comprehensive security tests"""
    client = TestClient()
    
    print("=" * 80)
    print("SQL INJECTION DATA LEAK DETECTION SYSTEM - TEST SUITE")
    print("=" * 80)
    
    # Test 1: User Registration
    print("\n[TEST 1] User Registration with Encrypted Credentials")
    print("-" * 80)
    result, status = client.register_user('john_doe', 'john@example.com', 'SecurePass123!')
    print(f"Status: {status}")
    print(f"Response: {json.dumps(result, indent=2)}")
    
    # Test 2: Attempt registration with SQL injection
    print("\n[TEST 2] SQL Injection Prevention - Registration Attempt")
    print("-" * 80)
    result, status = client.register_user("admin' --", "test@test.com", "pass123")
    print(f"Status: {status}")
    print(f"Response: {json.dumps(result, indent=2)}")
    
    # Test 3: User Login
    print("\n[TEST 3] User Login and Capability Code Issuance")
    print("-" * 80)
    result, status = client.login_user('john_doe', 'SecurePass123!')
    print(f"Status: {status}")
    print(f"Response: {json.dumps(result, indent=2)}")
    
    if status != 200:
        print("Login failed. Stopping tests.")
        return
    
    # Test 4: Detect SQL Injection - Classic Attack
    print("\n[TEST 4] SQL Injection Detection - Classic Attack")
    print("-" * 80)
    malicious_query = "SELECT * FROM users WHERE id = 1 OR '1'='1'"
    result, status = client.detect_sql_injection(malicious_query)
    print(f"Query: {malicious_query}")
    print(f"Status: {status}")
    print(f"Response: {json.dumps(result, indent=2)}")
    
    # Test 5: Detect SQL Injection - UNION-based Attack
    print("\n[TEST 5] SQL Injection Detection - UNION-based Attack")
    print("-" * 80)
    malicious_query = "SELECT * FROM users UNION SELECT * FROM admin_users"
    result, status = client.detect_sql_injection(malicious_query)
    print(f"Query: {malicious_query}")
    print(f"Status: {status}")
    print(f"Response: {json.dumps(result, indent=2)}")
    
    # Test 6: Detect SQL Injection - Time-based Blind Attack
    print("\n[TEST 6] SQL Injection Detection - Time-based Blind Attack")
    print("-" * 80)
    malicious_query = "SELECT * FROM users WHERE id = 1; DROP TABLE users; --"
    result, status = client.detect_sql_injection(malicious_query)
    print(f"Query: {malicious_query}")
    print(f"Status: {status}")
    print(f"Response: {json.dumps(result, indent=2)}")
    
    # Test 7: Safe Query Detection
    print("\n[TEST 7] Safe Query Detection")
    print("-" * 80)
    safe_query = "SELECT * FROM users WHERE username = ?"
    result, status = client.detect_sql_injection(safe_query)
    print(f"Query: {safe_query}")
    print(f"Status: {status}")
    print(f"Response: {json.dumps(result, indent=2)}")
    
    # Test 8: Input Sanitization
    print("\n[TEST 8] Input Sanitization")
    print("-" * 80)
    dangerous_input = "user' OR '1'='1'; DROP TABLE users; --"
    result, status = client.sanitize_input(dangerous_input)
    print(f"Original Input: {dangerous_input}")
    print(f"Status: {status}")
    print(f"Response: {json.dumps(result, indent=2)}")
    
    # Test 9: Email Validation
    print("\n[TEST 9] Input Validation - Email")
    print("-" * 80)
    result, status = client.validate_input('john@example.com', 'email')
    print(f"Email: john@example.com")
    print(f"Status: {status}")
    print(f"Response: {json.dumps(result, indent=2)}")
    
    # Test 10: Invalid Email Validation
    print("\n[TEST 10] Input Validation - Invalid Email")
    print("-" * 80)
    result, status = client.validate_input('not_an_email', 'email')
    print(f"Email: not_an_email")
    print(f"Status: {status}")
    print(f"Response: {json.dumps(result, indent=2)}")
    
    # Test 11: Username Validation
    print("\n[TEST 11] Input Validation - Username")
    print("-" * 80)
    result, status = client.validate_input('john_doe123', 'username')
    print(f"Username: john_doe123")
    print(f"Status: {status}")
    print(f"Response: {json.dumps(result, indent=2)}")
    
    # Test 12: Phone Validation
    print("\n[TEST 12] Input Validation - Phone Number")
    print("-" * 80)
    result, status = client.validate_input('+1234567890', 'phone')
    print(f"Phone: +1234567890")
    print(f"Status: {status}")
    print(f"Response: {json.dumps(result, indent=2)}")
    
    # Test 13: Audit Log Access
    print("\n[TEST 13] Access Audit Log")
    print("-" * 80)
    result, status = client.get_audit_log()
    print(f"Status: {status}")
    print(f"Total Entries: {result.get('total_entries', 0)}")
    print(f"Recent Entries (last 3):")
    for entry in result.get('recent_entries', [])[-3:]:
        print(f"  - {json.dumps(entry, indent=4)}")
    
    print("\n" + "=" * 80)
    print("TEST SUITE COMPLETED")
    print("=" * 80)


if __name__ == '__main__':
    print("Ensure the Flask server is running on http://localhost:5000")
    print("To start the server, run: python app.py\n")
    
    try:
        # Check if server is running
        response = requests.get(f'{BASE_URL}/health')
        if response.status_code == 200:
            print("Server is running. Starting tests...\n")
            run_tests()
        else:
            print("Server is not responding correctly.")
    except requests.exceptions.ConnectionError:
        print("ERROR: Cannot connect to the server.")
        print("Please ensure the Flask server is running on http://localhost:5000")
        print("\nTo start the server, run:")
        print("  1. pip install -r requirements.txt")
        print("  2. python app.py")
