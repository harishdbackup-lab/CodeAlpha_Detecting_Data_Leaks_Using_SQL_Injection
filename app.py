"""
Flask Application for Secure Data Leak Detection
Demonstrates AES-256 encryption, capability codes, and SQL injection prevention
"""

import os
import logging
from flask import Flask, request, jsonify
from datetime import datetime
from encryption_manager import EncryptionManager
from capability_manager import CapabilityManager
from sql_injection_prevention import SQLInjectionDetector, SQLInjectionPrevention

# Initialize Flask app
app = Flask(__name__)
app.config['JSON_SORT_KEYS'] = False

# Initialize security components
encryption_manager = EncryptionManager()
capability_manager = CapabilityManager()
sql_detector = SQLInjectionDetector()
sql_prevention = SQLInjectionPrevention()

# Setup logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Simulated user database (in production, use actual database)
users_db = {}
audit_log = []


@app.route('/health', methods=['GET'])
def health_check():
    """Health check endpoint"""
    return jsonify({
        'status': 'healthy',
        'timestamp': datetime.now().isoformat(),
        'service': 'SQL Injection Data Leak Detection System'
    }), 200


@app.route('/api/register', methods=['POST'])
def register_user():
    """
    Register a new user with encrypted credentials
    
    Expected JSON:
    {
        "username": "user123",
        "email": "user@example.com",
        "password": "securepassword123"
    }
    """
    try:
        data = request.get_json()
        
        # Validate input
        username = data.get('username', '').strip()
        email = data.get('email', '').strip()
        password = data.get('password', '').strip()
        
        # Layer 1: Input Validation
        validations = [
            (username, 'username', 'username'),
            (email, 'email', 'email'),
            (password, 'string', 128)
        ]
        
        for value, dtype, field in validations:
            is_valid, msg = sql_prevention.validate_input(value, dtype)
            if not is_valid:
                return jsonify({'error': f'{field} validation failed: {msg}'}), 400
        
        # Check for SQL injection attempts
        inputs_to_check = [username, email, password]
        for input_val in inputs_to_check:
            is_injection, threat_level, patterns = sql_detector.detect_injection_attempt(input_val)
            if is_injection:
                logger.warning(f"SQL injection attempt detected: {threat_level.value}")
                return jsonify({
                    'error': 'Suspicious input detected',
                    'threat_level': threat_level.value
                }), 400
        
        # Check if user already exists
        if username in users_db:
            return jsonify({'error': 'User already exists'}), 409
        
        # Layer 2: Encrypt credentials
        hashed_password, salt = encryption_manager.hash_password(password)
        encrypted_email = encryption_manager.encrypt(email)
        
        # Store user
        users_db[username] = {
            'username': username,
            'email_encrypted': encrypted_email,
            'password_hash': hashed_password,
            'password_salt': salt,
            'created_at': datetime.now().isoformat(),
            'capabilities': []
        }
        
        # Log action
        audit_log.append({
            'action': 'user_registration',
            'username': username,
            'timestamp': datetime.now().isoformat(),
            'status': 'success'
        })
        
        return jsonify({
            'message': 'User registered successfully',
            'username': username,
            'created_at': users_db[username]['created_at']
        }), 201
    
    except Exception as e:
        logger.error(f"Registration error: {str(e)}")
        return jsonify({'error': 'Registration failed', 'details': str(e)}), 500


@app.route('/api/login', methods=['POST'])
def login_user():
    """
    Login user and issue capability code
    
    Expected JSON:
    {
        "username": "user123",
        "password": "securepassword123"
    }
    """
    try:
        data = request.get_json()
        username = data.get('username', '').strip()
        password = data.get('password', '').strip()
        
        # Find user
        if username not in users_db:
            return jsonify({'error': 'Invalid credentials'}), 401
        
        user = users_db[username]
        
        # Verify password
        if not encryption_manager.verify_password(password, user['password_hash'], user['password_salt']):
            return jsonify({'error': 'Invalid credentials'}), 401
        
        # Issue capability code with read permissions
        capability = capability_manager.issue_capability_code(
            user_id=username,
            permissions=['read', 'query_analysis'],
            expiry_hours=24
        )
        
        # Store capability in user record
        user['capabilities'].append(capability.code_id)
        
        # Log action
        audit_log.append({
            'action': 'user_login',
            'username': username,
            'capability_code': capability.code_id,
            'timestamp': datetime.now().isoformat(),
            'status': 'success'
        })
        
        return jsonify({
            'message': 'Login successful',
            'username': username,
            'capability_code': capability.code_id,
            'signature': capability.signature,
            'permissions': capability.permissions,
            'expires_at': capability.expiry_time.isoformat()
        }), 200
    
    except Exception as e:
        logger.error(f"Login error: {str(e)}")
        return jsonify({'error': 'Login failed', 'details': str(e)}), 500


@app.route('/api/detect-injection', methods=['POST'])
def detect_sql_injection():
    """
    Detect potential SQL injection in provided SQL query
    
    Expected JSON:
    {
        "capability_code": "CAP_...",
        "signature": "...",
        "query": "SELECT * FROM users WHERE id = 1 OR '1'='1'"
    }
    """
    try:
        data = request.get_json()
        capability_code = data.get('capability_code', '')
        signature = data.get('signature', '')
        query = data.get('query', '')
        
        # Verify capability code
        if not capability_manager.verify_capability_code(capability_code, signature):
            return jsonify({'error': 'Invalid or expired capability code'}), 403
        
        # Check if code has permission
        if not capability_manager.check_permission(capability_code, 'query_analysis'):
            return jsonify({'error': 'Insufficient permissions for query analysis'}), 403
        
        # Analyze query for SQL injection
        is_injection, threat_level, patterns = sql_detector.detect_injection_attempt(query)
        threat_details = sql_detector.get_threat_details(query)
        
        # Log action
        audit_log.append({
            'action': 'sql_analysis',
            'capability_code': capability_code,
            'query_length': len(query),
            'threat_level': threat_level.value,
            'timestamp': datetime.now().isoformat()
        })
        
        return jsonify({
            'is_injection_attempt': is_injection,
            'threat_level': threat_level.value,
            'matched_patterns_count': len(patterns),
            'dangerous_keywords': threat_details['dangerous_keywords_found'],
            'special_characters': threat_details['special_characters'],
            'analysis_details': threat_details
        }), 200
    
    except Exception as e:
        logger.error(f"Query analysis error: {str(e)}")
        return jsonify({'error': 'Analysis failed', 'details': str(e)}), 500


@app.route('/api/sanitize-input', methods=['POST'])
def sanitize_input_endpoint():
    """
    Sanitize user input to prevent SQL injection
    
    Expected JSON:
    {
        "capability_code": "CAP_...",
        "signature": "...",
        "input": "user input with ' special chars"
    }
    """
    try:
        data = request.get_json()
        capability_code = data.get('capability_code', '')
        signature = data.get('signature', '')
        user_input = data.get('input', '')
        allow_wildcards = data.get('allow_wildcards', False)
        
        # Verify capability code
        if not capability_manager.verify_capability_code(capability_code, signature):
            return jsonify({'error': 'Invalid or expired capability code'}), 403
        
        # Sanitize input
        sanitized = sql_prevention.sanitize_input(user_input, allow_wildcards)
        
        # Log action
        audit_log.append({
            'action': 'input_sanitization',
            'capability_code': capability_code,
            'timestamp': datetime.now().isoformat()
        })
        
        return jsonify({
            'original_input': user_input,
            'sanitized_input': sanitized,
            'changed': user_input != sanitized,
            'message': 'Input successfully sanitized'
        }), 200
    
    except Exception as e:
        logger.error(f"Sanitization error: {str(e)}")
        return jsonify({'error': 'Sanitization failed', 'details': str(e)}), 500


@app.route('/api/validate-input', methods=['POST'])
def validate_input_endpoint():
    """
    Validate user input based on expected type
    
    Expected JSON:
    {
        "capability_code": "CAP_...",
        "signature": "...",
        "input": "user@example.com",
        "input_type": "email"
    }
    """
    try:
        data = request.get_json()
        capability_code = data.get('capability_code', '')
        signature = data.get('signature', '')
        user_input = data.get('input', '')
        input_type = data.get('input_type', 'string')
        max_length = data.get('max_length', 255)
        
        # Verify capability code
        if not capability_manager.verify_capability_code(capability_code, signature):
            return jsonify({'error': 'Invalid or expired capability code'}), 403
        
        # Validate input
        is_valid, message = sql_prevention.validate_input(user_input, input_type, max_length)
        
        return jsonify({
            'input_type': input_type,
            'is_valid': is_valid,
            'message': message,
            'max_length': max_length
        }), 200
    
    except Exception as e:
        logger.error(f"Validation error: {str(e)}")
        return jsonify({'error': 'Validation failed', 'details': str(e)}), 500


@app.route('/api/audit-log', methods=['GET'])
def get_audit_log():
    """Get security audit log (last 100 entries)"""
    try:
        capability_code = request.headers.get('X-Capability-Code', '')
        signature = request.headers.get('X-Signature', '')
        
        # Verify capability code
        if not capability_manager.verify_capability_code(capability_code, signature):
            return jsonify({'error': 'Invalid or expired capability code'}), 403
        
        # Return last 100 entries
        return jsonify({
            'total_entries': len(audit_log),
            'recent_entries': audit_log[-100:],
            'timestamp': datetime.now().isoformat()
        }), 200
    
    except Exception as e:
        logger.error(f"Audit log error: {str(e)}")
        return jsonify({'error': 'Failed to retrieve audit log', 'details': str(e)}), 500


@app.route('/api/capabilities/<username>', methods=['GET'])
def get_user_capabilities(username):
    """Get all active capability codes for a user"""
    try:
        capability_code = request.headers.get('X-Capability-Code', '')
        signature = request.headers.get('X-Signature', '')
        
        # Verify capability code
        if not capability_manager.verify_capability_code(capability_code, signature):
            return jsonify({'error': 'Invalid or expired capability code'}), 403
        
        # Get capabilities
        capabilities = capability_manager.get_user_capabilities(username)
        
        return jsonify({
            'username': username,
            'active_capabilities': capabilities,
            'count': len(capabilities)
        }), 200
    
    except Exception as e:
        logger.error(f"Capabilities fetch error: {str(e)}")
        return jsonify({'error': 'Failed to retrieve capabilities', 'details': str(e)}), 500


@app.route('/api/capabilities/<code_id>/revoke', methods=['POST'])
def revoke_capability(code_id):
    """Revoke a capability code"""
    try:
        capability_code = request.headers.get('X-Capability-Code', '')
        signature = request.headers.get('X-Signature', '')
        
        # Verify capability code
        if not capability_manager.verify_capability_code(capability_code, signature):
            return jsonify({'error': 'Invalid or expired capability code'}), 403
        
        # Revoke capability
        if capability_manager.revoke_capability_code(code_id):
            return jsonify({'message': 'Capability code revoked successfully'}), 200
        else:
            return jsonify({'error': 'Capability code not found'}), 404
    
    except Exception as e:
        logger.error(f"Revocation error: {str(e)}")
        return jsonify({'error': 'Failed to revoke capability', 'details': str(e)}), 500


@app.errorhandler(404)
def not_found(error):
    """Handle 404 errors"""
    return jsonify({'error': 'Endpoint not found'}), 404


@app.errorhandler(500)
def server_error(error):
    """Handle 500 errors"""
    logger.error(f"Server error: {str(error)}")
    return jsonify({'error': 'Internal server error'}), 500


if __name__ == '__main__':
    # Set environment variables if not already set
    if not os.getenv('ENCRYPTION_KEY'):
        os.environ['ENCRYPTION_KEY'] = 'CodeAlpha_Secure_Key_Change_In_Production_2024'
    
    if not os.getenv('CAPABILITY_SECRET'):
        os.environ['CAPABILITY_SECRET'] = 'CodeAlpha_Capability_Secret_Change_In_Production'
    
    # Run the app
    app.run(host='0.0.0.0', port=5000, debug=False)
