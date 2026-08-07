"""
Security utilities for OAuth 2.1 implementation.

This module provides password hashing, token generation, and input validation
utilities using industry-standard cryptographic libraries and best practices.
"""

import secrets
import string
import re
from typing import Optional, Union
from urllib.parse import urlparse


# Use the bcrypt library directly, falling back to basic hashing if unavailable.
# passlib is deliberately not used: it is unmaintained (last release 2020) and its
# backend probe reads bcrypt.__about__.__version__, which bcrypt removed in 4.1.
import hashlib

try:
    import bcrypt

    BCRYPT_ROUNDS = 12  # Strong but reasonable rounds for demo
    BCRYPT_AVAILABLE = True
except ImportError:
    # Fallback for when bcrypt is not available
    bcrypt = None
    BCRYPT_ROUNDS = 12
    BCRYPT_AVAILABLE = False

# bcrypt only considers the first 72 bytes of a password and raises on longer
# input, so callers must pre-truncate at the byte level (not the character level).
BCRYPT_MAX_BYTES = 72


def _bcrypt_secret(password: str) -> bytes:
    """Encode a password for bcrypt, truncating to its 72-byte limit."""
    return password.encode("utf-8")[:BCRYPT_MAX_BYTES]


class PasswordHasher:
    """
    Secure password hashing utilities using bcrypt.

    Provides password hashing and verification with configurable
    security parameters and fallback options.
    """

    @staticmethod
    def hash_password(password: str) -> str:
        """
        Hash a password using bcrypt with salt.

        Args:
            password: Plain text password to hash

        Returns:
            str: Bcrypt hashed password

        Example:
            hashed = PasswordHasher.hash_password("mypassword123")
            # Returns: "$2b$12$..."
        """
        if not isinstance(password, str):
            raise ValueError("Password must be a string")

        if len(password) == 0:
            raise ValueError("Password cannot be empty")

        if BCRYPT_AVAILABLE:
            return bcrypt.hashpw(
                _bcrypt_secret(password),
                bcrypt.gensalt(rounds=BCRYPT_ROUNDS),
            ).decode("ascii")
        else:
            # Fallback to SHA256 with salt (not recommended for production)
            salt = secrets.token_hex(16)
            hashed = hashlib.sha256((password + salt).encode()).hexdigest()
            return f"sha256${salt}${hashed}"

    @staticmethod
    def verify_password(password: str, hashed_password: str) -> bool:
        """
        Verify a password against its hash.

        Args:
            password: Plain text password to verify
            hashed_password: Previously hashed password

        Returns:
            bool: True if password matches hash, False otherwise

        Example:
            is_valid = PasswordHasher.verify_password("mypassword123", hashed)
        """
        if not isinstance(password, str) or not isinstance(hashed_password, str):
            return False

        try:
            if BCRYPT_AVAILABLE and hashed_password.startswith(('$2a$', '$2b$', '$2y$')):
                return bcrypt.checkpw(
                    _bcrypt_secret(password),
                    hashed_password.encode("ascii"),
                )
            elif hashed_password.startswith('sha256$'):
                # Handle fallback SHA256 format
                parts = hashed_password.split('$')
                if len(parts) != 3:
                    return False

                salt = parts[1]
                expected_hash = parts[2]
                actual_hash = hashlib.sha256((password + salt).encode()).hexdigest()
                return secrets.compare_digest(expected_hash, actual_hash)
            else:
                return False
        except Exception:
            return False

    @staticmethod
    def generate_demo_hashes() -> dict:
        """
        Generate password hashes for demo accounts.

        Returns:
            dict: Dictionary mapping usernames to password hashes
        """
        demo_passwords = {
            'alice': 'password123',
            'bob': 'secret456',
            'carol': 'mypass789'
        }

        return {
            username: PasswordHasher.hash_password(password)
            for username, password in demo_passwords.items()
        }


class TokenGenerator:
    """
    Secure token generation utilities.

    Provides various token generation methods for OAuth codes,
    access tokens, and other security-sensitive values.
    """

    @staticmethod
    def generate_authorization_code() -> str:
        """
        Generate a secure authorization code.

        Returns:
            str: URL-safe authorization code
        """
        return secrets.token_urlsafe(32)

    @staticmethod
    def generate_access_token() -> str:
        """
        Generate a secure access token.

        Returns:
            str: URL-safe access token
        """
        return secrets.token_urlsafe(48)

    @staticmethod
    def generate_refresh_token() -> str:
        """
        Generate a secure refresh token.

        Returns:
            str: URL-safe refresh token
        """
        return secrets.token_urlsafe(64)

    @staticmethod
    def generate_client_secret() -> str:
        """
        Generate a secure client secret.

        Returns:
            str: URL-safe client secret
        """
        return secrets.token_urlsafe(32)

    @staticmethod
    def generate_session_id() -> str:
        """
        Generate a secure session identifier.

        Returns:
            str: URL-safe session ID
        """
        return secrets.token_urlsafe(24)

    @staticmethod
    def generate_nonce() -> str:
        """
        Generate a cryptographic nonce.

        Returns:
            str: URL-safe nonce value
        """
        return secrets.token_urlsafe(16)


class InputValidator:
    """
    Input validation and sanitization utilities.

    Provides validation for OAuth parameters, URLs, and other
    user inputs to prevent injection attacks and ensure data integrity.
    """

    # Regex patterns for validation
    CLIENT_ID_PATTERN = re.compile(r'^[a-zA-Z0-9_-]+$')
    SCOPE_PATTERN = re.compile(r'^[a-zA-Z0-9_\s-]+$')
    STATE_PATTERN = re.compile(r'^[a-zA-Z0-9_-]+$')
    USERNAME_PATTERN = re.compile(r'^[a-zA-Z0-9_.-]+$')

    @staticmethod
    def validate_client_id(client_id: str) -> bool:
        """
        Validate OAuth client ID format.

        Args:
            client_id: Client identifier to validate

        Returns:
            bool: True if valid format, False otherwise
        """
        if not isinstance(client_id, str):
            return False

        return (
            1 <= len(client_id) <= 100 and
            InputValidator.CLIENT_ID_PATTERN.match(client_id) is not None
        )

    @staticmethod
    def validate_redirect_uri(redirect_uri: str, allowed_schemes: Optional[list] = None) -> bool:
        """
        Validate OAuth redirect URI.

        Args:
            redirect_uri: URI to validate
            allowed_schemes: List of allowed URI schemes (default: ['http', 'https'])

        Returns:
            bool: True if valid URI, False otherwise
        """
        if not isinstance(redirect_uri, str):
            return False

        if allowed_schemes is None:
            allowed_schemes = ['http', 'https']

        try:
            parsed = urlparse(redirect_uri)

            # Check scheme
            if parsed.scheme not in allowed_schemes:
                return False

            # Check hostname (must be present for http/https)
            if parsed.scheme in ['http', 'https'] and not parsed.netloc:
                return False

            # Check for dangerous characters
            dangerous_chars = ['<', '>', '"', "'", '&']
            if any(char in redirect_uri for char in dangerous_chars):
                return False

            return True
        except Exception:
            return False

    @staticmethod
    def validate_scope(scope: str) -> bool:
        """
        Validate OAuth scope parameter.

        Args:
            scope: Scope string to validate

        Returns:
            bool: True if valid scope, False otherwise
        """
        if not isinstance(scope, str):
            return False

        return (
            1 <= len(scope) <= 200 and
            InputValidator.SCOPE_PATTERN.match(scope) is not None
        )

    @staticmethod
    def validate_state(state: str) -> bool:
        """
        Validate OAuth state parameter.

        Args:
            state: State parameter to validate

        Returns:
            bool: True if valid state, False otherwise
        """
        if not isinstance(state, str):
            return False

        return (
            1 <= len(state) <= 128 and
            InputValidator.STATE_PATTERN.match(state) is not None
        )

    @staticmethod
    def validate_username(username: str) -> bool:
        """
        Validate username format.

        Args:
            username: Username to validate

        Returns:
            bool: True if valid username, False otherwise
        """
        if not isinstance(username, str):
            return False

        return (
            1 <= len(username) <= 50 and
            InputValidator.USERNAME_PATTERN.match(username) is not None
        )

    @staticmethod
    def sanitize_string(input_str: str, max_length: int = 1000) -> str:
        """
        Sanitize string input by removing dangerous characters.

        Args:
            input_str: String to sanitize
            max_length: Maximum allowed length

        Returns:
            str: Sanitized string
        """
        if not isinstance(input_str, str):
            return ""

        # Remove null bytes and control characters
        sanitized = ''.join(char for char in input_str if ord(char) >= 32 or char in ['\n', '\r', '\t'])

        # Truncate to max length
        sanitized = sanitized[:max_length]

        # Remove leading/trailing whitespace
        return sanitized.strip()

    @staticmethod
    def validate_password_strength(password: str) -> tuple[bool, list[str]]:
        """
        Validate password strength requirements.

        Args:
            password: Password to validate

        Returns:
            tuple: (is_valid, list_of_issues)
        """
        if not isinstance(password, str):
            return False, ["Password must be a string"]

        issues = []

        if len(password) < 8:
            issues.append("Password must be at least 8 characters long")

        if len(password) > 128:
            issues.append("Password must be no more than 128 characters long")

        if not re.search(r'[a-z]', password):
            issues.append("Password must contain at least one lowercase letter")

        if not re.search(r'[A-Z]', password):
            issues.append("Password must contain at least one uppercase letter")

        if not re.search(r'\d', password):
            issues.append("Password must contain at least one digit")

        # Check for common weak passwords
        weak_passwords = ['password', '123456', 'qwerty', 'admin', 'letmein']
        if password.lower() in weak_passwords:
            issues.append("Password is too common")

        return len(issues) == 0, issues


class SecurityHeaders:
    """
    Security headers for HTTP responses.

    Provides standard security headers to protect against
    common web vulnerabilities.
    """

    @staticmethod
    def get_oauth_security_headers() -> dict:
        """
        Get security headers for OAuth endpoints.

        Returns:
            dict: Dictionary of security headers
        """
        return {
            'X-Content-Type-Options': 'nosniff',
            'X-Frame-Options': 'DENY',
            'X-XSS-Protection': '1; mode=block',
            'Strict-Transport-Security': 'max-age=31536000; includeSubDomains',
            'Cache-Control': 'no-cache, no-store, must-revalidate',
            'Pragma': 'no-cache',
            'Expires': '0'
        }

    @staticmethod
    def get_cors_headers(allowed_origins: Optional[list] = None) -> dict:
        """
        Get CORS headers for cross-origin requests.

        Args:
            allowed_origins: List of allowed origins (default: localhost only)

        Returns:
            dict: Dictionary of CORS headers
        """
        if allowed_origins is None:
            allowed_origins = ['http://localhost:8080', 'http://localhost:8081', 'http://localhost:8082']

        return {
            'Access-Control-Allow-Origin': ', '.join(allowed_origins),
            'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
            'Access-Control-Allow-Headers': 'Content-Type, Authorization',
            'Access-Control-Max-Age': '86400'
        }


# Convenience functions for backward compatibility
def hash_password(password: str) -> str:
    """Hash a password using bcrypt."""
    return PasswordHasher.hash_password(password)


def verify_password(password: str, hashed_password: str) -> bool:
    """Verify a password against its hash."""
    return PasswordHasher.verify_password(password, hashed_password)


def generate_secure_token(length: int = 32) -> str:
    """Generate a secure random token."""
    return secrets.token_urlsafe(length)


def validate_oauth_parameter(param_name: str, param_value: str) -> bool:
    """
    Validate OAuth parameter based on its name.

    Args:
        param_name: Name of the parameter
        param_value: Value to validate

    Returns:
        bool: True if valid, False otherwise
    """
    validator_map = {
        'client_id': InputValidator.validate_client_id,
        'redirect_uri': InputValidator.validate_redirect_uri,
        'scope': InputValidator.validate_scope,
        'state': InputValidator.validate_state,
        'username': InputValidator.validate_username
    }

    validator = validator_map.get(param_name)
    if validator:
        return validator(param_value)

    # Default validation for unknown parameters
    return isinstance(param_value, str) and 0 < len(param_value) <= 1000