"""
Security utilities for password hashing and JWT token management
"""
from datetime import datetime, timedelta, timezone
from typing import Any
import hashlib
import secrets

import bcrypt
import jwt
from sqlmodel import Session

from core.config import get_settings
from api.auth.models import RefreshToken

# Bcrypt configuration
BCRYPT_ROUNDS = 12


def hash_password(password: str) -> str:
    """
    Hash a password using bcrypt

    Args:
        password: Plain text password

    Returns:
        Hashed password string
    """
    password_bytes = password.encode('utf-8')
    salt = bcrypt.gensalt(rounds=BCRYPT_ROUNDS)
    hashed = bcrypt.hashpw(password_bytes, salt)
    return hashed.decode('utf-8')


def verify_password(plain_password: str, hashed_password: str) -> bool:
    """
    Verify a password against its hash

    Args:
        plain_password: Plain text password to verify
        hashed_password: Hashed password to compare against

    Returns:
        True if password matches, False otherwise
    """
    try:
        password_bytes = plain_password.encode('utf-8')
        hashed_bytes = hashed_password.encode('utf-8')
        return bcrypt.checkpw(password_bytes, hashed_bytes)
    except (ValueError, AttributeError):
        return False


def create_access_token(data: dict[str, Any], expires_delta: timedelta | None = None) -> str:
    """
    Create a JWT access token

    Args:
        data: Data to encode in the token (typically {"sub": user_id})
        expires_delta: Optional custom expiration time

    Returns:
        Encoded JWT token string
    """
    settings = get_settings()
    to_encode = data.copy()

    if expires_delta:
        expire = datetime.now(timezone.utc) + expires_delta
    else:
        expire = datetime.now(timezone.utc) + timedelta(
            minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES
        )

    to_encode.update({
        "exp": expire,
        "iat": datetime.now(timezone.utc),
        "type": "access"
    })

    encoded_jwt = jwt.encode(
        to_encode,
        settings.JWT_SECRET_KEY,
        algorithm=settings.JWT_ALGORITHM
    )
    return encoded_jwt


def create_refresh_token(
    session: Session,
    username: str,
    device_info: str | None = None
) -> RefreshToken:
    """
    Create a refresh token and store in database

    Args:
        session: Database session
        username: Username to create token for
        device_info: Optional device/client information

    Returns:
        RefreshToken object
    """
    settings = get_settings()

    # Generate secure random token
    token_string = secrets.token_urlsafe(32)

    # Calculate expiration
    expires_at = datetime.now(timezone.utc) + timedelta(
        days=settings.REFRESH_TOKEN_EXPIRE_DAYS
    )

    # Create token record
    refresh_token = RefreshToken(
        username=username,
        token=token_string,
        expires_at=expires_at,
        device_info=device_info
    )

    session.add(refresh_token)
    session.commit()
    session.refresh(refresh_token)

    return refresh_token


def decode_token(token: str) -> dict[str, Any]:
    """
    Decode and validate a JWT token

    Args:
        token: JWT token string

    Returns:
        Decoded token payload

    Raises:
        jwt.PyJWTError: If token is invalid or expired (e.g.
            jwt.ExpiredSignatureError, jwt.InvalidTokenError)
    """
    settings = get_settings()

    payload = jwt.decode(
        token,
        settings.JWT_SECRET_KEY,
        algorithms=[settings.JWT_ALGORITHM]
    )
    return payload


def generate_secure_token(length: int = 32) -> str:
    """
    Generate a cryptographically secure random token

    Args:
        length: Number of bytes for token (default 32)

    Returns:
        URL-safe token string
    """
    return secrets.token_urlsafe(length)


def generate_api_key() -> tuple[str, str, str]:
    """
    Generate a new API key with prefix, hash, and display prefix.

    Returns:
        Tuple of (raw_key, hashed_key, key_prefix)
    """
    random_part = secrets.token_urlsafe(32)
    raw_key = f"ngs360_{random_part}"
    hashed_key = hash_api_key(raw_key)
    key_prefix = raw_key[:12]
    return raw_key, hashed_key, key_prefix


def hash_api_key(raw_key: str) -> str:
    """
    Hash an API key using SHA-256 for O(1) lookup.

    Args:
        raw_key: The raw API key string

    Returns:
        SHA-256 hex digest
    """
    return hashlib.sha256(raw_key.encode("utf-8")).hexdigest()


def validate_password_strength(password: str) -> tuple[bool, str | None]:
    """
    Validate password meets security requirements

    Args:
        password: Password to validate

    Returns:
        Tuple of (is_valid, error_message)
    """
    settings = get_settings()

    if len(password) < settings.PASSWORD_MIN_LENGTH:
        return False, f"Password must be at least {settings.PASSWORD_MIN_LENGTH} characters"

    if settings.PASSWORD_REQUIRE_UPPERCASE and not any(c.isupper() for c in password):
        return False, "Password must contain at least one uppercase letter"

    if settings.PASSWORD_REQUIRE_LOWERCASE and not any(c.islower() for c in password):
        return False, "Password must contain at least one lowercase letter"

    if settings.PASSWORD_REQUIRE_DIGIT and not any(c.isdigit() for c in password):
        return False, "Password must contain at least one digit"

    if settings.PASSWORD_REQUIRE_SPECIAL:
        special_chars = "!@#$%^&*()_+-=[]{}|;:,.<>?"
        if not any(c in special_chars for c in password):
            return False, "Password must contain at least one special character"

    return True, None
