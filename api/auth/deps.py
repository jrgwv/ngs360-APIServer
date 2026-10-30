"""
Authentication dependencies for protecting endpoints
"""
from datetime import datetime, timedelta, timezone
from typing import Annotated
import uuid

from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from jwt import PyJWTError
from sqlmodel import Session, select

from core.deps import SessionDep
from core.security import decode_token, hash_api_key
from api.auth.models import User, APIKey
from api.auth.services import ensure_timezone_aware

# How stale api_keys.last_used_at may get before a request refreshes it. The
# column answers "is this key still in use", which is judged in days, so
# minute precision buys nothing -- and writing it on every request made each
# API-key call a database write and commit, however read-only the call itself.
API_KEY_TOUCH_INTERVAL = timedelta(minutes=5)

# OAuth2 scheme for token extraction
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/v1/auth/login")

# Optional OAuth2 scheme (doesn't raise error if no token)
oauth2_scheme_optional = OAuth2PasswordBearer(
    tokenUrl="/api/v1/auth/login",
    auto_error=False
)


def authenticate_api_key(session: Session, token: str) -> User:
    """Authenticate a user via API key."""
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )

    hashed = hash_api_key(token)
    api_key = session.exec(
        select(APIKey).where(
            APIKey.hashed_key == hashed,
            APIKey.is_active.is_(True),
        )
    ).first()

    if api_key is None:
        raise credentials_exception

    # Check expiration
    expires_at = ensure_timezone_aware(api_key.expires_at)
    if expires_at is not None and expires_at < datetime.now(timezone.utc):
        raise credentials_exception

    user = session.get(User, api_key.user_id)
    if user is None:
        raise credentials_exception

    # Refresh last_used_at at most once per API_KEY_TOUCH_INTERVAL.
    now = datetime.now(timezone.utc)
    last_used = ensure_timezone_aware(api_key.last_used_at)
    if last_used is None or now - last_used >= API_KEY_TOUCH_INTERVAL:
        api_key.last_used_at = now
        session.add(api_key)
        session.commit()

    return user


def get_current_user(
    session: SessionDep,
    token: Annotated[str, Depends(oauth2_scheme)]
) -> User:
    """
    Get current authenticated user from JWT token or API key.

    Args:
        session: Database session
        token: JWT access token or API key

    Returns:
        Current User object

    Raises:
        HTTPException: If token is invalid or user not found
    """
    if token.startswith("ngs360_"):
        return authenticate_api_key(session, token)

    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )

    try:
        payload = decode_token(token)
        user_id_str: str | None = payload.get("sub")
        if user_id_str is None:
            raise credentials_exception

        # Parse the UUID from the string
        user_id = uuid.UUID(user_id_str)

    except (PyJWTError, ValueError):
        raise credentials_exception

    user = session.get(User, user_id)
    if user is None:
        raise credentials_exception

    return user


def get_current_active_user(
    current_user: Annotated[User, Depends(get_current_user)]
) -> User:
    """
    Get current active user (must be active and verified)

    Args:
        current_user: Current user from get_current_user

    Returns:
        Current User object

    Raises:
        HTTPException: If user is inactive or unverified
    """
    if not current_user.is_active:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Inactive user"
        )

    if not current_user.is_verified:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Email not verified"
        )

    return current_user


def get_current_superuser(
    current_user: Annotated[User, Depends(get_current_active_user)]
) -> User:
    """
    Get current superuser (must be active, verified, and superuser)

    Args:
        current_user: Current user from get_current_active_user

    Returns:
        Current User object

    Raises:
        HTTPException: If user is not a superuser
    """
    if not current_user.is_superuser:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Not enough permissions"
        )

    return current_user


def optional_current_user(
    session: SessionDep,
    token: Annotated[str | None, Depends(oauth2_scheme_optional)]
) -> User | None:
    """
    Get current user if token is provided, None otherwise

    Args:
        session: Database session
        token: Optional JWT access token or API key

    Returns:
        Current User object or None
    """
    if token is None:
        return None

    if token.startswith("ngs360_"):
        try:
            return authenticate_api_key(session, token)
        except HTTPException:
            return None

    try:
        payload = decode_token(token)
        user_id_str: str | None = payload.get("sub")
        if user_id_str is None:
            return None

        # Parse the UUID from the string
        user_id = uuid.UUID(user_id_str)

        return session.get(User, user_id)
    except (PyJWTError, ValueError):
        return None


# Type aliases for cleaner endpoint signatures
CurrentUser = Annotated[User, Depends(get_current_user)]
CurrentActiveUser = Annotated[User, Depends(get_current_active_user)]
CurrentSuperuser = Annotated[User, Depends(get_current_superuser)]
OptionalUser = Annotated[User | None, Depends(optional_current_user)]
