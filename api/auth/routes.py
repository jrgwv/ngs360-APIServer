"""
Authentication endpoints for login, registration, and token management
"""
from typing import Annotated

from fastapi import (
    APIRouter, Depends, HTTPException, status, Request
)
from fastapi.security import OAuth2PasswordRequestForm

from core.deps import SessionDep
from core.security import create_access_token, create_refresh_token
from core.config import get_settings
from api.auth.models import (
    User, UserRegister, UserPublic, TokenResponse,
    RefreshTokenRequest, PasswordResetRequest, PasswordResetConfirm,
    EmailVerificationRequest, ResendVerificationRequest, PasswordChange,
    APIKeyCreate, APIKeyCreateResponse, APIKeyPublic, APIKeysPublic,
)
from api.auth.deps import CurrentUser, CurrentActiveUser
import api.auth.services as auth_services
from api.auth.oauth2_service import get_user_oauth_providers

router = APIRouter(prefix="/auth", tags=["Authentication"])


def require_local_auth() -> None:
    """Hide password-account endpoints when the deployment is SSO only."""
    if not get_settings().LOCAL_AUTH_ENABLED:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Not Found",
        )


LOCAL_AUTH = [Depends(require_local_auth)]


@router.post(
    "/register",
    response_model=UserPublic,
    status_code=status.HTTP_201_CREATED,
    dependencies=LOCAL_AUTH,
)
def register(
    session: SessionDep,
    user_data: UserRegister
) -> User:
    """
    Register a new user account

    Creates a new user with email/password authentication.
    Sends verification email to confirm email address.

    Args:
        session: Database session
        user_data: User registration data

    Returns:
        Created user information

    Raises:
        409: Email or username already exists
        400: Invalid password strength
    """
    user = auth_services.register_user(session, user_data)
    return user


@router.post("/login", response_model=TokenResponse, dependencies=LOCAL_AUTH)
def login(
    session: SessionDep,
    request: Request,
    form_data: Annotated[OAuth2PasswordRequestForm, Depends()]
) -> TokenResponse:
    """
    Login with email and password

    Authenticates user and returns access and refresh tokens.
    Username field should contain the email address.

    Args:
        session: Database session
        request: HTTP request (for device info)
        form_data: OAuth2 form with username (email) and password

    Returns:
        Access token and refresh token

    Raises:
        401: Invalid credentials
        423: Account locked due to failed attempts
    """
    # Authenticate user (username field contains email)
    user = auth_services.authenticate_user(
        session,
        form_data.username,
        form_data.password
    )

    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect email or password",
            headers={"WWW-Authenticate": "Bearer"},
        )

    # Get device info from request
    user_agent = request.headers.get("user-agent", "unknown")
    device_info = f"{user_agent[:100]}"

    # Create tokens
    settings = get_settings()
    access_token = create_access_token({"sub": str(user.id)})
    refresh_token = create_refresh_token(session, user.username, device_info)

    return TokenResponse(
        access_token=access_token,
        refresh_token=refresh_token.token,
        token_type="bearer",
        expires_in=settings.ACCESS_TOKEN_EXPIRE_MINUTES * 60
    )


@router.post("/refresh", response_model=TokenResponse)
def refresh_token(
    session: SessionDep,
    token_data: RefreshTokenRequest
) -> TokenResponse:
    """
    Refresh access token

    Uses refresh token to obtain new access and refresh tokens.
    Old refresh token is revoked (token rotation).

    Args:
        session: Database session
        token_data: Refresh token

    Returns:
        New access token and refresh token

    Raises:
        401: Invalid or expired refresh token
    """
    token_response = auth_services.refresh_access_token(
        session,
        token_data.refresh_token
    )
    return TokenResponse(**token_response)


@router.post("/logout")
def logout(
    session: SessionDep,
    token_data: RefreshTokenRequest
) -> dict:
    """
    Logout user

    Revokes the refresh token to prevent further token refreshes.
    Access token will remain valid until expiration.

    Args:
        session: Database session
        token_data: Refresh token to revoke

    Returns:
        Success message
    """
    auth_services.revoke_refresh_token(session, token_data.refresh_token)
    return {"message": "Logged out successfully"}


@router.get("/me", response_model=UserPublic)
def get_current_user_info(
    session: SessionDep,
    current_user: CurrentUser
) -> UserPublic:
    """
    Get current user profile

    Returns information about the authenticated user.

    Args:
        session: Database session
        current_user: Current authenticated user

    Returns:
        User profile information

    Raises:
        401: Not authenticated
    """
    oauth_providers = get_user_oauth_providers(session, current_user)
    user_info = UserPublic(
        email=current_user.email,
        username=current_user.username,
        full_name=current_user.full_name,
        is_active=current_user.is_active,
        is_verified=current_user.is_verified,
        is_superuser=current_user.is_superuser,
        created_at=current_user.created_at,
        last_login=current_user.last_login,
        oauth_providers=oauth_providers
    )
    return user_info


@router.post("/password-reset/request", dependencies=LOCAL_AUTH)
def request_password_reset(
    session: SessionDep,
    reset_request: PasswordResetRequest
) -> dict:
    """
    Request password reset

    Sends password reset email if account exists.
    Always returns success to prevent email enumeration.

    Args:
        session: Database session
        reset_request: Email address

    Returns:
        Success message
    """
    auth_services.initiate_password_reset(session, reset_request.email)
    return {
        "message": "If the email exists, a password reset link "
                   "has been sent"
    }


@router.post("/password-reset/confirm", dependencies=LOCAL_AUTH)
def confirm_password_reset(
    session: SessionDep,
    reset_data: PasswordResetConfirm
) -> dict:
    """
    Confirm password reset

    Resets password using the token from email.

    Args:
        session: Database session
        reset_data: Reset token and new password

    Returns:
        Success message

    Raises:
        400: Invalid or expired token
    """
    auth_services.complete_password_reset(
        session,
        reset_data.token,
        reset_data.new_password
    )
    return {"message": "Password reset successful"}


@router.post("/password/change")
def change_password(
    session: SessionDep,
    current_user: CurrentActiveUser,
    password_data: PasswordChange
) -> dict:
    """
    Change password

    Changes password for authenticated user.
    Requires current password for verification.

    Args:
        session: Database session
        current_user: Current authenticated user
        password_data: Current and new password

    Returns:
        Success message

    Raises:
        400: Invalid current password or weak new password
        401: Not authenticated
    """
    from core.security import verify_password, hash_password
    from core.security import validate_password_strength

    # Verify current password
    if not current_user.hashed_password or not verify_password(
        password_data.current_password,
        current_user.hashed_password
    ):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Current password is incorrect"
        )

    # Validate new password strength
    is_valid, error_msg = validate_password_strength(
        password_data.new_password
    )
    if not is_valid:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=error_msg
        )

    # Update password
    from datetime import datetime, timezone
    current_user.hashed_password = hash_password(
        password_data.new_password
    )
    current_user.updated_at = datetime.now(timezone.utc)
    session.add(current_user)
    session.commit()

    return {"message": "Password changed successfully"}


@router.post("/verify-email", dependencies=LOCAL_AUTH)
def verify_email(
    session: SessionDep,
    verification_data: EmailVerificationRequest
) -> dict:
    """
    Verify email address

    Verifies user email using token from verification email.

    Args:
        session: Database session
        verification_data: Verification token

    Returns:
        Success message

    Raises:
        400: Invalid or expired token
    """
    auth_services.verify_email(session, verification_data.token)
    return {"message": "Email verified successfully"}


@router.post("/resend-verification", dependencies=LOCAL_AUTH)
def resend_verification(
    session: SessionDep,
    resend_request: ResendVerificationRequest
) -> dict:
    """
    Resend verification email

    Sends a new verification email to the user.

    Args:
        session: Database session
        resend_request: Email address

    Returns:
        Success message

    Raises:
        404: User not found
        400: Email already verified
    """
    user = auth_services.get_user_by_email(session, resend_request.email)

    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found"
        )

    if user.is_verified:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Email already verified"
        )

    auth_services.create_and_send_verification_email(session, user)
    return {"message": "Verification email sent"}


# --- API Key Management ---


@router.post(
    "/api-keys",
    response_model=APIKeyCreateResponse,
    status_code=status.HTTP_201_CREATED,
)
def create_api_key(
    session: SessionDep,
    current_user: CurrentActiveUser,
    data: APIKeyCreate,
) -> APIKeyCreateResponse:
    """Create a new API key for the authenticated user."""
    api_key, raw_key = auth_services.create_user_api_key(
        session, current_user, data
    )
    return APIKeyCreateResponse(
        id=api_key.id,
        name=api_key.name,
        key=raw_key,
        key_prefix=api_key.key_prefix,
        expires_at=api_key.expires_at,
        created_at=api_key.created_at,
    )


@router.get("/api-keys", response_model=APIKeysPublic)
def list_api_keys(
    session: SessionDep,
    current_user: CurrentActiveUser,
    page: int = 1,
    per_page: int = 20,
) -> APIKeysPublic:
    """List API keys for the authenticated user."""
    keys, count = auth_services.list_user_api_keys(
        session, current_user, page, per_page
    )
    return APIKeysPublic(
        data=[APIKeyPublic.model_validate(k) for k in keys],
        count=count,
        page=page,
        per_page=per_page,
    )


@router.delete(
    "/api-keys/{key_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    summary="Retire an API key",
)
def delete_api_key(
    session: SessionDep,
    current_user: CurrentActiveUser,
    key_id: str,
) -> None:
    """
    Retire an API key. Equivalent to `POST /api-keys/{key_id}/revoke`.

    The key stops authenticating immediately. The record is kept, with
    `is_active = false` and `revoked_at` set, so that the retirement stays
    auditable -- it is not erased. It continues to appear in `GET /api-keys`.

    Idempotent: retiring an already-retired key succeeds and preserves the
    original `revoked_at`.
    """
    auth_services.delete_user_api_key(session, current_user, key_id)


@router.post(
    "/api-keys/{key_id}/revoke",
    response_model=APIKeyPublic,
)
def revoke_api_key(
    session: SessionDep,
    current_user: CurrentActiveUser,
    key_id: str,
) -> APIKeyPublic:
    """Revoke an API key (soft-disable)."""
    api_key = auth_services.revoke_user_api_key(session, current_user, key_id)
    return APIKeyPublic.model_validate(api_key)
