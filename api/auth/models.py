"""
Authentication models for users, tokens, and OAuth providers
"""
from datetime import datetime, timezone
from enum import Enum
import uuid
from sqlalchemy import Column, Text
from sqlmodel import Field, SQLModel
from pydantic import EmailStr, ConfigDict


class User(SQLModel, table=True):
    """User model with authentication support"""

    __tablename__ = "users"
    __searchable__ = ["email", "username", "full_name"]

    # Primary identifiers
    id: uuid.UUID | None = Field(default_factory=uuid.uuid4, primary_key=True)

    # Authentication
    email: str | None = Field(unique=True, index=True, max_length=255)
    username: str = Field(unique=True, index=True, max_length=50)
    hashed_password: str | None = Field(default=None, max_length=255)  # None for OAuth-only

    # Profile
    full_name: str | None = Field(default=None, max_length=255)

    # Status flags
    is_active: bool = Field(default=True)
    is_verified: bool = Field(default=False)
    is_superuser: bool = Field(default=False)

    # Timestamps
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    updated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    last_login: datetime | None = Field(default=None)

    # Security
    failed_login_attempts: int = Field(default=0)
    locked_until: datetime | None = Field(default=None)

    model_config = ConfigDict(from_attributes=True)


class RefreshToken(SQLModel, table=True):
    """Refresh token for maintaining user sessions"""

    __tablename__ = "refresh_tokens"

    id: uuid.UUID | None = Field(default_factory=uuid.uuid4, primary_key=True)
    username: str = Field(foreign_key="users.username", index=True)
    token: str = Field(unique=True, index=True, max_length=500)
    expires_at: datetime
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    revoked: bool = Field(default=False)
    revoked_at: datetime | None = Field(default=None)
    device_info: str | None = Field(default=None, max_length=500)

    model_config = ConfigDict(from_attributes=True)


class OAuthProviderName(str, Enum):
    """Supported OAuth providers"""
    GOOGLE = "google"
    GITHUB = "github"
    MICROSOFT = "microsoft"
    CORP = "corp"  # For internal corporate SSO


class OAuthProvider(SQLModel, table=True):
    """OAuth provider linkage for external authentication"""

    __tablename__ = "oauth_providers"

    id: uuid.UUID | None = Field(default_factory=uuid.uuid4, primary_key=True)
    user_id: uuid.UUID = Field(foreign_key="users.id", index=True)

    provider_name: str = Field(max_length=50)
    provider_user_id: str = Field(index=True, max_length=255)

    # OAuth tokens (should be encrypted in production).
    # TEXT, not VARCHAR: corporate SSO issues stateless JWTs that exceed any
    # reasonable VARCHAR limit (>1KB), which caused MySQL error 1406 on write.
    access_token: str | None = Field(default=None, sa_column=Column(Text))
    refresh_token: str | None = Field(default=None, sa_column=Column(Text))
    token_expires_at: datetime | None = Field(default=None)

    # Timestamps
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    updated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

    model_config = ConfigDict(from_attributes=True)


class PasswordResetToken(SQLModel, table=True):
    """Password reset token for secure password recovery"""

    __tablename__ = "password_reset_tokens"

    id: uuid.UUID | None = Field(default_factory=uuid.uuid4, primary_key=True)
    username: str = Field(foreign_key="users.username", index=True)
    token: str = Field(unique=True, index=True, max_length=255)
    expires_at: datetime
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    used: bool = Field(default=False)
    used_at: datetime | None = Field(default=None)

    model_config = ConfigDict(from_attributes=True)


class EmailVerificationToken(SQLModel, table=True):
    """Email verification token for confirming user email addresses"""

    __tablename__ = "email_verification_tokens"

    id: uuid.UUID | None = Field(default_factory=uuid.uuid4, primary_key=True)
    username: str = Field(foreign_key="users.username", index=True)
    token: str = Field(unique=True, index=True, max_length=255)
    expires_at: datetime
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    used: bool = Field(default=False)
    used_at: datetime | None = Field(default=None)

    model_config = ConfigDict(from_attributes=True)


# Request/Response Models

class UserRegister(SQLModel):
    """User registration request"""
    email: EmailStr
    username: str = Field(min_length=3, max_length=50)
    password: str = Field(max_length=100)  # Validation done in service layer
    full_name: str | None = None


class UserLogin(SQLModel):
    """User login request"""
    email: EmailStr
    password: str


class TokenResponse(SQLModel):
    """Authentication token response"""
    access_token: str
    refresh_token: str
    token_type: str = "bearer"
    expires_in: int


class RefreshTokenRequest(SQLModel):
    """Refresh token request"""
    refresh_token: str


class PasswordResetRequest(SQLModel):
    """Password reset request"""
    email: EmailStr


class PasswordResetConfirm(SQLModel):
    """Password reset confirmation"""
    token: str
    new_password: str = Field(max_length=100)  # Validation in service layer


class PasswordChange(SQLModel):
    """Password change request"""
    current_password: str
    new_password: str = Field(max_length=100)  # Validation in service layer


class EmailVerificationRequest(SQLModel):
    """Email verification request"""
    token: str


class ResendVerificationRequest(SQLModel):
    """Resend verification email request"""
    email: EmailStr


class OAuthLinkRequest(SQLModel):
    """Link OAuth provider to account"""
    code: str


class UserPublic(SQLModel):
    """Public user information"""
    # Optional: SSO providers that release no email create accounts without one.
    email: str | None
    username: str
    full_name: str | None
    is_active: bool
    is_verified: bool
    is_superuser: bool
    created_at: datetime
    last_login: datetime | None
    oauth_providers: list[str] = []


class UserUpdate(SQLModel):
    """User profile update"""
    full_name: str | None = None
    email: EmailStr | None = None
    username: str | None = None


class UsersPublic(SQLModel):
    """Paginated users response"""
    data: list[UserPublic]
    count: int
    page: int
    per_page: int


class OAuthProviderInfo(SQLModel):
    """OAuth provider information"""
    name: str
    display_name: str
    logo_url: str
    authorize_url: str


class AvailableProvidersResponse(SQLModel):
    """Available OAuth providers response"""
    count: int
    providers: list[OAuthProviderInfo]


class APIKey(SQLModel, table=True):
    """User-generated API key for programmatic access"""

    __tablename__ = "api_keys"

    id: uuid.UUID | None = Field(default_factory=uuid.uuid4, primary_key=True)
    user_id: uuid.UUID = Field(foreign_key="users.id", index=True)
    name: str = Field(max_length=100)
    key_prefix: str = Field(max_length=12)
    hashed_key: str = Field(unique=True, index=True, max_length=64)
    expires_at: datetime | None = Field(default=None)
    is_active: bool = Field(default=True)
    last_used_at: datetime | None = Field(default=None)
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    revoked_at: datetime | None = Field(default=None)

    model_config = ConfigDict(from_attributes=True)


class APIKeyCreate(SQLModel):
    """Request to create a new API key"""
    name: str = Field(min_length=1, max_length=100)
    expires_at: datetime | None = None


class APIKeyCreateResponse(SQLModel):
    """Response after creating an API key (includes raw key, shown only once)"""
    id: uuid.UUID
    name: str
    key: str
    key_prefix: str
    expires_at: datetime | None
    created_at: datetime


class APIKeyPublic(SQLModel):
    """Public API key info (no raw key)"""
    id: uuid.UUID
    name: str
    key_prefix: str
    expires_at: datetime | None
    is_active: bool
    last_used_at: datetime | None
    created_at: datetime
    revoked_at: datetime | None


class APIKeysPublic(SQLModel):
    """Paginated API keys response"""
    data: list[APIKeyPublic]
    count: int
    page: int
    per_page: int
