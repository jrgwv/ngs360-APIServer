"""
OAuth2 service for external authentication providers
"""
import logging
from datetime import datetime, timezone
import os
from typing import Any, Dict, Optional
from urllib.parse import urlencode
import uuid
from pathlib import Path

from fastapi import HTTPException, status
from sqlmodel import Session, select
import httpx
import yaml

from api.auth.models import (
    User, OAuthProvider, OAuthProviderName,
    OAuthProviderInfo, AvailableProvidersResponse
)
from api.rbac.services import assign_default_roles
from core.config import get_settings
from core.security import generate_secure_token

from api.auth.services import is_bootstrap_admin

logger = logging.getLogger(__name__)


class OAuth2ProviderConfig:
    """Configuration for OAuth2 providers loaded from config file"""

    _config: Dict[str, Any] = None
    _providers: Dict[str, Dict] = {}

    @classmethod
    def load_config(cls, config_path: str = "config/oauth_providers.yaml"):
        """Load provider configuration from YAML file"""
        if cls._config is not None:
            return  # Already loaded

        config_file = Path(config_path)
        if config_file.exists():
            with open(config_file, 'r') as f:
                cls._config = yaml.safe_load(f)
                cls._providers = cls._config.get('providers', {})
        else:
            # Fallback to empty config if file doesn't exist
            cls._config = {'providers': {}, 'dynamic_provider': {'enabled': True}}
            cls._providers = {}

    @classmethod
    def get_provider_config(cls, provider: str) -> dict:
        """Get configuration for OAuth provider (built-in or dynamic)"""
        cls.load_config()

        # Check if it's a built-in provider
        if provider in cls._providers:
            config = cls._providers[provider]
            return cls._build_provider_config(config)

        # Check if it's the dynamic corporate provider
        return cls._get_dynamic_provider_config(provider)

    @classmethod
    def _build_provider_config(cls, config: dict) -> dict:
        """Build provider config from YAML definition"""
        return {
            "authorize_url": config['authorize_url'],
            "token_url": config['token_url'],
            "userinfo_url": config['userinfo_url'],
            "scopes": config['scopes'],
            "scope_separator": config.get('scope_separator', ' '),
            "field_mapping": config.get('field_mapping', {}),
        }

    @classmethod
    def _get_dynamic_provider_config(cls, provider: str) -> dict:
        """Get configuration for dynamically configured corporate provider"""
        settings = get_settings()

        if settings.OAUTH_CORP_NAME and provider.lower() == settings.OAUTH_CORP_NAME.lower():
            if not all([
                settings.OAUTH_CORP_AUTHORIZE_URL,
                settings.OAUTH_CORP_TOKEN_URL,
                settings.OAUTH_CORP_USERINFO_URL,
            ]):
                raise ValueError(f"Corporate OAuth provider '{provider}' is not fully configured")

            scopes_str = settings.OAUTH_CORP_SCOPES or "openid,email,profile"
            scopes = [scope.strip() for scope in scopes_str.split(",")]

            return {
                "authorize_url": settings.OAUTH_CORP_AUTHORIZE_URL,
                "token_url": settings.OAUTH_CORP_TOKEN_URL,
                "userinfo_url": settings.OAUTH_CORP_USERINFO_URL,
                "scopes": scopes,
                "scope_separator": " ",
                "field_mapping": {
                    "provider_user_id": "bmsid|sub|id",
                    "provider_username": "sub|username|login",
                    "email": "email",
                    "name": "name|displayName|email",
                    "picture": "picture",
                }
            }

        raise ValueError(f"Unsupported OAuth provider: {provider}")

    @classmethod
    def get_client_credentials(cls, provider: str) -> tuple[Optional[str], Optional[str]]:
        """Get client ID and secret from environment variables"""
        cls.load_config()

        # Check configured providers
        if provider in cls._providers:
            config = cls._providers[provider]
            client_id = os.getenv(config['client_id_env'])
            client_secret = os.getenv(config['client_secret_env'])
            return client_id, client_secret

        # Check dynamic provider
        settings = get_settings()
        if settings.OAUTH_CORP_NAME and provider == settings.OAUTH_CORP_NAME.lower():
            return settings.OAUTH_CORP_CLIENT_ID, settings.OAUTH_CORP_CLIENT_SECRET

        return None, None

    @classmethod
    def get_all_providers(cls) -> Dict[str, Dict]:
        """Get all available providers with their configs"""
        cls.load_config()

        available = {}

        # Add configured providers that have credentials
        for name, config in cls._providers.items():
            client_id, client_secret = cls.get_client_credentials(name)
            if client_id and client_secret:
                available[name] = {
                    'display_name': config.get('display_name', name.title()),
                    'logo_url': config.get('logo_url', f'/img/{name}.svg'),
                    'enabled': True,
                }

        # Add dynamic provider if configured
        settings = get_settings()
        if settings.OAUTH_CORP_NAME and settings.OAUTH_CORP_CLIENT_ID:
            corp_name = settings.OAUTH_CORP_NAME.lower()
            available[corp_name] = {
                'display_name': settings.OAUTH_CORP_DISPLAY_NAME,
                'logo_url': f'/img/{corp_name}.svg',
                'enabled': True,
            }

        return available


def get_available_providers() -> AvailableProvidersResponse:
    """Get list of configured OAuth providers"""
    providers_dict = OAuth2ProviderConfig.get_all_providers()

    providers_info = []

    for name, config in providers_dict.items():
        providers_info.append(OAuthProviderInfo(
            name=name,
            display_name=config['display_name'],
            logo_url=config['logo_url'],
            authorize_url=f"/api/v1/auth/oauth/{name}/authorize"
        ))

    return AvailableProvidersResponse(
        count=len(providers_info),
        providers=providers_info
    )


def get_authorization_url(
    provider: str,
    redirect_uri: str,
    state: str | None = None
) -> str:
    """
    Generate OAuth2 authorization URL

    Args:
        provider: OAuth provider name (google, github, microsoft)
        redirect_uri: Callback URL after authorization
        state: Optional state parameter for CSRF protection

    Returns:
        Authorization URL to redirect user to

    Raises:
        ValueError: If provider is not supported
        HTTPException: If provider credentials not configured
    """
    settings = get_settings()
    config = OAuth2ProviderConfig.get_provider_config(provider)
    # Get client ID based on provider
    match provider:
        case "google":
            client_id = settings.OAUTH_GOOGLE_CLIENT_ID
        case "github":
            client_id = settings.OAUTH_GITHUB_CLIENT_ID
        case "microsoft":
            client_id = settings.OAUTH_MICROSOFT_CLIENT_ID
        case _ if settings.OAUTH_CORP_NAME and provider == settings.OAUTH_CORP_NAME.lower():
            client_id = settings.OAUTH_CORP_CLIENT_ID
        case _:
            client_id = None

    if not client_id:
        raise HTTPException(
            status_code=status.HTTP_501_NOT_IMPLEMENTED,
            detail=f"{provider.title()} OAuth not configured"
        )

    # Generate state if not provided
    if not state:
        state = generate_secure_token(16)

    # Build authorization URL
    scopes = " ".join(config["scopes"])
    params = {
        "client_id": client_id,
        "redirect_uri": redirect_uri,
        "response_type": "code",
        "scope": scopes,
        "state": state,
    }

    # GitHub uses comma-separated scopes
    if provider == "github":
        params["scope"] = ",".join(config["scopes"])

    query_string = urlencode(params)
    return f"{config['authorize_url']}?{query_string}"


async def exchange_code_for_token(
    provider: str,
    code: str,
    redirect_uri: str
) -> dict:
    """
    Exchange authorization code for access token

    Args:
        provider: OAuth provider name
        code: Authorization code from callback
        redirect_uri: Callback URL (must match authorization request)

    Returns:
        Token response from provider

    Raises:
        HTTPException: If token exchange fails
    """
    settings = get_settings()
    config = OAuth2ProviderConfig.get_provider_config(provider)

    # Get client credentials
    match provider:
        case "google":
            client_id = settings.OAUTH_GOOGLE_CLIENT_ID
            client_secret = settings.OAUTH_GOOGLE_CLIENT_SECRET
        case "github":
            client_id = settings.OAUTH_GITHUB_CLIENT_ID
            client_secret = settings.OAUTH_GITHUB_CLIENT_SECRET
        case "microsoft":
            client_id = settings.OAUTH_MICROSOFT_CLIENT_ID
            client_secret = settings.OAUTH_MICROSOFT_CLIENT_SECRET
        case _ if settings.OAUTH_CORP_NAME and provider == settings.OAUTH_CORP_NAME.lower():
            client_id = settings.OAUTH_CORP_CLIENT_ID
            client_secret = settings.OAUTH_CORP_CLIENT_SECRET
        case _:
            client_id = None
            client_secret = None

    if not client_id or not client_secret:
        raise HTTPException(
            status_code=status.HTTP_501_NOT_IMPLEMENTED,
            detail=f"{provider.title()} OAuth not configured"
        )

    # Exchange code for token
    data = {
        "client_id": client_id,
        "client_secret": client_secret,
        "code": code,
        "redirect_uri": redirect_uri,
        "grant_type": "authorization_code",
    }

    headers = {"Accept": "application/json"}

    try:
        async with httpx.AsyncClient() as client:
            response = await client.post(
                config["token_url"],
                data=data,
                headers=headers
            )
            response.raise_for_status()
            return response.json()
    except httpx.HTTPError as e:
        logger.error(f"Token exchange failed: {e}")
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Failed to exchange authorization code"
        )


async def get_user_info(provider: str, access_token: str) -> dict:
    """
    Get user information from OAuth provider

    Args:
        provider: OAuth provider name
        access_token: Access token from provider

    Returns:
        User information from provider

    Raises:
        HTTPException: If user info request fails
    """
    config = OAuth2ProviderConfig.get_provider_config(provider)

    headers = {
        "Authorization": f"Bearer {access_token}",
        "Accept": "application/json"
    }

    try:
        async with httpx.AsyncClient() as client:
            response = await client.get(
                config["userinfo_url"],
                headers=headers
            )
            response.raise_for_status()
            user_data = response.json()
            logger.debug("Received user data from %s (keys: %s)", provider, sorted(user_data.keys()))

            # Normalize user data across providers
            return _normalize_user_data(provider, user_data)
    except httpx.HTTPError as e:
        logger.error(f"Failed to get user info: {e}")
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Failed to get user information"
        )


def _normalize_user_data(provider: str, data: dict) -> dict:
    """Normalize user data using field mapping from config"""
    config = OAuth2ProviderConfig.get_provider_config(provider)
    field_mapping = config.get('field_mapping', {})

    normalized = {}

    for target_field, source_spec in field_mapping.items():
        # Support fallback syntax: "field1|field2|field3"
        sources = source_spec.split('|') if isinstance(source_spec, str) else [source_spec]

        for source in sources:
            value = data.get(source.strip())
            if value:
                # Convert to string if needed (e.g., GitHub IDs are integers)
                if target_field == 'provider_user_id':
                    value = str(value)
                normalized[target_field] = value
                break

    return normalized


def find_or_create_oauth_user(
    session: Session,
    provider: str,
    provider_data: dict,
    access_token: str,
    refresh_token: str | None = None
) -> User:
    """
    Find existing user or create new user from OAuth data

    Args:
        session: Database session
        provider: OAuth provider name
        provider_data: Normalized user data from provider
        access_token: OAuth access token
        refresh_token: OAuth refresh token (optional)

    Returns:
        User object (existing or newly created)

    Raises:
        HTTPException: If user creation fails
    """
    provider_user_id = provider_data.get("provider_user_id")
    provider_username = provider_data.get("provider_username")
    email = provider_data.get("email")

    # Optional allowlist: only listed emails may sign in or be created via SSO.
    allowed = get_settings().OAUTH_ALLOWED_EMAILS
    if allowed and (not email or email.strip().lower() not in allowed):
        logger.warning("OAuth sign-in refused: email not in OAUTH_ALLOWED_EMAILS")
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="This account is not permitted to sign in",
        )

    if not provider_user_id or not (email or provider_username):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid user data from OAuth provider"
        )

    # Check if OAuth provider link already exists
    statement = select(OAuthProvider).where(
        OAuthProvider.provider_name == provider,
        OAuthProvider.provider_user_id == provider_user_id
    )
    oauth_link = session.exec(statement).first()

    if oauth_link:
        logger.debug(
            "Found existing OAuth link for provider %s and user ID %s",
            provider, provider_user_id
            )
        # User already exists, update tokens
        oauth_link.access_token = access_token
        oauth_link.refresh_token = refresh_token
        oauth_link.updated_at = datetime.now(timezone.utc)
        session.add(oauth_link)
        session.commit()

        # Return existing user
        user = session.get(User, oauth_link.user_id)
        if not user:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="User not found"
            )
        return user

    if email:
        # Check if user with email already exists
        statement = select(User).where(User.email == email)
    else:
        # If we don't have an email, we have to check by provider user ID (less ideal)
        statement = select(User).join(OAuthProvider).where(
            OAuthProvider.provider_name == provider,
            OAuthProvider.provider_user_id == provider_user_id
        )
    user = session.exec(statement).first()

    if not user:
        logger.debug("No existing user, creating new user...")
        # Create new user
        username = provider_username or email.split("@")[0]
        # Ensure unique username
        base_username = username
        counter = 1
        while True:
            statement = select(User).where(User.username == username)
            if not session.exec(statement).first():
                break
            username = f"{base_username}{counter}"
            counter += 1

        # If this is the first user, make them admin
        # Same rule as register_user, from the same function -- see
        # is_bootstrap_admin. Previously this site carried its own copy.
        is_admin = is_bootstrap_admin(username)
        if is_admin:
            logger.warning(
                "creating %s as a superuser: listed in BOOTSTRAP_ADMIN_USERNAMES",
                username,
            )

        user = User(
            email=email,
            username=username,
            full_name=provider_data.get("name"),
            hashed_password=None,  # OAuth-only user
            is_active=True,
            is_verified=True,  # Verified by OAuth provider
            is_superuser=is_admin
        )
        session.add(user)
        session.flush()

        # Same transaction as the user row: an SSO user who arrives without a
        # role would get 403s on their very first page.
        assign_default_roles(session, user)

        session.commit()
        session.refresh(user)

    # Link OAuth provider to user
    logger.debug("Linking OAuth provider %s to user %s", provider, user.username)
    oauth_provider = OAuthProvider(
        user_id=user.id,
        provider_name=provider,
        provider_user_id=provider_user_id,
        access_token=access_token,
        refresh_token=refresh_token
    )
    session.add(oauth_provider)
    session.commit()

    return user


def get_user_oauth_providers(session: Session, user: User) -> list[str]:
    """Get list of linked OAuth providers for the user"""
    oauth_providers = select(OAuthProvider.provider_name).where(OAuthProvider.user_id == user.id)
    return list(session.exec(oauth_providers).all())


def link_oauth_account(
    session: Session,
    user_id: uuid.UUID,
    provider: str,
    provider_data: dict,
    access_token: str,
    refresh_token: str | None = None
) -> OAuthProvider:
    """
    Link OAuth provider to existing user account

    Args:
        session: Database session
        user_id: User ID to link to
        provider: OAuth provider name
        provider_data: Normalized user data from provider
        access_token: OAuth access token
        refresh_token: OAuth refresh token (optional)

    Returns:
        Created OAuthProvider link

    Raises:
        HTTPException: If link already exists or creation fails
    """
    provider_user_id = provider_data.get("provider_user_id")

    if not provider_user_id:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid user data from OAuth provider"
        )

    # Check if already linked
    statement = select(OAuthProvider).where(
        OAuthProvider.user_id == user_id,
        OAuthProvider.provider_name == provider
    )
    existing = session.exec(statement).first()

    if existing:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"{provider.title()} account already linked"
        )

    # Create link
    oauth_provider = OAuthProvider(
        user_id=user_id,
        provider_name=OAuthProviderName(provider),
        provider_user_id=provider_user_id,
        access_token=access_token,
        refresh_token=refresh_token
    )
    session.add(oauth_provider)
    session.commit()
    session.refresh(oauth_provider)

    return oauth_provider


def unlink_oauth_account(
    session: Session,
    user_id: uuid.UUID,
    provider: str
) -> bool:
    """
    Unlink OAuth provider from user account

    Args:
        session: Database session
        user_id: User ID
        provider: OAuth provider name

    Returns:
        True if unlinked successfully

    Raises:
        HTTPException: If cannot unlink (last auth method)
    """
    # Get user
    user = session.get(User, user_id)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found"
        )

    # Check if user has password
    has_password = user.hashed_password is not None

    # Count OAuth providers
    statement = select(OAuthProvider).where(
        OAuthProvider.user_id == user_id
    )
    oauth_count = len(session.exec(statement).all())

    # Prevent unlinking if it's the only auth method
    if not has_password and oauth_count <= 1:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Cannot unlink last authentication method"
        )

    # Find and delete OAuth link
    statement = select(OAuthProvider).where(
        OAuthProvider.user_id == user_id,
        OAuthProvider.provider_name == provider
    )
    oauth_link = session.exec(statement).first()

    if not oauth_link:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"{provider.title()} account not linked"
        )

    session.delete(oauth_link)
    session.commit()

    return True
