"""
OAuth2 authentication endpoints for external providers
"""
import logging
from fastapi import APIRouter, HTTPException, status, Query
from fastapi.responses import RedirectResponse

from core.deps import SessionDep
from core.security import create_access_token, create_refresh_token
from core.config import get_settings
from api.auth.models import TokenResponse, OAuthLinkRequest, AvailableProvidersResponse
from api.auth.deps import CurrentUser
import api.auth.oauth2_service as oauth2_service
from api.auth.services import update_last_login

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/auth/oauth", tags=["OAuth2 Authentication"])


@router.get("/providers")
def get_available_oauth_providers() -> AvailableProvidersResponse:
    """
    Get list of available OAuth providers

    Returns:
        List of supported OAuth providers
    """
    return oauth2_service.get_available_providers()


@router.get("/{provider}/authorize")
def oauth_authorize(
    provider: str,
    redirect_uri: str | None = Query(None)
) -> RedirectResponse:
    """
    Initiate OAuth2 authorization flow

    Redirects user to OAuth provider's authorization page.

    Args:
        provider: OAuth provider (google, github, microsoft)
        redirect_uri: Optional custom redirect URI

    Returns:
        Redirect to provider authorization page

    Raises:
        501: Provider not configured
        400: Invalid provider
    """
    settings = get_settings()

    # Use default redirect URI if not provided
    if not redirect_uri:
        logger.debug(f"No redirect_uri provided, using default for provider {provider}")
        redirect_uri = (
            f"{settings.client_origin}/api/v1/auth/oauth/"
            f"{provider}/callback"
        )
    logger.debug(f"Using redirect_uri: {redirect_uri} for provider {provider}")
    try:
        # Generate authorization URL
        auth_url = oauth2_service.get_authorization_url(
            provider,
            redirect_uri
        )
        logger.info(f"Redirecting requestor to {auth_url} for OAuth authorization")
        return RedirectResponse(url=auth_url)
    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e)
        )


@router.get("/{provider}/callback")
async def oauth_callback(
    session: SessionDep,
    provider: str,
    code: str = Query(...),
    state: str | None = Query(None),
    redirect_uri: str | None = Query(None)
) -> TokenResponse:
    """
    OAuth2 callback handler

    Handles the callback from OAuth provider after user authorization.
    Exchanges code for tokens and creates/updates user account.

    Args:
        session: Database session
        provider: OAuth provider name
        code: Authorization code from provider
        state: State parameter for CSRF protection
        redirect_uri: Redirect URI (must match authorization request)

    Returns:
        Access and refresh tokens

    Raises:
        400: Invalid code or failed to get user info
        501: Provider not configured
    """
    logger.debug(
        "Received OAuth callback with provider: "
        "%s, code: %s, state: %s, redirect_uri: %s",
        provider, code, state, redirect_uri
    )
    settings = get_settings()

    # Use default redirect URI if not provided
    if not redirect_uri:
        redirect_uri = (
            f"{settings.client_origin}/api/v1/auth/oauth/"
            f"{provider}/callback"
        )

    try:
        # Exchange code for access token
        logger.debug("Exchanging authorization code for token with provider %s", provider)
        token_response = await oauth2_service.exchange_code_for_token(
            provider,
            code,
            redirect_uri
        )
        logger.debug(
            "Received token response from provider %s (keys: %s)",
            provider, sorted(token_response.keys()))

        access_token = token_response.get("access_token")
        refresh_token_oauth = token_response.get("refresh_token")

        if not access_token:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Failed to get access token"
            )

        # Get user info from provider
        logger.debug("Fetching user info from provider %s using access token", provider)
        user_info = await oauth2_service.get_user_info(
            provider,
            access_token
        )
        logger.debug("Received user info from provider %s: %s", provider, user_info)

        # Find or create user
        user = oauth2_service.find_or_create_oauth_user(
            session,
            provider,
            user_info,
            access_token,
            refresh_token_oauth
        )

        # Update last login timestamp
        update_last_login(session, user.id)

        # Create our own JWT tokens
        jwt_access_token = create_access_token({"sub": str(user.id)})
        jwt_refresh_token = create_refresh_token(
            session,
            user.username,
            f"OAuth2:{provider}"
        )

        return TokenResponse(
            access_token=jwt_access_token,
            refresh_token=jwt_refresh_token.token,
            token_type="bearer",
            expires_in=settings.ACCESS_TOKEN_EXPIRE_MINUTES * 60
        )

    except HTTPException:
        raise
    except Exception as e:
        logger.exception(
            "OAuth authentication failed for provider %s: %s", provider, e
        )
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"OAuth authentication failed: {str(e)}"
        )


@router.post("/{provider}/link")
async def link_oauth_provider(
    session: SessionDep,
    current_user: CurrentUser,
    provider: str,
    link_request: OAuthLinkRequest
) -> dict:
    """
    Link OAuth provider to existing account

    Links an OAuth provider account to the currently authenticated user.

    Args:
        session: Database session
        current_user: Current authenticated user
        provider: OAuth provider name
        link_request: OAuth authorization code

    Returns:
        Success message

    Raises:
        400: Failed to link account
        409: Provider already linked
        401: Not authenticated
    """
    settings = get_settings()

    # Build redirect URI
    redirect_uri = (
        f"{settings.client_origin}/api/v1/auth/oauth/{provider}/callback"
    )

    try:
        # Exchange code for access token
        token_response = await oauth2_service.exchange_code_for_token(
            provider,
            link_request.code,
            redirect_uri
        )

        access_token = token_response.get("access_token")
        refresh_token = token_response.get("refresh_token")

        if not access_token:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Failed to get access token"
            )

        # Get user info from provider
        user_info = await oauth2_service.get_user_info(
            provider,
            access_token
        )

        # Link provider to current user
        oauth2_service.link_oauth_account(
            session,
            current_user.id,
            provider,
            user_info,
            access_token,
            refresh_token
        )

        # Update last login timestamp
        update_last_login(session, current_user.id)

        return {"message": f"{provider.title()} account linked successfully"}

    except HTTPException:
        raise
    except Exception as e:
        logger.exception(
            "Failed to link OAuth provider %s to user %s: %s",
            provider, current_user.id, e
        )
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Failed to link account: {str(e)}"
        )


@router.delete("/{provider}/unlink")
def unlink_oauth_provider(
    session: SessionDep,
    current_user: CurrentUser,
    provider: str
) -> dict:
    """
    Unlink OAuth provider from account

    Removes the OAuth provider link from the user's account.
    Cannot unlink if it's the only authentication method.

    Args:
        session: Database session
        current_user: Current authenticated user
        provider: OAuth provider name

    Returns:
        Success message

    Raises:
        400: Cannot unlink last auth method
        404: Provider not linked
        401: Not authenticated
    """
    oauth2_service.unlink_oauth_account(
        session,
        current_user.id,
        provider
    )

    return {"message": f"{provider.title()} account unlinked successfully"}
