""" Test cases for the SSO-only controls: LOCAL_AUTH_ENABLED and OAUTH_ALLOWED_IDENTITIES """
import pytest
from fastapi import HTTPException
from fastapi.testclient import TestClient
from sqlmodel import Session

from api.auth.oauth2_service import find_or_create_oauth_user
from core.config import get_settings
from main import app


@pytest.fixture
def setting(monkeypatch):
    def _set(name: str, value: str):
        monkeypatch.setenv(name, value)
        get_settings.cache_clear()
    yield _set
    get_settings.cache_clear()


def _sso(session: Session, email, uid="u1", username="ssouser", login=None):
    data = {"provider_user_id": uid, "provider_username": username,
            "email": email, "name": "SSO User"}
    if login:
        data["provider_login"] = login
    return find_or_create_oauth_user(session, "corp", data, access_token="tok")


class TestLocalAuthSwitch:
    PASSWORD_ENDPOINTS = [
        ("/api/v1/auth/register", {}),
        ("/api/v1/auth/login", {}),
        ("/api/v1/auth/password-reset/request", {}),
        ("/api/v1/auth/password-reset/confirm", {}),
        ("/api/v1/auth/verify-email", {}),
        ("/api/v1/auth/resend-verification", {}),
    ]

    @pytest.mark.parametrize("path,body", PASSWORD_ENDPOINTS)
    def test_password_endpoints_are_hidden_when_disabled(self, setting, path, body):
        setting("LOCAL_AUTH_ENABLED", "false")
        response = TestClient(app).post(path, json=body)
        assert response.status_code == 404

    @pytest.mark.parametrize("path,body", PASSWORD_ENDPOINTS)
    def test_password_endpoints_exist_by_default(self, path, body):
        get_settings.cache_clear()
        response = TestClient(app).post(path, json=body)
        # Reached the handler: validation (422) rather than "no such route".
        assert response.status_code != 404

    def test_flag_defaults_to_enabled(self):
        get_settings.cache_clear()
        assert get_settings().LOCAL_AUTH_ENABLED is True

    def test_flag_values(self, setting):
        for value in ("false", "0", "NO", "off"):
            setting("LOCAL_AUTH_ENABLED", value)
            assert get_settings().LOCAL_AUTH_ENABLED is False


class TestOAuthAllowlist:

    def test_unlisted_email_is_refused_and_nothing_is_created(self, session, setting):
        from api.auth.models import User
        from sqlmodel import select

        setting("OAUTH_ALLOWED_IDENTITIES", "me@example.com")
        with pytest.raises(HTTPException) as exc:
            _sso(session, "stranger@example.com")
        assert exc.value.status_code == 403
        assert session.exec(select(User)).all() == []

    def test_missing_email_is_refused(self, session, setting):
        setting("OAUTH_ALLOWED_IDENTITIES", "me@example.com")
        with pytest.raises(HTTPException) as exc:
            _sso(session, None)
        assert exc.value.status_code == 403

    def test_listed_email_is_created_case_insensitively(self, session, setting):
        setting("OAUTH_ALLOWED_IDENTITIES", " Me@Example.com , other@example.com ")
        user = _sso(session, "ME@example.COM")
        assert user.email == "ME@example.COM"

    def test_empty_list_keeps_upstream_behaviour(self, session, setting):
        setting("OAUTH_ALLOWED_IDENTITIES", "")
        assert _sso(session, "anyone@example.com").id is not None

    def test_an_existing_link_is_checked_on_every_sign_in(self, session, setting):
        setting("OAUTH_ALLOWED_IDENTITIES", "me@example.com")
        _sso(session, "me@example.com", uid="same")
        setting("OAUTH_ALLOWED_IDENTITIES", "someone-else@example.com")
        with pytest.raises(HTTPException) as exc:
            _sso(session, "me@example.com", uid="same")
        assert exc.value.status_code == 403


class TestLoginClaimMatching:
    """IdPs that release no email (Cognito + corporate IdP, openid scope only)."""

    def test_login_claim_allows_a_user_with_no_email(self, session, setting):
        setting("OAUTH_ALLOWED_IDENTITIES", "AmazonFederate_me")
        user = _sso(session, None, uid="sub-1", username="AmazonFederate_me",
                    login="AmazonFederate_me")
        assert user.email is None
        assert user.username == "AmazonFederate_me"

    def test_other_login_claims_are_refused(self, session, setting):
        setting("OAUTH_ALLOWED_IDENTITIES", "AmazonFederate_me")
        with pytest.raises(HTTPException) as exc:
            _sso(session, None, uid="sub-2", username="AmazonFederate_other",
                 login="AmazonFederate_other")
        assert exc.value.status_code == 403

    def test_no_identity_at_all_is_refused(self, session, setting):
        setting("OAUTH_ALLOWED_IDENTITIES", "AmazonFederate_me")
        with pytest.raises(HTTPException) as exc:
            _sso(session, None, uid="sub-3", username="anonymous")
        assert exc.value.status_code == 403

    def test_corp_mapping_prefers_the_username_claim(self):
        from api.auth.oauth2_service import _normalize_user_data
        from unittest.mock import patch

        cfg = {"field_mapping": {
            "provider_user_id": "bmsid|sub|id",
            "provider_username": "username|sub|login",
            "provider_login": "username|preferred_username|login",
            "email": "email"}}
        with patch("api.auth.oauth2_service.OAuth2ProviderConfig.get_provider_config",
                   return_value=cfg):
            out = _normalize_user_data(
                "corp", {"sub": "uuid-1", "username": "AmazonFederate_me"})
        assert out == {"provider_user_id": "uuid-1",
                       "provider_username": "AmazonFederate_me",
                       "provider_login": "AmazonFederate_me"}
