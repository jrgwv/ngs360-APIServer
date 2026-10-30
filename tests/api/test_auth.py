"""
Unit tests for authentication functionality
"""
import pytest
from mock import patch
from fastapi.testclient import TestClient
from sqlmodel import Session, create_engine, SQLModel
from sqlmodel.pool import StaticPool

from main import app
from core.deps import get_db
from core.security import hash_password
from api.auth.models import User


# Test database setup
@pytest.fixture(name="session")
def session_fixture():
    """Create a test database session"""
    engine = create_engine(
        "sqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    SQLModel.metadata.create_all(engine)
    with Session(engine) as session:
        yield session


@pytest.fixture(name="client")
def client_fixture(session: Session):
    """Create a test client with test database"""
    def get_session_override():
        return session

    app.dependency_overrides[get_db] = get_session_override
    client = TestClient(app)
    yield client
    app.dependency_overrides.clear()


@pytest.fixture(name="test_user")
def test_user_fixture(session: Session):
    """Create a test user"""
    user = User(
        user_id="U-20260122-0001",
        email="testuser@example.com",
        username="testuser",
        hashed_password=hash_password("TestPassword123"),
        full_name="Test User",
        is_active=True,
        is_verified=True,
        is_superuser=False
    )
    session.add(user)
    session.commit()
    session.refresh(user)
    return user


@pytest.fixture(name="oauth_token_response")
def mock_oauth_token_response():
    """Mock OAuth token exchange response"""
    return {
        "access_token": "mock_access_token_12345",
        "refresh_token": "mock_refresh_token_67890",
        "token_type": "Bearer",
        "expires_in": 3600
    }


@pytest.fixture(name="oauth_user_info")
def mock_oauth_user_info():
    """Mock OAuth user info response"""
    return {
        "provider_user_id": "oauth_user_123",
        # "email": "oauth.user@example.com",
        "provider_username": "oauthuser",
        "name": "OAuth Test User",
        "picture": "https://example.com/avatar.jpg"
    }


@pytest.fixture(name="mock_oauth_provider")
def mock_oauth_provider(oauth_token_response, oauth_user_info):
    """
    Mock OAuth provider HTTP calls

    This fixture patches the async HTTP calls made by oauth2_service
    """
    with patch("api.auth.oauth2_service.exchange_code_for_token") as mock_exchange, \
         patch("api.auth.oauth2_service.get_user_info") as mock_user_info:

        # Configure async mocks
        mock_exchange.return_value = oauth_token_response
        mock_user_info.return_value = oauth_user_info

        yield {
            "exchange_code": mock_exchange,
            "user_info": mock_user_info
        }


class TestUserRegistration:
    """Test user registration functionality"""

    def test_register_new_user(self, client: TestClient):
        """Test successful user registration"""
        response = client.post(
            "/api/v1/auth/register",
            json={
                "email": "newuser@example.com",
                "username": "newuser",
                "password": "SecurePass123",
                "full_name": "New User"
            }
        )
        assert response.status_code == 201
        data = response.json()
        assert data["email"] == "newuser@example.com"
        assert data["username"] == "newuser"
        assert data["full_name"] == "New User"
        assert data["is_active"] is True
        assert data["is_verified"] is False  # Email not verified yet

    def test_register_duplicate_email(self, client: TestClient, test_user):
        """Test registration with duplicate email fails"""
        response = client.post(
            "/api/v1/auth/register",
            json={
                "email": test_user.email,
                "username": "differentuser",
                "password": "SecurePass123"
            }
        )
        assert response.status_code == 409
        assert "Email already registered" in response.json()["detail"]

    def test_register_duplicate_username(self, client: TestClient, test_user):
        """Test registration with duplicate username fails"""
        response = client.post(
            "/api/v1/auth/register",
            json={
                "email": "different@example.com",
                "username": test_user.username,
                "password": "SecurePass123"
            }
        )
        assert response.status_code == 409
        assert "Username already taken" in response.json()["detail"]

    def test_register_weak_password(self, client: TestClient):
        """Test registration with weak password fails"""
        response = client.post(
            "/api/v1/auth/register",
            json={
                "email": "newuser@example.com",
                "username": "newuser",
                "password": "weak"  # Too short
            }
        )
        assert response.status_code == 400
        assert "Password must be at least" in response.json()["detail"]


class TestUserLogin:
    """Test user login functionality"""

    def test_login_success(self, client: TestClient, test_user):
        """Test successful login"""
        response = client.post(
            "/api/v1/auth/login",
            data={
                "username": test_user.email,  # username field contains email
                "password": "TestPassword123"
            }
        )
        assert response.status_code == 200
        data = response.json()
        assert "access_token" in data
        assert "refresh_token" in data
        assert data["token_type"] == "bearer"
        assert data["expires_in"] > 0

    def test_login_wrong_password(self, client: TestClient, test_user):
        """Test login with wrong password fails"""
        response = client.post(
            "/api/v1/auth/login",
            data={
                "username": test_user.email,
                "password": "WrongPassword123"
            }
        )
        assert response.status_code == 401
        assert "Incorrect email or password" in response.json()["detail"]

    def test_login_nonexistent_user(self, client: TestClient):
        """Test login with nonexistent user fails"""
        response = client.post(
            "/api/v1/auth/login",
            data={
                "username": "nonexistent@example.com",
                "password": "SomePassword123"
            }
        )
        assert response.status_code == 401


class TestOAuthLogin:
    """Test OAuth login functionality"""

    def test_get_available_oauth_providers(self, client: TestClient):
        """Test retrieving no available OAuth providers"""
        response = client.get("/api/v1/auth/oauth/providers")
        assert response.status_code == 200
        data = response.json()
        assert data["count"] == 0
        assert "providers" in data
        assert isinstance(data["providers"], list)
        assert len(data["providers"]) == 0

    def test_get_available_providers(self, client: TestClient):
        """Test retrieving 1 available OAuth providers"""

        with patch("api.auth.oauth2_service.get_settings") as mock_settings:
            # Explicitly disable other providers (or else they are MagicMock'd)
            mock_settings.return_value.OAUTH_GOOGLE_CLIENT_ID = None
            mock_settings.return_value.OAUTH_GOOGLE_CLIENT_SECRET = None
            mock_settings.return_value.OAUTH_GITHUB_CLIENT_ID = None
            mock_settings.return_value.OAUTH_GITHUB_CLIENT_SECRET = None
            mock_settings.return_value.OAUTH_MICROSOFT_CLIENT_ID = None
            mock_settings.return_value.OAUTH_MICROSOFT_CLIENT_SECRET = None
            mock_settings.return_value.OAUTH_CORP_NAME = "testcorp"
            mock_settings.return_value.OAUTH_CORP_DISPLAY_NAME = "TestCorp"
            mock_settings.return_value.OAUTH_CORP_CLIENT_ID = "test_client_id"
            mock_settings.return_value.OAUTH_CORP_CLIENT_SECRET = "test_secret"
            mock_settings.return_value.client_origin = "http://localhost:3000"

            response = client.get("/api/v1/auth/oauth/providers")
            assert response.status_code == 200
            data = response.json()
            assert data["count"] == 1
            assert "providers" in data
            assert isinstance(data["providers"], list)
            assert len(data["providers"]) == 1

    def test_oauth_login_redirect(self, client: TestClient):
        """Test successful OAuth login (mocked)"""
        with patch("api.auth.oauth2_service.get_settings") as mock_settings:
            mock_settings.return_value.client_origin = "http://localhost:3000"
            mock_settings.return_value.OAUTH_CORP_NAME = "corp"
            mock_settings.return_value.OAUTH_ALLOWED_EMAILS = frozenset()
            mock_settings.return_value.OAUTH_CORP_CLIENT_ID = "test_client_id"
            mock_settings.return_value.OAUTH_CORP_CLIENT_SECRET = "test_secret"
            mock_settings.return_value.OAUTH_CORP_AUTHORIZE_URL = "https://oauth.testcorp.com/authorize"  # noqa: E501
            mock_settings.return_value.OAUTH_CORP_TOKEN_URL = "https://oauth.testcorp.com/token"  # noqa: E501
            mock_settings.return_value.OAUTH_CORP_USERINFO_URL = "https://oauth.testcorp.com/userinfo"  # noqa: E501

            response = client.get(
                "/api/v1/auth/oauth/corp/authorize",
                follow_redirects=False
            )
            assert response.status_code == 307  # Redirect
            assert "oauth.testcorp.com" in response.headers["location"]

    def test_oauth_login_callback(self, client: TestClient, mock_oauth_provider):
        """Test OAuth callback handling (mocked)"""
        with patch("api.auth.oauth2_service.get_settings") as mock_settings:
            mock_settings.return_value.client_origin = "http://localhost:3000"
            mock_settings.return_value.OAUTH_CORP_NAME = "corp"
            mock_settings.return_value.OAUTH_ALLOWED_EMAILS = frozenset()
            mock_settings.return_value.OAUTH_CORP_CLIENT_ID = "test_client_id"
            mock_settings.return_value.OAUTH_CORP_CLIENT_SECRET = "test_secret"
            mock_settings.return_value.OAUTH_CORP_AUTHORIZE_URL = "https://oauth.testcorp.com/authorize"  # noqa: E501
            mock_settings.return_value.OAUTH_CORP_TOKEN_URL = "https://oauth.testcorp.com/token"
            mock_settings.return_value.OAUTH_CORP_USERINFO_URL = "https://oauth.testcorp.com/userinfo"  # noqa: E501

            response = client.get(
                "/api/v1/auth/oauth/corp/callback",
                params={"code": "mock_code_123"}
            )
            assert response.status_code == 200
            data = response.json()
            assert "access_token" in data
            assert "refresh_token" in data
            assert data["token_type"] == "bearer"
            assert data["expires_in"] > 0


class TestTokenRefresh:
    """Test token refresh functionality"""

    def test_refresh_token_success(self, client: TestClient, test_user):
        """Test successful token refresh"""
        # First login to get tokens
        login_response = client.post(
            "/api/v1/auth/login",
            data={
                "username": test_user.email,
                "password": "TestPassword123"
            }
        )
        refresh_token = login_response.json()["refresh_token"]

        # Refresh the token
        response = client.post(
            "/api/v1/auth/refresh",
            json={"refresh_token": refresh_token}
        )
        assert response.status_code == 200
        data = response.json()
        assert "access_token" in data
        assert "refresh_token" in data
        # New refresh token should be different (token rotation)
        assert data["refresh_token"] != refresh_token

    def test_refresh_invalid_token(self, client: TestClient):
        """Test refresh with invalid token fails"""
        response = client.post(
            "/api/v1/auth/refresh",
            json={"refresh_token": "invalid-token"}
        )
        assert response.status_code == 401

    def test_refresh_token_reuse_fails(self, client: TestClient, test_user):
        """Test that refresh token cannot be reused"""
        # Login and get refresh token
        login_response = client.post(
            "/api/v1/auth/login",
            data={
                "username": test_user.email,
                "password": "TestPassword123"
            }
        )
        refresh_token = login_response.json()["refresh_token"]

        # Use refresh token once
        client.post(
            "/api/v1/auth/refresh",
            json={"refresh_token": refresh_token}
        )

        # Try to use same token again (should fail)
        response = client.post(
            "/api/v1/auth/refresh",
            json={"refresh_token": refresh_token}
        )
        assert response.status_code == 401


class TestProtectedEndpoints:
    """Test authentication on protected endpoints"""

    def test_access_protected_endpoint_with_token(
        self,
        client: TestClient,
        test_user
    ):
        """Test accessing protected endpoint with valid token"""
        # Login to get access token
        login_response = client.post(
            "/api/v1/auth/login",
            data={
                "username": test_user.email,
                "password": "TestPassword123"
            }
        )
        access_token = login_response.json()["access_token"]

        # Access protected endpoint
        response = client.get(
            "/api/v1/auth/me",
            headers={"Authorization": f"Bearer {access_token}"}
        )
        assert response.status_code == 200
        data = response.json()
        assert data["email"] == test_user.email
        assert data["username"] == test_user.username
        assert data["is_superuser"] == test_user.is_superuser

    def test_access_protected_endpoint_without_token(self, client: TestClient):
        """Test accessing protected endpoint without token fails"""
        response = client.get("/api/v1/auth/me")
        assert response.status_code == 401

    def test_access_protected_endpoint_invalid_token(
        self,
        client: TestClient
    ):
        """Test accessing protected endpoint with invalid token fails"""
        response = client.get(
            "/api/v1/auth/me",
            headers={"Authorization": "Bearer invalid-token"}
        )
        assert response.status_code == 401


class TestLogout:
    """Test logout functionality"""

    def test_logout_success(self, client: TestClient, test_user):
        """Test successful logout"""
        # Login first
        login_response = client.post(
            "/api/v1/auth/login",
            data={
                "username": test_user.email,
                "password": "TestPassword123"
            }
        )
        refresh_token = login_response.json()["refresh_token"]

        # Logout
        response = client.post(
            "/api/v1/auth/logout",
            json={"refresh_token": refresh_token}
        )
        assert response.status_code == 200
        assert "Logged out successfully" in response.json()["message"]

        # Try to use revoked refresh token (should fail)
        refresh_response = client.post(
            "/api/v1/auth/refresh",
            json={"refresh_token": refresh_token}
        )
        assert refresh_response.status_code == 401


class TestPasswordChange:
    """Test password change functionality"""

    def test_change_password_success(self, client: TestClient, test_user):
        """Test successful password change"""
        # Login to get access token
        login_response = client.post(
            "/api/v1/auth/login",
            data={
                "username": test_user.email,
                "password": "TestPassword123"
            }
        )
        access_token = login_response.json()["access_token"]

        # Change password
        response = client.post(
            "/api/v1/auth/password/change",
            headers={"Authorization": f"Bearer {access_token}"},
            json={
                "current_password": "TestPassword123",
                "new_password": "NewPassword456"
            }
        )
        assert response.status_code == 200

        # Verify old password no longer works
        old_login = client.post(
            "/api/v1/auth/login",
            data={
                "username": test_user.email,
                "password": "TestPassword123"
            }
        )
        assert old_login.status_code == 401

        # Verify new password works
        new_login = client.post(
            "/api/v1/auth/login",
            data={
                "username": test_user.email,
                "password": "NewPassword456"
            }
        )
        assert new_login.status_code == 200

    def test_change_password_wrong_current(
        self,
        client: TestClient,
        test_user
    ):
        """Test password change with wrong current password fails"""
        # Login
        login_response = client.post(
            "/api/v1/auth/login",
            data={
                "username": test_user.email,
                "password": "TestPassword123"
            }
        )
        access_token = login_response.json()["access_token"]

        # Try to change with wrong current password
        response = client.post(
            "/api/v1/auth/password/change",
            headers={"Authorization": f"Bearer {access_token}"},
            json={
                "current_password": "WrongPassword",
                "new_password": "NewPassword456"
            }
        )
        assert response.status_code == 400
        assert "Current password is incorrect" in response.json()["detail"]


class TestPasswordReset:
    """Test password reset functionality"""

    def test_request_password_reset(self, client: TestClient, test_user):
        """Test password reset request"""
        response = client.post(
            "/api/v1/auth/password-reset/request",
            json={"email": test_user.email}
        )
        assert response.status_code == 200
        # Should always return success to prevent email enumeration
        assert "reset link" in response.json()["message"].lower()

    def test_request_password_reset_nonexistent_email(
        self,
        client: TestClient
    ):
        """Test password reset for nonexistent email still returns success"""
        response = client.post(
            "/api/v1/auth/password-reset/request",
            json={"email": "nonexistent@example.com"}
        )
        # Should return success to prevent email enumeration
        assert response.status_code == 200


class TestAccountSecurity:
    """Test account security features"""

    def test_account_lockout_after_failed_attempts(
        self,
        client: TestClient,
        test_user
    ):
        """Test account locks after multiple failed login attempts"""
        # Attempt multiple failed logins
        for _ in range(6):  # MAX_FAILED_LOGIN_ATTEMPTS is 5
            client.post(
                "/api/v1/auth/login",
                data={
                    "username": test_user.email,
                    "password": "WrongPassword"
                }
            )

        # Next attempt should indicate account is locked
        response = client.post(
            "/api/v1/auth/login",
            data={
                "username": test_user.email,
                "password": "TestPassword123"  # Even correct password
            }
        )
        assert response.status_code == 423  # Locked
        assert "locked" in response.json()["detail"].lower()


class TestSecurityUtilities:
    """Test security utility functions"""

    def test_password_hashing(self):
        """Test password hashing and verification"""
        from core.security import hash_password, verify_password

        password = "TestPassword123"
        hashed = hash_password(password)

        # Hash should be different from original
        assert hashed != password

        # Should verify correctly
        assert verify_password(password, hashed) is True

        # Wrong password should not verify
        assert verify_password("WrongPassword", hashed) is False

    def test_password_strength_validation(self):
        """Test password strength validation"""
        from core.security import validate_password_strength

        # Valid password
        is_valid, error = validate_password_strength("ValidPass123")
        assert is_valid is True
        assert error is None

        # Too short
        is_valid, error = validate_password_strength("Short1")
        assert is_valid is False
        assert "at least" in error.lower()

        # No uppercase
        is_valid, error = validate_password_strength("nouppercas123")
        assert is_valid is False
        assert "uppercase" in error.lower()

        # No lowercase
        is_valid, error = validate_password_strength("NOLOWERCASE123")
        assert is_valid is False
        assert "lowercase" in error.lower()

        # No digit
        is_valid, error = validate_password_strength("NoDigitPass")
        assert is_valid is False
        assert "digit" in error.lower()

    def test_jwt_token_creation_and_validation(self):
        """Test JWT token creation and decoding"""
        from core.security import create_access_token, decode_token
        import uuid

        user_id = str(uuid.uuid4())
        token = create_access_token({"sub": user_id})

        # Token should be a string
        assert isinstance(token, str)
        assert len(token) > 0

        # Should be able to decode
        payload = decode_token(token)
        assert payload["sub"] == user_id
        assert "exp" in payload
        assert "iat" in payload
        assert payload["type"] == "access"
