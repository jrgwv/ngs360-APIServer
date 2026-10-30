"""
Application Configuration
Add constants, secrets, env variables here
"""

from functools import lru_cache
import os
import json
from pathlib import Path
from typing import overload
from pydantic import computed_field, PrivateAttr
from pydantic_settings import BaseSettings, SettingsConfigDict
import boto3
from botocore.exceptions import ClientError
from dotenv import load_dotenv

# Load .env file into os.environ so os.getenv() works correctly
# This must happen before Settings class is instantiated
env_path = Path(__file__).parent.parent / ".env"
if env_path.exists():
    load_dotenv(env_path)


# Dev-only sentinel; refused outside dev by Settings.JWT_SECRET_KEY.
INSECURE_DEFAULT_JWT_SECRET = "change-this-secret-key-in-production"  # nosec B105
JWT_SECRET_MIN_LENGTH = 32


class InsecureConfigurationError(RuntimeError):
    """Raised when security-critical configuration is unsafe for this tier."""


def get_secret(secret_name: str, region_name: str) -> dict | None:
    """
    Retrieve secrets from AWS Secrets Manager

    Args:
        secret_name: Name of the secret in Secrets Manager
        region_name: AWS region where secret is stored

    Returns:
        dict: Parsed secret value or None if secret cannot be retrieved
    """
    session = boto3.session.Session()
    client = session.client(
        service_name='secretsmanager',
        region_name=region_name
    )
    try:
        secret_value_response = client.get_secret_value(
            SecretId=secret_name
        )
    except ClientError:
        return None
    # Parse and return the secret
    secret = secret_value_response['SecretString'].replace('\n', '')
    return json.loads(
        secret
    )


# Define settings class for univeral access
class Settings(BaseSettings):
    # Computed or constant values
    client_origin: str | None = os.getenv("client_origin")

    # Cache for AWS Secrets Manager to avoid multiple API calls
    # Note: Must use PrivateAttr for Pydantic v2 private attributes
    _secret_cache: dict | None = PrivateAttr(default=None)

    @overload
    def _get_config_value(self, env_var_name: str, default: str) -> str: ...

    @overload
    def _get_config_value(
        self, env_var_name: str, default: None = None
    ) -> str | None: ...

    def _get_config_value(
        self,
        env_var_name: str,
        default: str | None = None
    ) -> str | None:
        """
        Get configuration value from environment variable or AWS Secrets Manager (with caching).

        Args:
            env_var_name: Environment variable name to check first
            secret_key_name: Key name in AWS Secrets (defaults to env_var_name if not provided)
            default: Default value to return if not found in env or secrets

        Returns:
            Configuration value, or default value if not found
        """
        # 1. Check environment variable first
        env_value = os.getenv(env_var_name)
        if env_value:
            return env_value

        # 2. Try to get from AWS Secrets Manager with caching
        # Use cached secret if available
        if self._secret_cache is None:
            env_secret = os.getenv('ENV_SECRETS')
            if env_secret:
                self._secret_cache = get_secret(env_secret,
                                                os.getenv("AWS_REGION",
                                                          'us-east-1'))
        if self._secret_cache:
            secret_value = self._secret_cache.get(env_var_name)
            if secret_value is not None:
                return secret_value

        # 3. Return default value if provided
        return default

    @computed_field
    @property
    def LOG_LEVEL(self) -> str:
        """Get application log level from env or secrets (defaults to INFO)"""
        return self._get_config_value("LOG_LEVEL", default="INFO")

    @computed_field
    @property
    def ENVIRONMENT(self) -> str:
        """
        Deployment tier: "dev", "staging", or "prod".

        Set as an Elastic Beanstalk application environment property, one per
        environment. Nothing else distinguishes the tiers at runtime -- they are
        otherwise told apart only by which EB environment was deployed to, which
        means behaviour cannot be varied per tier without this value.

        Unrecognised values fall back to "dev", the least privileged tier: a
        typo must never cause a non-production setting to be treated as
        production, or vice versa.
        """
        value = self._get_config_value("ENVIRONMENT", default="dev").strip().lower()
        if value not in ("dev", "staging", "prod"):
            return "dev"
        return value

    @computed_field
    @property
    def RBAC_MODE(self) -> str:
        """
        Authorization enforcement mode: "off", "dry_run", or "enforce".

        Three properties, each deliberate:

        Unrecognised values resolve to "enforce", not to the default. A typo
        such as RBAC_MODE=enforced must never be read as "authorization is off"
        -- the failure mode of a misspelling has to be a visible 403, not a
        silent hole.

        The default is "dry_run" for this release and tightens to "enforce" in
        the Phase 5 release. Making the *default* move is what stops a
        forgotten flag from leaving a tier unprotected indefinitely: the switch
        decays toward safe rather than toward open.

        "off" is clamped to "dry_run" in prod. It exists for local work, and a
        production environment where authorization can be turned off entirely
        by one `eb setenv` is a worse risk than any it mitigates. Rollback is a
        forward fix -- grant the missing role -- per docs/RBAC.md.

        Note this is read from the environment and Secrets Manager only, never
        from the settings table: a PUT /settings/RBAC_MODE that switches
        authorization off would be self-defeating.
        """
        value = self._get_config_value("RBAC_MODE", default="dry_run").strip().lower()
        if value not in ("off", "dry_run", "enforce"):
            return "enforce"
        if value == "off" and self.ENVIRONMENT == "prod":
            return "dry_run"
        return value

    @computed_field
    @property
    def DEFAULT_USER_ROLE(self) -> str:
        """
        Global role granted to every user at creation. "none" disables it.

        Without this, a new user holds nothing, and under RBAC_MODE=enforce that
        is a 403 on every endpoint from their first request -- one support ticket
        per person who signs in, which is the most predictable way to make an
        authorization rollout look like an outage.

        "member" is deliberately a wide, read-heavy set rather than a minimal
        one: it is what an authenticated caller could already do before RBAC, so
        granting it changes nothing for anybody. Narrowing it later is a role
        edit through the API, not a deploy -- which is the whole reason roles are
        rows and permissions are code.

        Disabling takes the literal string "none" rather than an empty value,
        because _get_config_value treats empty as unset and falls through to the
        default -- so DEFAULT_USER_ROLE= would silently still grant `member`.
        Returned as "" so callers test one falsy condition either way.
        """
        value = self._get_config_value("DEFAULT_USER_ROLE", default="member").strip()
        return "" if value.lower() == "none" else value

    @computed_field
    @property
    def BOOTSTRAP_ADMIN_USERNAMES(self) -> frozenset[str]:
        """
        Usernames that receive `is_superuser` when their account is created.

        This replaces "the first user to register becomes an administrator",
        which was duplicated at both account-creation sites and is a privilege
        escalation path on any database with no users yet: whoever registers
        first gets superuser, and superuser short-circuits every permission check
        ahead of the resolver. It is also a race, because two concurrent
        registrations can both observe an empty table.

        That was tolerable while empty databases were hypothetical. The CI work
        established they are not -- a new tier, a restored snapshot, and the
        migrations job all start from nothing.

        Semantics, each chosen deliberately:

        * **Creation only.** A username added here later does not promote an
          existing account on next login. A configuration change should not
          silently grant superuser to someone who already has a session; use
          scripts/promote_superuser.py, which records who did it.
        * **Empty means nobody.** No fallback to first-user-wins, because a
          fallback that restores the unsafe behaviour whenever the variable is
          unset is not a fix. A fresh deployment with this unset gets no
          administrator, which is why the promote script exists and why startup
          warns when the database has no superuser.
        * **Compared case-insensitively and trimmed**, matching how the
          ownership backfill resolves usernames.
        """
        raw = self._get_config_value("BOOTSTRAP_ADMIN_USERNAMES", default="")
        return frozenset(
            name.strip().lower() for name in raw.split(",") if name.strip()
        )

    @computed_field
    @property
    def LOG_FORMAT(self) -> str:
        """
        Log output format: "json" or "text".

        JSON is the default so deployed logs are queryable in CloudWatch Logs
        Insights. Text is easier to read when running locally; the Docker
        entrypoint and local .env files can set LOG_FORMAT=text.
        """
        value = self._get_config_value("LOG_FORMAT", default="json").strip().lower()
        if value not in ("json", "text"):
            return "json"
        return value

    # AI Assistant Chat - deployed NGS360 LLM Agent on the LangGraph Platform
    @computed_field
    @property
    def LANGGRAPH_DEPLOYMENT_URL(self) -> str | None:
        """Base URL of the deployed LangGraph agent (LangSmith/LangGraph Platform).

        No default: must be supplied via env var or Secrets Manager for the
        target environment. Chat endpoints are disabled when it is unset.
        """
        return self._get_config_value("LANGGRAPH_DEPLOYMENT_URL")

    @computed_field
    @property
    def LANGSMITH_ASSISTANT_ID(self) -> str:
        """Graph name (or assistant UUID) to invoke on the deployment."""
        return self._get_config_value(
            "LANGSMITH_ASSISTANT_ID", default="ngs360_agent"
        )

    @computed_field
    @property
    def LANGSMITH_API_KEY(self) -> str | None:
        """LangSmith API key sent as the X-Api-Key header when calling the agent."""
        return self._get_config_value("LANGSMITH_API_KEY")

    # SQLAlchemy - Create db connection string
    @computed_field
    @property
    def SQLALCHEMY_DATABASE_URI(self) -> str:
        """Build database URI from env or secrets, defaults to sqlite://"""
        return self._get_config_value("SQLALCHEMY_DATABASE_URI", default="sqlite://")

    # ElasticSearch Configuration
    @computed_field
    @property
    def OPENSEARCH_HOST(self) -> str | None:
        """Get OpenSearch host from env or secrets"""
        return self._get_config_value("OPENSEARCH_HOST")

    @computed_field
    @property
    def OPENSEARCH_PORT(self) -> str | None:
        """Get OpenSearch post from env or secrets"""
        return self._get_config_value("OPENSEARCH_PORT")

    @computed_field
    @property
    def OPENSEARCH_USER(self) -> str | None:
        """Get OpenSearch user from env or secrets"""
        return self._get_config_value("OPENSEARCH_USER")

    @computed_field
    @property
    def OPENSEARCH_PASSWORD(self) -> str | None:
        """Get OpenSearch password from env or secrets"""
        # Note: Secret key is 'OPENSEARCH_PASS' not 'OPENSEARCH_PASSWORD'
        return self._get_config_value("OPENSEARCH_PASSWORD")

    @computed_field
    @property
    def OPENSEARCH_USE_SSL(self) -> bool:
        """Get OpenSearch use SSL flag from env or secrets"""
        value = self._get_config_value("OPENSEARCH_USE_SSL", default="true")
        return value.lower() in ("true", "1", "yes")

    @computed_field
    @property
    def OPENSEARCH_VERIFY_CERTS(self) -> bool:
        """Get OpenSearch certificate verification setting from env or secrets (defaults to False)"""
        value = self._get_config_value("OPENSEARCH_VERIFY_CERTS", default="false")
        return value.lower() in ("true", "1", "yes")

    # AWS Configuration
    @computed_field
    @property
    def AWS_ACCESS_KEY_ID(self) -> str | None:
        """Get AWS Access Key ID from env or secrets"""
        return self._get_config_value("AWS_ACCESS_KEY_ID")

    @computed_field
    @property
    def AWS_SECRET_ACCESS_KEY(self) -> str | None:
        """Get AWS Secret Access Key from env or secrets"""
        return self._get_config_value("AWS_SECRET_ACCESS_KEY")

    @computed_field
    @property
    def AWS_REGION(self) -> str:
        """Get AWS Region from env or secrets (defaults to us-east-1)"""
        return self._get_config_value("AWS_REGION", default="us-east-1")

    @computed_field
    @property
    def OMICS_REGISTER_WORKFLOW_LAMBDA(self) -> str | None:
        """Lambda function name that registers a workflow on AWS HealthOmics."""
        return self._get_config_value("OMICS_REGISTER_WORKFLOW_LAMBDA")

    @computed_field
    @property
    def OMICS_REGISTER_LAMBDA_READ_TIMEOUT(self) -> int:
        """Seconds to wait for the Omics registration Lambda to respond.

        Must exceed how long the Lambda actually takes. Giving up early does
        not cancel it -- it just discards the ARN of a workflow version AWS
        has already created. Registrations have been observed at 60-90s and
        scale with the size of the packed CWL, so the default leaves real
        headroom rather than sitting just above the observed maximum.
        """
        return int(
            self._get_config_value(
                "OMICS_REGISTER_LAMBDA_READ_TIMEOUT", default="300",
            )
        )

    # Options are from api.files.models.StorageBackend
    STORAGE_BACKEND: str = os.getenv("STORAGE_BACKEND", "s3")
    STORAGE_ROOT_PATH: str = os.getenv("STORAGE_URI", "s3://my-storage-bucket")

    # JWT Configuration
    @computed_field
    @property
    def JWT_SECRET_KEY(self) -> str:
        """
        Get JWT secret key from env or secrets.

        Outside the "dev" tier the key must be set explicitly and be at least
        JWT_SECRET_MIN_LENGTH characters; the insecure built-in default is
        refused so a misconfigured deployment cannot mint forgeable tokens.
        The secret value itself is never included in the error.
        """
        value = self._get_config_value(
            "JWT_SECRET_KEY",
            default=INSECURE_DEFAULT_JWT_SECRET
        )
        if self.ENVIRONMENT != "dev" and (
            value == INSECURE_DEFAULT_JWT_SECRET
            or len(value) < JWT_SECRET_MIN_LENGTH
        ):
            raise InsecureConfigurationError(
                "JWT_SECRET_KEY is unset, uses the insecure default, or is "
                f"shorter than {JWT_SECRET_MIN_LENGTH} characters "
                f"(ENVIRONMENT={self.ENVIRONMENT}). Set a strong random value, "
                "e.g. `openssl rand -hex 32`."
            )
        return value

    def validate_security(self) -> None:
        """Fail fast on insecure security-critical configuration."""
        # Accessing the property performs the validation.
        _ = self.JWT_SECRET_KEY

    @computed_field
    @property
    def JWT_ALGORITHM(self) -> str:
        """Get JWT algorithm from env or secrets"""
        return self._get_config_value("JWT_ALGORITHM", default="HS256")

    @computed_field
    @property
    def ACCESS_TOKEN_EXPIRE_MINUTES(self) -> int:
        """Get access token expiration in minutes"""
        value = self._get_config_value("ACCESS_TOKEN_EXPIRE_MINUTES", default="30")
        return int(value)

    @computed_field
    @property
    def REFRESH_TOKEN_EXPIRE_DAYS(self) -> int:
        """Get refresh token expiration in days"""
        value = self._get_config_value("REFRESH_TOKEN_EXPIRE_DAYS", default="30")
        return int(value)

    # Password Policy
    @computed_field
    @property
    def PASSWORD_MIN_LENGTH(self) -> int:
        """Get minimum password length"""
        value = self._get_config_value("PASSWORD_MIN_LENGTH", default="8")
        return int(value)

    @computed_field
    @property
    def PASSWORD_REQUIRE_UPPERCASE(self) -> bool:
        """Check if password requires uppercase"""
        value = self._get_config_value("PASSWORD_REQUIRE_UPPERCASE", default="true")
        return value.lower() in ("true", "1", "yes")

    @computed_field
    @property
    def PASSWORD_REQUIRE_LOWERCASE(self) -> bool:
        """Check if password requires lowercase"""
        value = self._get_config_value("PASSWORD_REQUIRE_LOWERCASE", default="true")
        return value.lower() in ("true", "1", "yes")

    @computed_field
    @property
    def PASSWORD_REQUIRE_DIGIT(self) -> bool:
        """Check if password requires digit"""
        value = self._get_config_value("PASSWORD_REQUIRE_DIGIT", default="true")
        return value.lower() in ("true", "1", "yes")

    @computed_field
    @property
    def PASSWORD_REQUIRE_SPECIAL(self) -> bool:
        """Check if password requires special character"""
        value = self._get_config_value("PASSWORD_REQUIRE_SPECIAL", default="false")
        return value.lower() in ("true", "1", "yes")

    # Account Lockout
    @computed_field
    @property
    def MAX_FAILED_LOGIN_ATTEMPTS(self) -> int:
        """Get max failed login attempts before lockout"""
        value = self._get_config_value("MAX_FAILED_LOGIN_ATTEMPTS", default="5")
        return int(value)

    @computed_field
    @property
    def ACCOUNT_LOCKOUT_DURATION_MINUTES(self) -> int:
        """Get account lockout duration in minutes"""
        value = self._get_config_value("ACCOUNT_LOCKOUT_DURATION_MINUTES", default="30")
        return int(value)

    # Email Configuration
    @computed_field
    @property
    def EMAIL_ENABLED(self) -> bool:
        """Check if email is enabled"""
        value = self._get_config_value("EMAIL_ENABLED", default="false")
        return value.lower() in ("true", "1", "yes")

    @computed_field
    @property
    def FROM_EMAIL(self) -> str:
        """Get from email address"""
        return self._get_config_value("FROM_EMAIL", default="noreply@example.com")

    @computed_field
    @property
    def FROM_NAME(self) -> str:
        """Get from name"""
        return self._get_config_value("FROM_NAME", default="NGS360")

    @computed_field
    @property
    def FRONTEND_URL(self) -> str:
        """Get frontend URL"""
        return self._get_config_value("FRONTEND_URL", default="http://localhost:3000")

    @computed_field
    @property
    def MAIL_SERVER(self) -> str | None:
        """Get mail server"""
        return self._get_config_value("MAIL_SERVER")

    @computed_field
    @property
    def MAIL_PORT(self) -> str | None:
        """Get mail server port"""
        return self._get_config_value("MAIL_PORT")

    @computed_field
    @property
    def MAIL_USERNAME(self) -> str | None:
        """Get mail username"""
        return self._get_config_value("MAIL_USERNAME")

    @computed_field
    @property
    def MAIL_PASSWORD(self) -> str | None:
        """Get mail password"""
        return self._get_config_value("MAIL_PASSWORD")

    @computed_field
    @property
    def MAIL_USE_TLS(self) -> bool:
        """Check if mail uses TLS"""
        value = self._get_config_value("MAIL_USE_TLS", default="false")
        return value.lower() in ("true", "1", "yes")

    @computed_field
    @property
    def MAIL_ADMINS(self) -> str | None:
        """Get mail admins"""
        return self._get_config_value("MAIL_ADMINS")

    # OAuth2 Configuration
    @computed_field
    @property
    def OAUTH_GOOGLE_CLIENT_ID(self) -> str | None:
        """Get Google OAuth client ID"""
        return self._get_config_value("OAUTH_GOOGLE_CLIENT_ID")

    @computed_field
    @property
    def OAUTH_GOOGLE_CLIENT_SECRET(self) -> str | None:
        """Get Google OAuth client secret"""
        return self._get_config_value("OAUTH_GOOGLE_CLIENT_SECRET")

    @computed_field
    @property
    def OAUTH_GITHUB_CLIENT_ID(self) -> str | None:
        """Get GitHub OAuth client ID"""
        return self._get_config_value("OAUTH_GITHUB_CLIENT_ID")

    @computed_field
    @property
    def OAUTH_GITHUB_CLIENT_SECRET(self) -> str | None:
        """Get GitHub OAuth client secret"""
        return self._get_config_value("OAUTH_GITHUB_CLIENT_SECRET")

    @computed_field
    @property
    def OAUTH_MICROSOFT_CLIENT_ID(self) -> str | None:
        """Get Microsoft OAuth client ID"""
        return self._get_config_value("OAUTH_MICROSOFT_CLIENT_ID")

    @computed_field
    @property
    def OAUTH_MICROSOFT_CLIENT_SECRET(self) -> str | None:
        """Get Microsoft OAuth client secret"""
        return self._get_config_value("OAUTH_MICROSOFT_CLIENT_SECRET")

    # For Oauth2 Corporate SSO
    @computed_field
    @property
    def OAUTH_CORP_NAME(self) -> str | None:
        return self._get_config_value("OAUTH_CORP_NAME")

    @computed_field
    @property
    def OAUTH_CORP_DISPLAY_NAME(self) -> str | None:
        return self._get_config_value("OAUTH_CORP_DISPLAY_NAME", default=self.OAUTH_CORP_NAME)

    @computed_field
    @property
    def OAUTH_CORP_CLIENT_ID(self) -> str | None:
        """Get Corporate OAuth client ID"""
        return self._get_config_value("OAUTH_CORP_CLIENT_ID")

    @computed_field
    @property
    def OAUTH_CORP_CLIENT_SECRET(self) -> str | None:
        """Get Corporate OAuth client secret"""
        return self._get_config_value("OAUTH_CORP_CLIENT_SECRET")

    @computed_field
    @property
    def OAUTH_CORP_AUTHORIZE_URL(self) -> str | None:
        """Get Corporate OAuth authorization URL"""
        return self._get_config_value("OAUTH_CORP_AUTHORIZE_URL")

    @computed_field
    @property
    def OAUTH_CORP_TOKEN_URL(self) -> str | None:
        """Get Corporate OAuth token URL"""
        return self._get_config_value("OAUTH_CORP_TOKEN_URL")

    @computed_field
    @property
    def OAUTH_CORP_USERINFO_URL(self) -> str | None:
        """Get Corporate OAuth userinfo URL"""
        return self._get_config_value("OAUTH_CORP_USERINFO_URL")

    @computed_field
    @property
    def OAUTH_CORP_SCOPES(self) -> str | None:
        """Get Corporate OAuth scopes (comma-separated)"""
        return self._get_config_value("OAUTH_CORP_SCOPES", default="openid,email,profile")

    # LDAP Configuration
    @computed_field
    @property
    def LDAP_ENABLED(self) -> bool:
        """Check if LDAP is enabled for user search"""
        value = self._get_config_value("LDAP_ENABLED", default="false")
        return value.lower() in ("true", "1", "yes")

    @computed_field
    @property
    def LDAP_SERVER(self) -> str | None:
        """LDAP server URL (e.g., ldap://ldap.example.com or ldaps://ldap.example.com)"""
        return self._get_config_value("LDAP_SERVER")

    @computed_field
    @property
    def LDAP_PORT(self) -> int:
        """LDAP server port (389 for LDAP, 636 for LDAPS)"""
        value = self._get_config_value("LDAP_PORT", default="389")
        return int(value)

    @computed_field
    @property
    def LDAP_USE_SSL(self) -> bool:
        """Whether to use SSL/TLS for LDAP connection"""
        value = self._get_config_value("LDAP_USE_SSL", default="false")
        return value.lower() in ("true", "1", "yes")

    @computed_field
    @property
    def LDAP_BIND_DN(self) -> str | None:
        """Distinguished Name for LDAP bind (service account)"""
        return self._get_config_value("LDAP_BIND_DN")

    @computed_field
    @property
    def LDAP_BIND_PASSWORD(self) -> str | None:
        """Password for LDAP bind"""
        return self._get_config_value("LDAP_BIND_PASSWORD")

    @computed_field
    @property
    def LDAP_BASE_DN(self) -> str | None:
        """Base DN for user search (e.g., ou=People,dc=example,dc=com)"""
        return self._get_config_value("LDAP_BASE_DN")

    @computed_field
    @property
    def LDAP_USER_SEARCH_FILTER(self) -> str:
        """LDAP search filter template. Use {query} as placeholder.
        Default searches cn, mail, and uid."""
        return self._get_config_value(
            "LDAP_USER_SEARCH_FILTER",
            default="(|(cn=*{query}*)(mail=*{query}*)(uid=*{query}*))"
        )

    @computed_field
    @property
    def LDAP_USER_ATTRIBUTES(self) -> str:
        """Comma-separated LDAP attributes to retrieve"""
        return self._get_config_value(
            "LDAP_USER_ATTRIBUTES",
            default="cn,mail,uid,displayName,department,title"
        )

    @computed_field
    @property
    def LDAP_TIMEOUT(self) -> int:
        """LDAP connection/search timeout in seconds"""
        value = self._get_config_value("LDAP_TIMEOUT", default="10")
        return int(value)

    # Read environment variables from .env file, if it exists
    # extra='ignore' prevents validation errors from extra env vars
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )


# Export settings
@lru_cache
def get_settings() -> Settings:
    """
    Get settings instance, cached for performance
    """
    return Settings()


if __name__ == "__main__":
    # To use in other modules
    # from core.config import get_settings
    print(get_settings().SQLALCHEMY_DATABASE_URI)
