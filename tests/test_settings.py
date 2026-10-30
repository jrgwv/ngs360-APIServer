'''Test cases for settings.py'''
from unittest.mock import patch, MagicMock
import json
from core.config import get_secret, Settings
from botocore.exceptions import ClientError


def test_get_secret_does_not_exist():
    ''' Get that secret does not exist '''
    with patch('boto3.session.Session') as mock_session:
        error_response = {
            'Error': {
                'Code': 'NoSuchKey',
                'Message': 'The specified key does not exist.'
            },
            'ResponseMetadata': {'HTTPStatusCode': 404}
        }
        operation_name = 'GetSecretValue'

        mock_client = MagicMock()
        mock_client.get_secret_value.side_effect = ClientError(error_response, operation_name)
        mock_session.return_value.client.return_value = mock_client
        secret_arn = "My_test_secret"
        region_name = "us-east-1"
        secret = get_secret(secret_arn, region_name)
        assert secret is None


def test_get_secret_exists():
    ''' Get that secret exists '''
    mock_response = {
        'SecretString': '{"SQLALCHEMY_DATABASE_URI": "mysql+pymysql://user:pass@host:3306/db"}'
    }

    with patch('boto3.session.Session') as mock_session:
        mock_client = MagicMock()
        mock_client.get_secret_value.return_value = mock_response
        mock_session.return_value.client.return_value = mock_client

        secret_arn = "test-secret-arn"  # Use a fake ARN for tests
        region_name = "us-east-1"
        secret = get_secret(secret_arn, region_name)

        assert secret is not None
        assert "SQLALCHEMY_DATABASE_URI" in secret


def test_get_config_value_from_env():
    ''' Test retrieving config value from environment variable '''
    settings = Settings()

    with patch.dict('os.environ', {'TEST_ENV_VAR': 'env_value'}):
        value = settings._get_config_value(
            env_var_name='TEST_ENV_VAR',
            default='default_value')
        assert value == 'env_value'


def test_get_config_value_from_secrets():
    ''' Test retrieving config value from AWS Secrets Manager '''
    mock_secret = {
        'TEST_ENV_VAR': 'secret_value'
    }
    with patch('boto3.session.Session') as mock_session:
        mock_client = MagicMock()
        mock_client.get_secret_value.return_value = {
            'SecretString': json.dumps(mock_secret)
        }
        mock_session.return_value.client.return_value = mock_client
        with patch.dict(
            'os.environ',
            {'ENV_SECRETS': 'arn:aws:secretsmanager:us-east-1:123456789012:secret:mysecret'}
        ):
            settings = Settings()
            value = settings._get_config_value(
                env_var_name='TEST_ENV_VAR')
            assert value == 'secret_value'


def test_get_config_value_from_default():
    ''' Test retrieving config value and getting default when not in env or secrets '''
    settings = Settings()

    value = settings._get_config_value(
        env_var_name='TEST_ENV_VAR',
        default='default_value')
    assert value == 'default_value'


class TestJwtSecretValidation:
    """Non-dev tiers must refuse a default or weak JWT secret (F02)."""

    def test_default_secret_allowed_in_dev(self, monkeypatch):
        from core.config import INSECURE_DEFAULT_JWT_SECRET
        monkeypatch.setenv("ENVIRONMENT", "dev")
        monkeypatch.delenv("JWT_SECRET_KEY", raising=False)
        monkeypatch.delenv("ENV_SECRETS", raising=False)
        assert Settings().JWT_SECRET_KEY == INSECURE_DEFAULT_JWT_SECRET

    def test_default_secret_refused_outside_dev(self, monkeypatch):
        import pytest
        from core.config import InsecureConfigurationError
        monkeypatch.delenv("JWT_SECRET_KEY", raising=False)
        monkeypatch.delenv("ENV_SECRETS", raising=False)
        for tier in ("staging", "prod"):
            monkeypatch.setenv("ENVIRONMENT", tier)
            with pytest.raises(InsecureConfigurationError):
                Settings().validate_security()

    def test_short_secret_refused_outside_dev(self, monkeypatch):
        import pytest
        from core.config import InsecureConfigurationError
        monkeypatch.setenv("ENVIRONMENT", "prod")
        monkeypatch.setenv("JWT_SECRET_KEY", "too-short-secret")
        with pytest.raises(InsecureConfigurationError) as exc:
            Settings().validate_security()
        assert "too-short-secret" not in str(exc.value)

    def test_strong_secret_accepted_outside_dev(self, monkeypatch):
        strong = "x" * 32
        monkeypatch.setenv("ENVIRONMENT", "prod")
        monkeypatch.setenv("JWT_SECRET_KEY", strong)
        Settings().validate_security()
        assert Settings().JWT_SECRET_KEY == strong
