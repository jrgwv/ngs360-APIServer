import os
from contextlib import ExitStack, contextmanager

import pytest

from fastapi.testclient import TestClient
from sqlmodel import Session, create_engine, select, SQLModel
from sqlmodel.pool import StaticPool

from core.config import get_settings
from core.deps import get_db, get_opensearch_client, get_s3_client
from main import app

# Strong, test-only JWT signing key. Non-dev tiers refuse the insecure default
# (see Settings.JWT_SECRET_KEY), and several tests run with ENVIRONMENT=staging
# or prod, so provide one (read lazily per access). Never a real secret.
os.environ.setdefault(
    "JWT_SECRET_KEY", "test-only-jwt-secret-key-0123456789abcdef"
)


class MockOpenSearchClient:
    """Mock OpenSearch client for testing"""

    def __init__(self):
        self.documents = {}  # Store documents by index
        self.indices_data = {}  # Store index metadata

    def index(self, index: str, id: str, body: dict):
        """Mock index operation"""
        if index not in self.documents:
            self.documents[index] = {}
        self.documents[index][id] = body
        return {"_id": id, "_index": index, "result": "created"}

    def delete(self, index: str, id: str, ignore=None):
        """Mock delete document operation"""
        ignore = ignore or []
        if index in self.documents and id in self.documents[index]:
            del self.documents[index][id]
            return {"_id": id, "_index": index, "result": "deleted"}
        if 404 not in ignore:
            raise Exception(f"Document {id} not found in index {index}")
        return {"_id": id, "_index": index, "result": "not_found"}

    def search(self, index: str, body: dict):
        """Mock search operation"""
        if index not in self.documents:
            return {"hits": {"total": {"value": 0}, "hits": []}}

        # Extract search query
        query_info = body.get("query", {})
        search_term = ""

        if "query_string" in query_info:
            search_term = query_info["query_string"].get("query", "").lower()
        elif "match_all" in query_info:
            search_term = ""  # Match all documents

        # Parse wildcard queries like (*AI*)
        def parse_wildcard_query(query_term):
            """Convert OpenSearch wildcard query to simple substring search"""
            # Remove parentheses and convert (*term*) to just term
            if query_term.startswith("(*") and query_term.endswith("*)"):
                return query_term[2:-2]  # Remove (*..*)
            elif query_term.startswith("*") and query_term.endswith("*"):
                return query_term[1:-1]  # Remove *...*
            return query_term

        # Handle AND queries by splitting on " AND "
        def matches_query(text, query_term):
            """Check if text matches the query term (handling wildcards and AND)"""
            if " AND " in query_term:
                # Split on AND and check all terms match
                terms = [
                    parse_wildcard_query(term.strip())
                    for term in query_term.split(" AND ")
                ]
                return all(term in text.lower() for term in terms if term)
            else:
                # Single term
                parsed_term = parse_wildcard_query(query_term)
                return parsed_term in text.lower()

        # Filter documents based on search term
        hits = []
        for doc_id, doc_body in self.documents[index].items():
            should_include = False

            if not search_term:  # Empty search or match_all
                should_include = True
            else:
                # Search across ALL fields in the document (since they are already __searchable__)
                for field_name, field_value in doc_body.items():
                    if field_value and matches_query(str(field_value), search_term):
                        should_include = True
                        break

            if should_include:
                hits.append({"_id": doc_id, "_source": doc_body, "_score": 1.0})

        # Apply sorting if specified
        sort_config = body.get("sort", [])
        if sort_config:
            for sort_item in sort_config:
                if isinstance(sort_item, dict):
                    for field, sort_order in sort_item.items():
                        order = (
                            sort_order.get("order", "asc")
                            if isinstance(sort_order, dict)
                            else "asc"
                        )
                        reverse = order == "desc"

                        # Sort by the specified field
                        def get_sort_key(hit):
                            source = hit.get("_source", {})
                            # Remove .keyword suffix if present for compatibility with API
                            base_field = field.split(".")[0] if "." in field else field
                            value = source.get(base_field, "")
                            # Convert to string for consistent sorting
                            return str(value).lower() if value is not None else ""

                        hits.sort(key=get_sort_key, reverse=reverse)
                        break  # Only apply first sort for simplicity
                    break

        # Apply pagination
        from_param = body.get("from", 0)
        size_param = body.get("size", 10)
        paginated_hits = hits[from_param:from_param + size_param]

        return {"hits": {"total": {"value": len(hits)}, "hits": paginated_hits}}

    @property
    def indices(self):
        """Mock indices property"""
        return MockIndices(self)


class MockIndices:
    """Mock indices operations"""

    def __init__(self, client):
        self.client = client

    def exists(self, index: str):
        """Mock index exists check"""
        return index in self.client.indices_data

    def create(self, index: str, body=None):
        """Mock index creation"""
        self.client.indices_data[index] = body or {}
        if index not in self.client.documents:
            self.client.documents[index] = {}
        return {"acknowledged": True}

    def refresh(self, index: str):
        """Mock index refresh"""
        return {"_shards": {"total": 1, "successful": 1, "failed": 0}}

    def delete(self, index: str, ignore=None):
        """Mock index deletion"""
        ignore = ignore or []
        if index in self.client.documents:
            del self.client.documents[index]
        if index in self.client.indices_data:
            del self.client.indices_data[index]
        return {"acknowledged": True}


class MockS3Paginator:
    """Mock S3 paginator for list_objects_v2"""

    def __init__(self, client, bucket: str, prefix: str, delimiter: str):
        self.client = client
        self.bucket = bucket
        self.prefix = prefix
        self.delimiter = delimiter

    def paginate(self, **kwargs):
        """Return mock page iterator"""
        # Check if client is in error mode
        if self.client.error_mode:
            error_type = self.client.error_mode
            if error_type == "NoSuchBucket":
                from botocore.exceptions import ClientError

                error_response = {
                    "Error": {
                        "Code": "NoSuchBucket",
                        "Message": "The specified bucket does not exist",
                    }
                }
                raise ClientError(error_response, "ListObjectsV2")
            elif error_type == "AccessDenied":
                from botocore.exceptions import ClientError

                raise ClientError(
                    {"Error": {"Code": "AccessDenied", "Message": "Access Denied"}},
                    "ListObjectsV2",
                )
            elif error_type == "NoCredentialsError":
                from botocore.exceptions import NoCredentialsError

                raise NoCredentialsError()

        # Get bucket data
        bucket_data = self.client.buckets.get(self.bucket, {})

        # If delimiter is provided, return hierarchical listing (folders + files at this level)
        if self.delimiter:
            prefix_data = bucket_data.get(self.prefix, {"files": [], "folders": []})

            # Build response page
            page = {}

            # Add CommonPrefixes (folders)
            if prefix_data["folders"]:
                page["CommonPrefixes"] = [
                    {"Prefix": folder} for folder in prefix_data["folders"]
                ]

            # Add Contents (files)
            if prefix_data["files"]:
                page["Contents"] = prefix_data["files"]

            # Return single page (simplified for testing)
            yield page
        else:
            # No delimiter means recursive listing - return ALL files under prefix
            all_files = []
            for prefix_key, data in bucket_data.items():
                if prefix_key.startswith(self.prefix):
                    all_files.extend(data.get("files", []))

            # Build response page with all files
            page = {}
            if all_files:
                page["Contents"] = all_files

            yield page


class MockS3Client:
    """Mock S3 client for testing"""

    def __init__(self):
        self.buckets = (
            {}
        )  # Store bucket data: {bucket_name: {prefix: {"files": [], "folders": []}}}
        self.uploaded_files = {}  # Track uploaded files: {bucket: {key: body}}
        self.error_mode = None  # For simulating errors

    def setup_bucket(self, bucket: str, prefix: str, files: list, folders: list):
        """
        Setup mock data for a bucket/prefix

        Args:
            bucket: S3 bucket name
            prefix: S3 prefix/path
            files: List of file dicts with Keys, LastModified, Size
            folders: List of folder prefixes (strings ending with /)
        """
        if bucket not in self.buckets:
            self.buckets[bucket] = {}

        self.buckets[bucket][prefix] = {"files": files, "folders": folders}

    def get_paginator(self, operation: str):
        """Return a mock paginator"""
        if operation == "list_objects_v2":
            # Return a factory function that creates paginator with params
            def create_paginator(Bucket: str, Prefix: str, Delimiter: str):
                return MockS3Paginator(self, Bucket, Prefix, Delimiter)

            # Return object with paginate method
            class PaginatorFactory:
                def __init__(self, client):
                    self.client = client

                def paginate(self, Bucket: str, Prefix: str, Delimiter: str = None):
                    paginator = MockS3Paginator(self.client, Bucket, Prefix, Delimiter)
                    return paginator.paginate()

            return PaginatorFactory(self)

        raise NotImplementedError(f"Paginator for {operation} not implemented")

    def simulate_error(self, error_type: str):
        """
        Configure client to raise specific errors

        Args:
            error_type: One of "NoSuchBucket", "AccessDenied", "NoCredentialsError"
        """
        self.error_mode = error_type

    def get_object(self, Bucket: str, Key: str, **kwargs):
        """Mock S3 get_object operation"""
        from botocore.exceptions import NoCredentialsError, ClientError

        # Check for simulated errors
        if self.error_mode == "NoCredentialsError":
            raise NoCredentialsError()
        elif self.error_mode == "NoSuchBucket":
            error_response = {
                "Error": {
                    "Code": "NoSuchBucket",
                    "Message": "The specified bucket does not exist",
                }
            }
            raise ClientError(error_response, "GetObject")
        elif self.error_mode == "AccessDenied":
            error_response = {
                "Error": {"Code": "AccessDenied", "Message": "Access Denied"}
            }
            raise ClientError(error_response, "GetObject")

        # Check if file exists in uploaded files
        if Bucket in self.uploaded_files and Key in self.uploaded_files[Bucket]:
            body = self.uploaded_files[Bucket][Key]

            # Create a mock response with Body attribute and read() method
            class MockBody:
                def __init__(self, content):
                    self.content = content

                def read(self):
                    return self.content

                def decode(self, encoding='utf-8'):
                    if isinstance(self.content, bytes):
                        return self.content.decode(encoding)
                    return self.content

            return {
                "Body": MockBody(body),
                "ContentType": "application/octet-stream",
                "ContentLength": len(body) if body else 0,
            }

        # File not found
        error_response = {
            "Error": {
                "Code": "NoSuchKey",
                "Message": "The specified key does not exist.",
            }
        }
        raise ClientError(error_response, "GetObject")

    def put_object(self, Bucket: str, Key: str, Body: bytes, **kwargs):
        """Mock S3 put_object operation"""
        from botocore.exceptions import NoCredentialsError, ClientError

        # Check for simulated errors
        if self.error_mode == "NoCredentialsError":
            raise NoCredentialsError()
        elif self.error_mode == "NoSuchBucket":
            error_response = {
                "Error": {
                    "Code": "NoSuchBucket",
                    "Message": "The specified bucket does not exist",
                }
            }
            raise ClientError(error_response, "PutObject")
        elif self.error_mode == "AccessDenied":
            error_response = {
                "Error": {"Code": "AccessDenied", "Message": "Access Denied"}
            }
            raise ClientError(error_response, "PutObject")

        # Store the uploaded file
        if Bucket not in self.uploaded_files:
            self.uploaded_files[Bucket] = {}
        self.uploaded_files[Bucket][Key] = Body

        return {"ETag": '"mock-etag"', "VersionId": "mock-version-id"}

    def generate_presigned_url(
        self, ClientMethod: str, Params: dict = None, ExpiresIn: int = 3600
    ):
        """Mock S3 generate_presigned_url operation"""
        from botocore.exceptions import NoCredentialsError, ClientError

        # Check for simulated errors
        if self.error_mode == "NoCredentialsError":
            raise NoCredentialsError()
        elif self.error_mode == "NoSuchBucket":
            error_response = {
                "Error": {
                    "Code": "NoSuchBucket",
                    "Message": "The specified bucket does not exist",
                }
            }
            raise ClientError(error_response, "GeneratePresignedUrl")
        elif self.error_mode == "AccessDenied":
            error_response = {
                "Error": {"Code": "AccessDenied", "Message": "Access Denied"}
            }
            raise ClientError(error_response, "GeneratePresignedUrl")

        Params = Params or {}
        bucket = Params.get("Bucket", "mock-bucket")
        key = Params.get("Key", "mock-key")
        return (
            f"https://{bucket}.s3.amazonaws.com/{key}"
            f"?X-Amz-Expires={ExpiresIn}&X-Amz-Signature=mock-signature"
        )

    def head_object(self, Bucket: str, Key: str, **kwargs):
        """Mock S3 head_object operation - check if object exists"""
        from botocore.exceptions import NoCredentialsError, ClientError

        # Check for simulated errors
        if self.error_mode == "NoCredentialsError":
            raise NoCredentialsError()
        elif self.error_mode == "NoSuchBucket":
            error_response = {
                "Error": {
                    "Code": "NoSuchBucket",
                    "Message": "The specified bucket does not exist",
                }
            }
            raise ClientError(error_response, "HeadObject")
        elif self.error_mode == "AccessDenied":
            error_response = {
                "Error": {"Code": "AccessDenied", "Message": "Access Denied"}
            }
            raise ClientError(error_response, "HeadObject")

        # Check if file exists in uploaded files
        if Bucket in self.uploaded_files and Key in self.uploaded_files[Bucket]:
            body = self.uploaded_files[Bucket][Key]
            return {
                "ContentType": "application/octet-stream",
                "ContentLength": len(body) if body else 0,
                "ETag": '"mock-etag"',
            }

        # File not found - return 404
        error_response = {
            "Error": {
                "Code": "404",
                "Message": "Not Found",
            }
        }
        raise ClientError(error_response, "HeadObject")


class MockLambdaPayload:
    """Mock Lambda response payload"""

    def __init__(self, content: bytes):
        self.content = content

    def read(self) -> bytes:
        return self.content


class MockLambdaClient:
    """Mock Lambda client for testing"""

    def __init__(self):
        self.response_data = {}  # The response to return
        self.error_mode = None  # For simulating errors
        self.invocations = []  # Track invocations
        self.client_kwargs = {}  # kwargs boto3.client() was called with

    def set_response(self, response: dict):
        """Set the response that will be returned by invoke()"""
        self.response_data = response

    def simulate_error(self, error_type: str):
        """
        Configure client to raise specific errors

        Args:
            error_type: One of "ResourceNotFoundException", "AccessDeniedException",
                        "NoCredentialsError", "ReadTimeoutError"
        """
        self.error_mode = error_type

    def invoke(self, FunctionName: str, InvocationType: str, Payload: str):
        """Mock Lambda invoke operation"""
        import json
        from botocore.exceptions import NoCredentialsError, ClientError

        # Track the invocation
        self.invocations.append({
            "FunctionName": FunctionName,
            "InvocationType": InvocationType,
            "Payload": json.loads(Payload)
        })

        # Check for simulated errors
        if self.error_mode == "NoCredentialsError":
            raise NoCredentialsError()
        elif self.error_mode == "ReadTimeoutError":
            # What a Lambda that outruns the client's read_timeout looks like.
            # The Lambda keeps running regardless, so the invocation above is
            # still recorded -- that is the point of the failure mode.
            from botocore.exceptions import ReadTimeoutError

            raise ReadTimeoutError(endpoint_url="https://lambda.us-east-1.amazonaws.com")
        elif self.error_mode == "ResourceNotFoundException":
            error_response = {
                "Error": {
                    "Code": "ResourceNotFoundException",
                    "Message": f"Function not found: {FunctionName}",
                }
            }
            raise ClientError(error_response, "Invoke")
        elif self.error_mode == "AccessDeniedException":
            error_response = {
                "Error": {
                    "Code": "AccessDeniedException",
                    "Message": "Access Denied"
                }
            }
            raise ClientError(error_response, "Invoke")

        # Return the configured response
        response_json = json.dumps(self.response_data).encode("utf-8")
        return {
            "StatusCode": 200,
            "Payload": MockLambdaPayload(response_json)
        }


@pytest.fixture(name="mock_lambda_client")
def mock_lambda_client_fixture():
    """Provide a mock Lambda client for testing"""
    return MockLambdaClient()


@pytest.fixture(name="test_project")
def test_project_fixture(session):
    """Provide a test project instance"""
    from api.project.models import Project

    project = Project(
        project_id="P-19900109-0001",
        name="Test Project",
        created_by="testuser"
    )
    session.add(project)
    session.commit()
    session.refresh(project)
    return project


@pytest.fixture(scope="session", autouse=True)
def isolate_test_environment():
    """Isolate tests from production environment variables"""
    # Clear the lru_cache for settings
    get_settings.cache_clear()

    # Store original env vars
    original_env = os.environ.copy()

    # Set test-specific environment variables
    os.environ["LDAP_ENABLED"] = "false"
    os.environ["SQLALCHEMY_DATABASE_URI"] = "sqlite://"  # In-memory DB
    os.environ["OPENSEARCH_HOST"] = "localhost"
    os.environ["OPENSEARCH_PORT"] = "9200"
    os.environ["DATA_BUCKET_URI"] = "s3://test-data-bucket"
    os.environ["RESULTS_BUCKET_URI"] = "s3://test-results-bucket"
    os.environ["DEMUX_WORKFLOW_CONFIGS_BUCKET_URI"] = "s3://test-tool-configs-bucket"

    # Tests run under full enforcement, never the deployed default of dry_run,
    # so a guard cannot pass merely because the suite was running in a mode that
    # lets every refusal through. Tests that care about a particular mode set it
    # themselves via the `mode` fixture.
    os.environ["RBAC_MODE"] = "enforce"

    # Remove AWS credentials to prevent real AWS calls
    os.environ.pop("AWS_ACCESS_KEY_ID", None)
    os.environ.pop("AWS_SECRET_ACCESS_KEY", None)
    os.environ.pop("ENV_SECRETS", None)  # Prevent Secrets Manager lookup

    yield

    # Restore original environment
    os.environ.clear()
    os.environ.update(original_env)
    get_settings.cache_clear()


@pytest.fixture(autouse=True)
def reset_settings_cache():
    """Clear settings cache before each test"""
    get_settings.cache_clear()
    yield
    get_settings.cache_clear()


@pytest.fixture(name="session")
def session_fixture():
    """Provide a fresh database session for each test"""
    engine = create_engine(
        "sqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
        pool_pre_ping=True
    )
    connection = engine.connect()
    SQLModel.metadata.create_all(bind=connection)

    session = Session(bind=connection, expire_on_commit=False)

    # Seed test settings
    from api.settings.models import Setting
    test_settings = [
        Setting(
            key="DATA_BUCKET_URI",
            value="s3://test-data-bucket",
            name="Data Bucket URI",
            description="Test data bucket"
        ),
        Setting(
            key="RESULTS_BUCKET_URI",
            value="s3://test-results-bucket",
            name="Results Bucket URI",
            description="Test results bucket"
        ),
        Setting(
            key="DEMUX_WORKFLOW_CONFIGS_BUCKET_URI",
            value="s3://test-tool-configs-bucket",
            name="Demux Workflow Configs Bucket URI",
            description="Test demux workflow configs bucket"
        ),
        Setting(
            key="MANIFEST_VALIDATION_LAMBDA",
            value="test-manifest-validation-lambda",
            name="Manifest Validation Lambda",
            description="Test Lambda function for manifest validation"
        ),
    ]
    for setting in test_settings:
        session.add(setting)
    session.commit()

    yield session

    # Cleanup: properly close session, connection, and dispose engine
    try:
        session.rollback()
    except Exception:
        pass
    finally:
        session.close()
        SQLModel.metadata.drop_all(bind=connection)
        connection.close()
        engine.dispose()


@pytest.fixture(name="mock_opensearch_client")
def mock_opensearch_client_fixture():
    """Provide a mock OpenSearch client for testing"""
    return MockOpenSearchClient()


@pytest.fixture(name="mock_s3_client")
def mock_s3_client_fixture():
    """Provide a mock S3 client for testing"""
    return MockS3Client()


# Permissions an authenticated non-superuser could NOT reach before RBAC, either
# because a CurrentSuperuser check guarded the route or because the route did not
# exist yet:
#
#   file:update, file:delete        api/files/routes.py -- CurrentSuperuser
#   sample:delete                   delete_sample_from_project -- CurrentSuperuser
#   setting:update                  api/settings/routes.py, now setting:update
#   project:manage_members          the membership endpoints, now the permission
#   role:manage, role:read          all of api/rbac/routes.py, now the permission
#   user:manage                     PATCH /users/{username}, a new route
#
# The last four no longer carry a CurrentSuperuser dependency -- require_permission
# is the whole guard. They stay on this list because the point of the list is what
# a *pre-RBAC* caller could do, and the answer is still "not this".
#
# Everything else in the catalog was reachable by any authenticated caller, and
# most of it by an anonymous one. Keep this list in step with the routes: when a
# route moves onto require_permission in a later phase, whether its permission
# belongs here is the question that decides if the change is breaking.
LEGACY_SUPERUSER_ONLY = frozenset({
    "file:update", "file:delete", "setting:update", "sample:delete",
    "project:manage_members", "role:manage", "role:read", "user:manage",
})

LEGACY_ROLE_NAME = "legacy_authenticated"


def legacy_permissions() -> list[str]:
    """
    What the pre-RBAC API allowed an authenticated user to do.

    The default `client` fixture holds exactly this, which does two jobs. It
    keeps ~32 existing test modules passing unchanged as routes gain guards --
    they assert the old behaviour, and the old behaviour is what this grants --
    and it makes that behaviour executable rather than described, so tightening
    it later shows up as a specific failing test instead of a silent change.
    """
    from api.rbac.permissions import ALL_PERMISSIONS

    return sorted(
        str(p) for p in ALL_PERMISSIONS if str(p) not in LEGACY_SUPERUSER_ONLY
    )


def persist_user(session: Session, username: str, *, superuser: bool = False):
    """
    Create the fixture user as a real row, and return it.

    This is the fix for the bug that would otherwise break every guarded route:
    the old fixtures built `User(...)` fresh inside the dependency override, so
    `user.id` was a new uuid4 on every request and matched no row in the
    database. Grants are looked up by user id, so every permission check would
    resolve to the empty set and 403 under enforce -- regardless of what the
    test had granted.
    """
    from api.auth.models import User

    user = session.exec(select(User).where(User.username == username)).first()
    if user is None:
        user = User(
            username=username,
            email=f"{username}@example.com",
            is_active=True,
            is_verified=True,
            is_superuser=superuser,
        )
        session.add(user)
        session.commit()
        session.refresh(user)
    return user


def _grant_legacy_role(session: Session, user) -> None:
    """Give `user` the pre-RBAC permission set, creating the role if needed."""
    from api.rbac.models import GrantSource, Role, RolePermission, UserRole
    from api.rbac.roles import RoleScope
    from api.rbac.seed import sync_rbac_catalog

    # The builtin catalog has to exist first: the project role rows are what
    # project membership in tests points at.
    sync_rbac_catalog(session)

    role = session.exec(select(Role).where(Role.name == LEGACY_ROLE_NAME)).first()
    if role is None:
        role = Role(
            name=LEGACY_ROLE_NAME,
            display_name="Legacy authenticated user",
            description="What an authenticated caller could do before RBAC",
            scope=RoleScope.GLOBAL,
            is_builtin=False,
        )
        session.add(role)
        session.flush()
        for permission in legacy_permissions():
            session.add(RolePermission(role_id=role.id, permission=permission))
        session.commit()

    held = session.exec(
        select(UserRole).where(UserRole.user_id == user.id,
                               UserRole.role_id == role.id)
    ).first()
    if held is None:
        session.add(UserRole(user_id=user.id, role_id=role.id,
                             source=GrantSource.MANUAL))
        session.commit()


@contextmanager
def _make_client(
    session: Session,
    mock_opensearch_client: MockOpenSearchClient,
    mock_s3_client: MockS3Client,
    mock_lambda_client: MockLambdaClient,
    monkeypatch,
    user=None,
):
    """
    Shared construction for every client fixture.

    The three fixtures below differed only in which user the auth override
    returned; everything else -- the database, OpenSearch, S3 and Lambda
    overrides -- was copied three times, so a change to any of it had to be
    made in triplicate or the fixtures would quietly diverge.

    `user=None` means no auth override at all, i.e. real authentication.
    """
    import boto3

    original_boto3_client = boto3.client

    def mock_boto3_client(service_name, **kwargs):
        if service_name == "lambda":
            # Recorded so tests can assert on the client's timeout/retry
            # config, which is part of the contract for slow invocations.
            mock_lambda_client.client_kwargs = kwargs
            return mock_lambda_client
        return original_boto3_client(service_name, **kwargs)

    monkeypatch.setattr(boto3, "client", mock_boto3_client)

    app.dependency_overrides[get_db] = lambda: session
    app.dependency_overrides[get_opensearch_client] = lambda: mock_opensearch_client
    app.dependency_overrides[get_s3_client] = lambda: mock_s3_client

    if user is not None:
        from api.auth.deps import get_current_user, optional_current_user

        app.dependency_overrides[get_current_user] = lambda: user
        # optional_current_user is not built on get_current_user -- it parses the
        # token itself and returns None on any failure -- so overriding only
        # get_current_user leaves every OptionalUser route seeing an anonymous
        # caller. Tests of authenticated behaviour on those routes would then
        # pass or fail for the wrong reason.
        app.dependency_overrides[optional_current_user] = lambda: user

    try:
        yield TestClient(app)
    finally:
        app.dependency_overrides.clear()


@pytest.fixture(name="unauthenticated_client")
def unauthenticated_client_fixture(
    session: Session,
    mock_opensearch_client: MockOpenSearchClient,
    mock_s3_client: MockS3Client,
    mock_lambda_client: MockLambdaClient,
    monkeypatch,
):
    """Client that requires real authentication (no auth override)"""
    with _make_client(session, mock_opensearch_client, mock_s3_client,
                      mock_lambda_client, monkeypatch) as client:
        yield client


@pytest.fixture(name="client")
def client_fixture(
    session: Session,
    mock_opensearch_client: MockOpenSearchClient,
    mock_s3_client: MockS3Client,
    mock_lambda_client: MockLambdaClient,
    monkeypatch,
):
    """
    An ordinary authenticated user, holding the pre-RBAC permission set.

    Persisted, and granted `legacy_authenticated`, so tests written against the
    old behaviour keep asserting the old behaviour once routes carry guards.
    """
    user = persist_user(session, "testuser")
    _grant_legacy_role(session, user)
    with _make_client(session, mock_opensearch_client, mock_s3_client,
                      mock_lambda_client, monkeypatch, user=user) as client:
        yield client


@pytest.fixture(name="auth_headers")
def auth_headers_fixture():
    """Provide authentication headers with a valid token"""
    from core.security import create_access_token

    # Create a token for the test user
    access_token = create_access_token(
        data={"sub": "testuser"}
    )

    return {
        "Authorization": f"Bearer {access_token}"
    }


@pytest.fixture(name="restricted_client")
def restricted_client_fixture(
    session: Session,
    mock_opensearch_client: MockOpenSearchClient,
    mock_s3_client: MockS3Client,
    mock_lambda_client: MockLambdaClient,
    monkeypatch,
):
    """
    An authenticated user holding no roles at all.

    The counterpart to `client`: it proves a guard actually refuses, where
    `client` only proves it lets the legacy permission set through. Without
    this, a guard wired to the wrong permission still passes every test.
    """
    from api.rbac.seed import sync_rbac_catalog

    user = persist_user(session, "norole")
    sync_rbac_catalog(session)
    with _make_client(session, mock_opensearch_client, mock_s3_client,
                      mock_lambda_client, monkeypatch, user=user) as client:
        yield client


def _grant_global_role(session: Session, user, role_name: str) -> None:
    """Grant a builtin global role, seeding the catalog first if need be."""
    from api.rbac.models import GrantSource, Role, UserRole
    from api.rbac.seed import sync_rbac_catalog

    sync_rbac_catalog(session)
    role = session.exec(select(Role).where(Role.name == role_name)).one()
    session.add(UserRole(user_id=user.id, role_id=role.id,
                         source=GrantSource.MANUAL))
    session.commit()


@pytest.fixture(name="auditor_client")
def auditor_client_fixture(
    session: Session,
    mock_opensearch_client: MockOpenSearchClient,
    mock_s3_client: MockS3Client,
    mock_lambda_client: MockLambdaClient,
    monkeypatch,
):
    """
    A non-superuser holding the builtin `auditor` role, which carries role:read.

    The persona the CurrentSuperuser dependency used to lock out of the admin
    panel: read-only across the platform, which is exactly what compliance and
    read-only agents are given.
    """
    user = persist_user(session, "auditor_user")
    _grant_global_role(session, user, "auditor")
    with _make_client(session, mock_opensearch_client, mock_s3_client,
                      mock_lambda_client, monkeypatch, user=user) as client:
        yield client


@pytest.fixture(name="other_project")
def other_project_fixture(session):
    """A second project, for proving a project-scoped grant does not generalise."""
    from api.project.models import Project

    project = Project(
        project_id="P-19900109-0002",
        name="Other Project",
        created_by="someone_else",
    )
    session.add(project)
    session.commit()
    session.refresh(project)
    return project


@pytest.fixture(name="project_owner_client")
def project_owner_client_fixture(
    session: Session,
    test_project,
    mock_opensearch_client: MockOpenSearchClient,
    mock_s3_client: MockS3Client,
    mock_lambda_client: MockLambdaClient,
    monkeypatch,
):
    """
    A non-superuser who owns `test_project` and holds no global role.

    Deliberately given nothing on the global plane, so anything this client can
    reach it reached through the project grant alone. That is the self-serve
    case the project plane exists for.
    """
    from api.rbac.models import GrantSource, ProjectMember, Role
    from api.rbac.seed import sync_rbac_catalog

    user = persist_user(session, "project_owner_user")
    sync_rbac_catalog(session)
    role = session.exec(select(Role).where(Role.name == "project_owner")).one()
    session.add(ProjectMember(project_id=test_project.id, user_id=user.id,
                              role_id=role.id, source=GrantSource.MANUAL))
    session.commit()
    with _make_client(session, mock_opensearch_client, mock_s3_client,
                      mock_lambda_client, monkeypatch, user=user) as client:
        yield client


@pytest.fixture(name="client_with_permissions")
def client_with_permissions_fixture(
    session: Session,
    mock_opensearch_client: MockOpenSearchClient,
    mock_s3_client: MockS3Client,
    mock_lambda_client: MockLambdaClient,
    monkeypatch,
):
    """
    Build a client holding exactly the permissions named, and nothing else.

    `client` holds the whole legacy set and `restricted_client` holds none, so
    between them they cannot express "holds job:read but not job:update" -- which
    is the distinction any guard resolving its requirement from the payload turns
    on. Without a fixture at this granularity such a guard passes its tests while
    checking the wrong permission on one of its two branches.

    One client per test: _make_client clears app.dependency_overrides on exit, so
    building a second and tearing down the first would unauthenticate both.
    """
    stack = ExitStack()

    def make(permissions, *, username="scoped"):
        from api.rbac.models import GrantSource, Role, RolePermission, UserRole
        from api.rbac.roles import RoleScope
        from api.rbac.seed import sync_rbac_catalog

        sync_rbac_catalog(session)
        user = persist_user(session, username)
        role = Role(
            name=f"test_{username}",
            display_name=f"Ad-hoc test role for {username}",
            description="Created by client_with_permissions for a single test",
            scope=RoleScope.GLOBAL,
            is_builtin=False,
        )
        session.add(role)
        session.flush()
        for permission in permissions:
            session.add(
                RolePermission(role_id=role.id, permission=str(permission))
            )
        session.add(
            UserRole(user_id=user.id, role_id=role.id, source=GrantSource.MANUAL)
        )
        session.commit()
        return stack.enter_context(
            _make_client(session, mock_opensearch_client, mock_s3_client,
                         mock_lambda_client, monkeypatch, user=user)
        )

    try:
        yield make
    finally:
        stack.close()


@pytest.fixture(name="superuser_client")
def superuser_client_fixture(
    session: Session,
    mock_opensearch_client: MockOpenSearchClient,
    mock_s3_client: MockS3Client,
    mock_lambda_client: MockLambdaClient,
    monkeypatch,
):
    """
    A superuser, which short-circuits ahead of roles and so holds no grant.

    Persisted all the same: the RBAC admin endpoints record `granted_by` as an
    FK to users.id, and a caller who is not a row makes every grant it issues a
    dangling reference.
    """
    user = persist_user(session, "admin", superuser=True)
    with _make_client(session, mock_opensearch_client, mock_s3_client,
                      mock_lambda_client, monkeypatch, user=user) as client:
        yield client


@pytest.fixture(name="opensearch_client")
def opensearch_client_fixture(mock_opensearch_client: MockOpenSearchClient):
    """Provide the mock OpenSearch client directly for tests that need it"""
    return mock_opensearch_client
