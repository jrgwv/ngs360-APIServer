"""
Unified File Models - Supporting both file uploads and external file references.

This module provides a unified file metadata system that supports:
- Both file uploads and external file references
- Typed junction tables for entity associations with real FK constraints
- Flexible sample associations with roles via FileSample
- Multi-algorithm hash storage via FileHash
- Flexible key-value tags via FileTag

Entity associations use typed junction tables (FileProject, FileSequencingRun,
FileQCRecord, FilePipeline) with real FK constraints and cascade deletes.
"""

from datetime import datetime, timezone
import hashlib
import mimetypes
import re
from typing import List, TYPE_CHECKING
import uuid

from pydantic import ConfigDict, model_validator
from sqlalchemy import BigInteger
from sqlmodel import Field, Relationship, SQLModel, UniqueConstraint

if TYPE_CHECKING:
    from api.samples.models import Sample  # noqa: F811


# ============================================================================
# Database Tables — Junction Tables (File ↔ Entity)
# ============================================================================


class FileHash(SQLModel, table=True):
    """
    Hash values for files (supports multiple algorithms).

    Supports: md5, sha256, etag, etc.
    """
    __tablename__ = "filehash"

    id: uuid.UUID = Field(default_factory=uuid.uuid4, primary_key=True)
    file_id: uuid.UUID = Field(foreign_key="file.id", nullable=False)
    algorithm: str = Field(max_length=50, nullable=False)
    value: str = Field(max_length=128, nullable=False)

    # Relationship back to parent
    file: "File" = Relationship(back_populates="hashes")

    __table_args__ = (
        UniqueConstraint("file_id", "algorithm", name="uq_filehash_file_algorithm"),
    )


class FileTag(SQLModel, table=True):
    """
    Flexible key-value metadata for files.

    Standard tags:
    - archived: true/false
    - public: true/false
    - description: file description
    - type: alignment, variant, expression, qc_report, etc.
    - format: bam, vcf, fastq, csv, etc.
    """
    __tablename__ = "filetag"

    id: uuid.UUID = Field(default_factory=uuid.uuid4, primary_key=True)
    file_id: uuid.UUID = Field(foreign_key="file.id", nullable=False)
    key: str = Field(max_length=255, nullable=False)
    value: str = Field(nullable=False)

    # Relationship back to parent
    file: "File" = Relationship(back_populates="tags")

    __table_args__ = (
        UniqueConstraint("file_id", "key", name="uq_filetag_file_key"),
    )


class FileSample(SQLModel, table=True):
    """
    Associates samples with a file (supports roles for paired analysis).

    Supports:
    - 0 rows: workflow-level file (e.g., expression matrix)
    - 1 row: single-sample file (e.g., BAM file)
    - N rows: multi-sample file with roles (e.g., tumor/normal VCF)
    """
    __tablename__ = "filesample"

    id: uuid.UUID = Field(default_factory=uuid.uuid4, primary_key=True)
    file_id: uuid.UUID = Field(foreign_key="file.id", nullable=False)
    sample_id: uuid.UUID = Field(foreign_key="sample.id", nullable=False)
    role: str | None = Field(default=None, max_length=50)  # e.g., "tumor", "normal"

    # Relationship back to parent file
    file: "File" = Relationship(back_populates="samples")
    # Bidirectional relationship to Sample
    sample: "Sample" = Relationship(back_populates="file_samples")

    __table_args__ = (
        UniqueConstraint("file_id", "sample_id", name="uq_filesample_file_sample"),
    )


class FileProject(SQLModel, table=True):
    """
    Associates a file with a project.

    A project describes a physical location (e.g., s3://<bucket>/<project_id>/).
    Common roles: manifest, samplesheet, documentation.
    """
    __tablename__ = "fileproject"
    __table_args__ = (
        UniqueConstraint("file_id", "project_id", name="uq_fileproject"),
    )

    id: uuid.UUID = Field(default_factory=uuid.uuid4, primary_key=True)
    file_id: uuid.UUID = Field(foreign_key="file.id", nullable=False)
    project_id: uuid.UUID = Field(foreign_key="project.id", nullable=False)
    role: str | None = Field(default=None, max_length=50)

    # Relationship back to parent file
    file: "File" = Relationship(back_populates="projects")


class FileSequencingRun(SQLModel, table=True):
    """
    Associates a file with a sequencing run.

    Common roles: samplesheet, stats, interop, runinfo.
    """
    __tablename__ = "filesequencingrun"
    __table_args__ = (
        UniqueConstraint("file_id", "sequencing_run_id", name="uq_filesequencingrun"),
    )

    id: uuid.UUID = Field(default_factory=uuid.uuid4, primary_key=True)
    file_id: uuid.UUID = Field(foreign_key="file.id", nullable=False)
    sequencing_run_id: uuid.UUID = Field(foreign_key="sequencingrun.id", nullable=False)
    role: str | None = Field(default=None, max_length=50)

    # Relationship back to parent file
    file: "File" = Relationship(back_populates="sequencing_runs")


class FileQCRecord(SQLModel, table=True):
    """
    Associates a file with a QC record (pipeline output files).

    Common roles: output, log, report.
    """
    __tablename__ = "fileqcrecord"
    __table_args__ = (
        UniqueConstraint("file_id", "qcrecord_id", name="uq_fileqcrecord"),
    )

    id: uuid.UUID = Field(default_factory=uuid.uuid4, primary_key=True)
    file_id: uuid.UUID = Field(foreign_key="file.id", nullable=False)
    qcrecord_id: uuid.UUID = Field(foreign_key="qcrecord.id", nullable=False)
    role: str | None = Field(default=None, max_length=50)

    # Relationship back to parent file
    file: "File" = Relationship(back_populates="qcrecords")


class FilePipeline(SQLModel, table=True):
    """
    Associates a file with a pipeline.

    Common roles: definition, documentation, config.
    """
    __tablename__ = "filepipeline"
    __table_args__ = (
        UniqueConstraint("file_id", "pipeline_id", name="uq_filepipeline"),
    )

    id: uuid.UUID = Field(default_factory=uuid.uuid4, primary_key=True)
    file_id: uuid.UUID = Field(foreign_key="file.id", nullable=False)
    pipeline_id: uuid.UUID = Field(foreign_key="pipeline.id", nullable=False)
    role: str | None = Field(default=None, max_length=50)

    # Relationship back to parent file
    file: "File" = Relationship(back_populates="pipelines")


# ============================================================================
# Core File Table
# ============================================================================


class File(SQLModel, table=True):
    """
    Core file entity supporting both uploads and external references.

    This unified model replaces both the original File model (upload-focused)
    and FileRecord model (reference-focused).

    The `uri` field is the file location. Filename can be derived as
    `uri.split('/')[-1]`. Same URI can exist multiple times with different
    `created_on` timestamps, enabling versioning.

    Version queries:
    - Latest version: WHERE uri = ? ORDER BY created_on DESC LIMIT 1
    - All versions: WHERE uri = ? ORDER BY created_on
    """
    __tablename__ = "file"
    __searchable__ = ["uri"]

    id: uuid.UUID = Field(default_factory=uuid.uuid4, primary_key=True)
    uri: str = Field(max_length=512)  # File location (not unique alone)
    original_filename: str | None = Field(default=None, max_length=255)  # For uploads only
    size: int | None = Field(default=None, sa_type=BigInteger)  # Bytes (BIGINT — files > 2 GB)
    created_on: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    created_by: str | None = Field(default=None, max_length=100)  # Who did the work
    # Who actually made the API call. Client-supplied created_by is an
    # "on behalf of" claim -- one pipeline registers files for 42 scientists, 40
    # of whom hold no credential of their own -- so it cannot also carry
    # accountability. This can: it is set from the authenticated caller and is
    # never accepted from a request. Null for rows written before it existed, and
    # for anonymous callers while the create routes remain open.
    submitted_by: str | None = Field(default=None, max_length=100)
    source: str | None = Field(default=None, max_length=1024)  # Origin of file record
    storage_backend: str | None = Field(default=None, max_length=20)  # LOCAL, S3, AZURE, GCS

    # Composite unique constraint: uri + created_on enables versioning
    __table_args__ = (
        UniqueConstraint("uri", "created_on", name="uq_file_uri_created_on"),
    )

    # Relationships to child tables — hash/tag/sample
    hashes: List["FileHash"] = Relationship(
        back_populates="file",
        sa_relationship_kwargs={"cascade": "all, delete-orphan"}
    )
    tags: List["FileTag"] = Relationship(
        back_populates="file",
        sa_relationship_kwargs={"cascade": "all, delete-orphan"}
    )
    samples: List["FileSample"] = Relationship(
        back_populates="file",
        sa_relationship_kwargs={"cascade": "all, delete-orphan"}
    )

    # Relationships to typed entity junction tables
    projects: List["FileProject"] = Relationship(
        back_populates="file",
        sa_relationship_kwargs={"cascade": "all, delete-orphan"}
    )
    sequencing_runs: List["FileSequencingRun"] = Relationship(
        back_populates="file",
        sa_relationship_kwargs={"cascade": "all, delete-orphan"}
    )
    qcrecords: List["FileQCRecord"] = Relationship(
        back_populates="file",
        sa_relationship_kwargs={"cascade": "all, delete-orphan"}
    )
    pipelines: List["FilePipeline"] = Relationship(
        back_populates="file",
        sa_relationship_kwargs={"cascade": "all, delete-orphan"}
    )

    model_config = ConfigDict(from_attributes=True)

    @property
    def filename(self) -> str:
        """Derive filename from URI."""
        return self.uri.split("/")[-1] if self.uri else ""

    @staticmethod
    def generate_uri(
        base_path: str,
        entity_type: str,
        entity_id: str,
        filename: str,
        relative_path: str | None = None,
    ) -> str:
        """
        Generate a structured URI for file storage.

        Args:
            base_path: Storage root (e.g., s3://bucket)
            entity_type: Type of entity (project, run, sample, qcrecord)
            entity_id: ID of the entity
            filename: Name of the file
            relative_path: Optional subdirectory path (e.g., "raw_data/sample1")

        Returns:
            Full URI string

        Examples:
            generate_uri("s3://bucket", "project", "P-123", "file.txt")
            => "s3://bucket/project/P-123/file.txt"

            generate_uri("s3://bucket", "project", "P-123", "file.txt", "raw_data")
            => "s3://bucket/project/P-123/raw_data/file.txt"
        """
        # Build path components
        path_parts = [base_path.rstrip("/"), entity_type.lower(), entity_id]

        # Add subdirectory if provided
        if relative_path:
            normalized = relative_path.strip("/")
            if normalized:
                path_parts.append(normalized)

        # Add filename
        path_parts.append(filename)

        return "/".join(path_parts)

    @staticmethod
    def validate_relative_path(relative_path: str | None) -> str | None:
        """
        Validate and sanitize relative path to prevent security issues.

        Args:
            relative_path: Path to validate

        Returns:
            Sanitized path or None

        Raises:
            ValueError: If path contains invalid characters or patterns
        """
        if not relative_path:
            return None

        if relative_path.startswith("/"):
            raise ValueError("Absolute paths not allowed")

        if "//" in relative_path:
            raise ValueError("Double slashes not allowed")

        path = relative_path.strip("/")

        if not path:
            return None

        if ".." in path:
            raise ValueError("Path traversal not allowed (..)")

        if not re.match(r"^[a-zA-Z0-9_\-/]+$", path):
            raise ValueError(
                "Invalid characters in path. "
                "Only alphanumeric, dash, underscore, and forward slash allowed"
            )

        return path

    @staticmethod
    def calculate_checksum(file_content: bytes, algorithm: str = "sha256") -> str:
        """Calculate checksum of file content."""
        if algorithm == "sha256":
            return hashlib.sha256(file_content).hexdigest()
        elif algorithm == "md5":
            return hashlib.md5(file_content, usedforsecurity=False).hexdigest()
        else:
            raise ValueError(f"Unsupported hash algorithm: {algorithm}")

    @staticmethod
    def get_mime_type(filename: str) -> str:
        """Get MIME type based on file extension."""
        mime_type, _ = mimetypes.guess_type(filename)
        return mime_type or "application/octet-stream"


# ============================================================================
# Request/Response Models (Pydantic)
# ============================================================================


class SampleInput(SQLModel):
    """Sample association input for file creation."""
    sample_name: str
    role: str | None = None


class FileCreate(SQLModel):
    """
    Request model for creating a file (upload or reference).

    For uploads, file_content is provided separately.
    For external references, just the metadata is needed.

    Entity associations use scalar UUID fields — a file typically belongs to
    one entity of each type (one project, one run, one QCRecord, etc.).
    """
    uri: str  # Required - serves as unique identifier
    original_filename: str | None = None  # For uploads only
    size: int | None = None
    created_on: datetime | None = None  # File timestamp - defaults to now if not provided
    source: str | None = None  # Origin of file record
    created_by: str | None = None
    storage_backend: str | None = None
    project_id: str | None = None  # String business key, resolved to UUID at service layer

    # Typed entity associations (replaces polymorphic EntityInput)
    sequencing_run_id: uuid.UUID | None = None
    qcrecord_id: uuid.UUID | None = None
    pipeline_id: uuid.UUID | None = None

    # Existing
    samples: List[SampleInput] | None = None
    hashes: dict[str, str] | None = None  # {"md5": "abc...", "sha256": "def..."}
    tags: dict[str, str] | None = None  # {"type": "alignment", "format": "bam"}

    model_config = ConfigDict(extra="forbid")

    @model_validator(mode="after")
    def validate_at_least_one_entity(self):
        """Ensure at least one entity association is provided (prevent orphan files)."""
        entities = [
            self.project_id,
            self.sequencing_run_id,
            self.qcrecord_id,
            self.pipeline_id,
        ]
        if not any(e is not None for e in entities):
            raise ValueError(
                "At least one entity association is required "
                "(project_id, sequencing_run_id, qcrecord_id, or pipeline_id)"
            )
        return self

    @model_validator(mode="after")
    def validate_project_id_with_samples(self):
        if self.samples and not self.project_id:
            raise ValueError("project_id is required when samples are provided")
        return self


class FileUploadCreate(SQLModel):
    """
    Request model for file upload via form data.

    This is a simplified version of FileCreate for form-based uploads
    where files are associated with a single entity.

    Uses typed entity ID fields instead of polymorphic entity_type/entity_id.
    Exactly one entity ID should be provided per upload.
    """
    filename: str  # Display filename for the upload
    original_filename: str | None = None
    description: str | None = None

    # Typed entity associations — exactly one should be populated per upload
    project_id: str | None = None  # String business key
    sequencing_run_id: uuid.UUID | None = None
    qcrecord_id: uuid.UUID | None = None
    pipeline_id: uuid.UUID | None = None

    role: str | None = None  # e.g., samplesheet
    is_public: bool = False
    created_by: str | None = None
    relative_path: str | None = None
    overwrite: bool = False

    model_config = ConfigDict(extra="forbid")

    @model_validator(mode="after")
    def validate_exactly_one_entity(self):
        """Ensure at least one entity association is provided."""
        entities = [
            self.project_id,
            self.sequencing_run_id,
            self.qcrecord_id,
            self.pipeline_id,
        ]
        provided = [e for e in entities if e is not None]
        if len(provided) == 0:
            raise ValueError(
                "At least one entity association is required "
                "(project_id, sequencing_run_id, qcrecord_id, or pipeline_id)"
            )
        if len(provided) > 1:
            raise ValueError(
                "Only one entity association should be provided per upload"
            )
        return self

    @property
    def entity_type_for_uri(self) -> str:
        """Return the entity type string for URI generation."""
        if self.project_id is not None:
            return "project"
        if self.sequencing_run_id is not None:
            return "run"
        if self.qcrecord_id is not None:
            return "qcrecord"
        if self.pipeline_id is not None:
            return "pipeline"
        return "unknown"

    @property
    def entity_id_for_uri(self) -> str:
        """Return the entity ID string for URI generation."""
        if self.project_id is not None:
            return self.project_id
        if self.sequencing_run_id is not None:
            return str(self.sequencing_run_id)
        if self.qcrecord_id is not None:
            return str(self.qcrecord_id)
        if self.pipeline_id is not None:
            return str(self.pipeline_id)
        return "unknown"


class HashPublic(SQLModel):
    """Public representation of a file hash."""
    algorithm: str
    value: str


class TagPublic(SQLModel):
    """Public representation of a file tag."""
    key: str
    value: str


class FileSamplePublic(SQLModel):
    """Public representation of a file-sample association."""
    sample_name: str
    role: str | None


class FileAssociationPublic(SQLModel):
    """
    Typed entity association in file responses.

    Unifies all typed junction tables into a single response format.
    The underlying storage uses proper FK-backed junction tables.
    """
    entity_type: str  # PROJECT, SEQUENCING_RUN, QCRECORD, PIPELINE
    entity_id: uuid.UUID
    role: str | None


class FilePublic(SQLModel):
    """Public representation of a file."""
    id: uuid.UUID
    uri: str
    filename: str  # Computed from uri
    original_filename: str | None
    size: int | None
    created_on: datetime
    created_by: str | None
    submitted_by: str | None
    source: str | None
    storage_backend: str | None
    associations: List[FileAssociationPublic]
    samples: List[FileSamplePublic]
    hashes: List[HashPublic]
    tags: List[TagPublic]


class PresignedDownload(SQLModel):
    """
    A time-limited URL the caller can fetch the bytes from directly.

    Exists so that authorization can be checked on a request a *browser* is able
    to authenticate. GET /files/download answers with a 307 to S3, which means
    the UI uses it as a plain link -- and a browser following a link cannot
    attach an Authorization header, so that endpoint cannot be closed without
    breaking every download in the product. Here the caller fetches the URL with
    its token and then navigates to S3 itself.

    No new exposure: the bytes already bypass the API today, because the redirect
    sends the browser straight to the same presigned URL.
    """
    url: str
    expires_in: int  # seconds from now


class FileSummary(SQLModel):
    """
    Compact file representation for lists.

    Used when embedding files in other responses (e.g., QCRecord).
    """
    id: uuid.UUID
    uri: str
    filename: str  # Computed from uri
    size: int | None
    created_on: datetime | None = None
    hashes: List[HashPublic] = []
    tags: List[TagPublic] = []
    samples: List[FileSamplePublic] = []


class FileUpdate(SQLModel):
    """
    Request model for updating a file record.

    All fields are optional — only provided fields are updated.
    Primary use case: correcting a URI (e.g., wrong bucket name).
    """
    uri: str | None = None
    original_filename: str | None = None
    size: int | None = None
    source: str | None = None
    # Neither created_by nor submitted_by is updatable.
    #
    # created_by is an attribution claim: correcting it is a deliberate,
    # auditable act, not a field on a general-purpose PATCH whose documented
    # purpose is fixing a URI. Nobody has needed it in 634k rows.
    #
    # submitted_by is derived from the caller by definition, so a client
    # setting it would defeat the only thing it is for.
    storage_backend: str | None = None

    model_config = ConfigDict(extra="forbid")


class FilesPublic(SQLModel):
    """Paginated list of files."""
    data: List[FilePublic]
    total: int
    page: int
    per_page: int


# ============================================================================
# File Browser Models (for S3/local file listing)
# ============================================================================


class FileBrowserFolder(SQLModel):
    """Folder item for file browser."""
    name: str
    date: str


class FileBrowserFile(SQLModel):
    """File item for file browser."""
    name: str
    date: str
    size: int


class FileBrowserData(SQLModel):
    """File browser data structure with separate folders and files."""
    folders: List[FileBrowserFolder]
    files: List[FileBrowserFile]


# ============================================================================
# Helper Functions
# ============================================================================


def file_to_public(file: File) -> FilePublic:
    """Convert a File model instance to FilePublic response."""
    # Build unified associations list from all typed junction tables
    associations = []
    for fp in file.projects:
        associations.append(FileAssociationPublic(
            entity_type="PROJECT", entity_id=fp.project_id, role=fp.role
        ))
    for fsr in file.sequencing_runs:
        associations.append(FileAssociationPublic(
            entity_type="SEQUENCING_RUN", entity_id=fsr.sequencing_run_id, role=fsr.role
        ))
    for fqr in file.qcrecords:
        associations.append(FileAssociationPublic(
            entity_type="QCRECORD", entity_id=fqr.qcrecord_id, role=fqr.role
        ))
    for fpl in file.pipelines:
        associations.append(FileAssociationPublic(
            entity_type="PIPELINE", entity_id=fpl.pipeline_id, role=fpl.role
        ))

    return FilePublic(
        id=file.id,
        uri=file.uri,
        filename=file.filename,
        original_filename=file.original_filename,
        size=file.size,
        created_on=file.created_on,
        created_by=file.created_by,
        submitted_by=file.submitted_by,
        source=file.source,
        storage_backend=file.storage_backend,
        associations=associations,
        samples=[
            FileSamplePublic(sample_name=s.sample.sample_id, role=s.role)
            for s in file.samples
        ],
        hashes=[
            HashPublic(algorithm=h.algorithm, value=h.value)
            for h in file.hashes
        ],
        tags=[
            TagPublic(key=t.key, value=t.value)
            for t in file.tags
        ],
    )


def file_to_summary(file: File) -> FileSummary:
    """Convert a File model instance to FileSummary response."""
    return FileSummary(
        id=file.id,
        uri=file.uri,
        filename=file.filename,
        size=file.size,
        hashes=[
            HashPublic(algorithm=h.algorithm, value=h.value)
            for h in file.hashes
        ],
        tags=[
            TagPublic(key=t.key, value=t.value)
            for t in file.tags
        ],
        samples=[
            FileSamplePublic(sample_name=s.sample.sample_id, role=s.role)
            for s in file.samples
        ],
    )
