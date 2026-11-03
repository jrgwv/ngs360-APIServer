"""
Services for the Project API
"""

from datetime import datetime, timezone as tz
from typing import Literal
import boto3
import logging

from fastapi import HTTPException, status
from api.utils import check_duplicate_attribute_keys
from pydantic import PositiveInt, ValidationError
from pytz import timezone
from sqlmodel import Session, func, select
from sqlalchemy.orm import selectinload
from opensearchpy import OpenSearch
import yaml

from api.jobs.models import BatchJob, VendorIngestionConfig
from api.settings.services import get_setting, get_setting_value
from api.actions.services import get_all_action_configs
from api.actions.models import ActionOption, ActionPlatform
from api.jobs.services import submit_batch_job

from core.utils import define_search_body, interpolate

from api.project.models import (
    Project,
    ProjectAttribute,
    ProjectCreate,
    ProjectUpdate,
    ProjectPublic,
    ProjectsPublic,
)
from api.search.models import SearchDocument
from api.search.services import (
    add_object_to_index, add_objects_to_index, reset_index
)
from api.samples.models import (
    Sample,
    SampleAttribute,
    SampleCreate,
    SamplePublic,
    SamplesPublic,
    SamplesWithFilesPublic,
    SampleWithFilesPublic,
    SampleFilePublic,
    Attribute,
)
from api.runs.models import SequencingRun, SequencingRunPublic, SampleSequencingRun

logger = logging.getLogger(__name__)


def generate_project_id(*, session: Session) -> str:
    """
    Generate a unique project_id.
    This ID could be anything as long as its unique and human-readable.
    In this case, we generate an ID with the format P-YYYYMMDD-NNNN
    """
    # Prefix out of todays date (e.g., "P-20250717-")
    now = datetime.now(timezone("US/Eastern"))
    prefix = f"P-{now:%Y%m%d}-"

    # Find last project with today's date
    project = session.exec(
        select(Project)
        .where(Project.project_id.like(f"{prefix}%"))
        .order_by(Project.project_id.desc())
        .limit(1)
    ).one_or_none()

    if not project:
        return f"{prefix}0001"

    # Increment the suffix (part after the second hyphen)
    suffix = int(project.project_id.split("-")[2]) + 1
    return f"{prefix}{suffix:04d}"


def _enrol_creator_as_owner(
    session: Session, project: "Project", username: str
) -> None:
    """
    Give the creator project_owner, in the same transaction as the project insert.

    docs/RBAC.md has required this since the design was written; it was never
    implemented, and the omission is invisible until permissions are enforced.
    The ownership backfill covered projects that already existed, so every project
    created after it has **no members at all** -- not even the person who made it.
    Found in the production dry-run log: the largest single source of would_deny
    from a real user was someone downloading FASTQs from a project created two days
    earlier, refused because nobody was a member of it.

    Deliberately not routed through rbac.services.set_project_member, which
    commits. The membership has to land in the same transaction as the project, or
    a failure between the two leaves a project nobody can administer -- which is
    the state this fixes.

    Best-effort by design. A missing role row or an unresolvable username must not
    fail project creation: refusing to create the project is a worse outcome than
    creating one that needs a grant, and the dry-run log already surfaces the
    latter. Both cases are logged at ERROR because both mean someone will be
    refused later.
    """
    from api.auth.models import User
    from api.rbac.models import GrantSource, ProjectMember, Role

    user = session.exec(
        select(User).where(User.username == username)
    ).first()
    if user is None:
        # Service accounts and API-key callers resolve fine; this is the
        # unexpected case, e.g. a username changed underneath a live session.
        logger.error(
            "project %s created by %r, who is not a user row: no owner enrolled",
            project.project_id, username,
        )
        return

    role = session.exec(
        select(Role).where(Role.name == "project_owner")
    ).first()
    if role is None:
        # The catalog is seeded at startup; if it is absent something is wrong
        # with this deployment, not with this request.
        logger.error(
            "role project_owner is missing; %s created with no owner",
            project.project_id,
        )
        return

    session.add(ProjectMember(
        project_id=project.id,
        user_id=user.id,
        role_id=role.id,
        granted_by=user.id,
        source=GrantSource.MANUAL,
    ))


def create_project(
    session: Session,
    project_in: ProjectCreate,
    current_user: str,
    opensearch_client: OpenSearch = None
) -> ProjectPublic:
    """
    Create a new project with optional attributes.
    """
    # Create initial project
    project = Project(
        project_id=generate_project_id(session=session),
        name=project_in.name,
        created_by=current_user,
        restricted=project_in.restricted
    )
    session.add(project)
    session.flush()

    # Handle attribute mapping
    if project_in.attributes:
        check_duplicate_attribute_keys(
            project_in.attributes, "project attributes"
        )

        # Parse and create project attributes
        # linking to new project
        project_attributes = [
            ProjectAttribute(project_id=project.id, key=attr.key.strip(), value=attr.value.strip())
            for attr in project_in.attributes
        ]

        # Update database with attribute links
        session.add_all(project_attributes)

    _enrol_creator_as_owner(session, project, current_user)

    # With orm_mode=True, attributes will be eagerly loaded
    # and mapped to ProjectPublic via response model
    session.commit()
    session.refresh(project)

    # Add project to opensearch
    if opensearch_client:
        search_doc = SearchDocument(id=project.project_id, body=project)
        add_object_to_index(opensearch_client, search_doc, index="projects")

    data_bucket = get_setting_value(session, "DATA_BUCKET_URI")
    results_bucket = get_setting_value(session, "RESULTS_BUCKET_URI")

    return ProjectPublic(
        project_id=project.project_id,
        name=project.name,
        created_at=project.created_at,
        created_by=project.created_by,
        last_modified=project.last_modified,
        data_folder_uri=f"{data_bucket}/{project.project_id}/",
        results_folder_uri=f"{results_bucket}/{project.project_id}/",
        restricted=project.restricted,
        attributes=project.attributes,
        sequencing_runs=None  # No sequencing runs at time of project creation
    )


def get_projects(
    *,
    session: Session,
    page: PositiveInt,
    per_page: PositiveInt,
    sort_by: str,
    sort_order: Literal["asc", "desc"],
) -> ProjectsPublic:
    """
    Returns all projects from the database along
    with pagination information.
    """
    # Get total project count
    total_count = session.exec(select(func.count()).select_from(Project)).one()

    # Compute total pages
    total_pages = (total_count + per_page - 1) // per_page  # Ceiling division

    # Determine sort field and direction
    sort_field = getattr(Project, sort_by, Project.id)
    sort_direction = sort_field.asc() if sort_order == "asc" else sort_field.desc()

    # Get project selection
    projects = session.exec(
        select(Project)
        .order_by(sort_direction)
        .limit(per_page)
        .offset((page - 1) * per_page)
    ).all()

    data_bucket = get_setting_value(session, "DATA_BUCKET_URI")
    results_bucket = get_setting_value(session, "RESULTS_BUCKET_URI")

    # Map to public project
    public_projects = []
    for project in projects:
        try:
            public_projects.append(
                ProjectPublic(
                    project_id=project.project_id,
                    name=project.name,
                    created_at=project.created_at,
                    created_by=project.created_by,
                    last_modified=project.last_modified,
                    data_folder_uri=f"{data_bucket}/{project.project_id}/",
                    results_folder_uri=f"{results_bucket}/{project.project_id}/",
                    restricted=project.restricted,
                    attributes=project.attributes,
                    sequencing_runs=None  # Sequencing runs are not included for performance reasons
                )
            )
        except ValidationError as e:
            logger.error("Skipping project %s due to invalid data: %s", project.project_id, e)

    return ProjectsPublic(
        data=public_projects,
        total_items=total_count,
        total_pages=total_pages,
        current_page=page,
        per_page=per_page,
        has_next=page < total_pages,
        has_prev=page > 1,
    )


def get_project_attributes(session: Session) -> list[str]:
    """
    Returns a sorted list of all unique project attributes across all projects.
    """
    # select distinct `key` from projectattribute order by `key` asc
    return session.exec(
        select(ProjectAttribute.key)
        .distinct()
        .order_by(ProjectAttribute.key.asc())
    ).all()


def get_project_by_project_id(session: Session, project_id: str) -> ProjectPublic:
    """
    Returns a single project by its project_id.
    Note: This is different from its internal "id".
    """
    project = session.exec(
        select(Project).where(Project.project_id == project_id)
    ).first()

    if not project:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Project {project_id} not found.",
        )

    # Query sequencing runs associated with this project through samples
    sequencing_runs_query = (
        select(SequencingRun)
        .join(SampleSequencingRun, SampleSequencingRun.sequencing_run_id == SequencingRun.id)
        .join(Sample, Sample.id == SampleSequencingRun.sample_id)
        .where(Sample.project_id == project.project_id)
        .distinct()
    )
    sequencing_runs = session.exec(sequencing_runs_query).all()

    # Convert to public model
    sequencing_runs_public = [
        SequencingRunPublic(
            run_id=run.run_id,
            run_date=run.run_date,
            machine_id=run.machine_id,
            run_number=run.run_number,
            flowcell_id=run.flowcell_id,
            experiment_name=run.experiment_name,
            run_folder_uri=run.run_folder_uri,
            status=run.status,
            run_time=run.run_time
        )
        for run in sequencing_runs
    ]

    data_bucket = get_setting_value(session, "DATA_BUCKET_URI")
    results_bucket = get_setting_value(session, "RESULTS_BUCKET_URI")

    return ProjectPublic(
        project_id=project.project_id,
        name=project.name,
        created_at=project.created_at,
        created_by=project.created_by,
        last_modified=project.last_modified,
        data_folder_uri=f"{data_bucket}/{project.project_id}/",
        results_folder_uri=f"{results_bucket}/{project.project_id}/",
        restricted=project.restricted,
        attributes=project.attributes,
        sequencing_runs=sequencing_runs_public,
    )


def update_project(
    *,
    session: Session,
    opensearch_client: OpenSearch,
    project_id: str,
    update_request: ProjectUpdate,
) -> ProjectPublic:
    """
    Update an existing project with optional name and attributes.
    """
    # Fetch the project
    project = session.exec(
        select(Project).where(Project.project_id == project_id)
    ).first()

    if not project:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Project {project_id} not found.",
        )

    # Update name if provided
    if update_request.name is not None:
        project.name = update_request.name

    # Lock the project down, or open it back up.
    #
    # Added 2026-10-13. The field has been on ProjectUpdate since the flag was
    # introduced in #425 and was never persisted here, so a request setting it
    # returned 200 and changed nothing -- silently, because an ignored field is
    # indistinguishable from an applied one in the response.
    #
    # That is why "0 of 11,156 projects are restricted" kept turning up as
    # evidence while the downloads-open-by-default policy was argued: it was
    # read as nobody wanting a restricted project, and it meant nobody could
    # make one. Found by trying to set it in production in order to prove the
    # membership gate.
    if update_request.restricted is not None:
        project.restricted = update_request.restricted

    # Handle attributes if provided
    if update_request.attributes is not None:
        check_duplicate_attribute_keys(
            update_request.attributes, "project attributes"
        )

        # Delete all existing attributes for this project
        existing_attributes = session.exec(
            select(ProjectAttribute).where(
                ProjectAttribute.project_id == project.id
            )
        ).all()
        for existing_attr in existing_attributes:
            session.delete(existing_attr)

        # Flush to execute DELETEs before INSERTs to avoid constraint violations
        session.flush()

        # Add new attributes
        for attr in update_request.attributes:
            new_attr = ProjectAttribute(
                project_id=project.id,
                key=attr.key,
                value=attr.value,
            )
            session.add(new_attr)

    # Explicitly bump last_modified (onupdate only fires when the project row itself changes)
    project.last_modified = datetime.now(tz.utc)

    session.commit()
    session.refresh(project)

    # Update project in opensearch
    if opensearch_client:
        search_doc = SearchDocument(id=project.project_id, body=project)
        add_object_to_index(opensearch_client, search_doc, index="projects")

    data_bucket = get_setting_value(session, "DATA_BUCKET_URI")
    results_bucket = get_setting_value(session, "RESULTS_BUCKET_URI")

    return ProjectPublic(
        project_id=project.project_id,
        name=project.name,
        created_at=project.created_at,
        created_by=project.created_by,
        last_modified=project.last_modified,
        data_folder_uri=f"{data_bucket}/{project.project_id}/",
        results_folder_uri=f"{results_bucket}/{project.project_id}/",
        restricted=project.restricted,
        attributes=project.attributes,
        sequencing_runs=None  # Sequencing runs are not included in list view for performance reasons
    )


def patch_project(
    *,
    session: Session,
    opensearch_client: OpenSearch,
    project_id: str,
    update_request: ProjectUpdate,
) -> ProjectPublic:
    """
    Partially update a project using merge/upsert semantics.

    Unlike ``update_project`` (PUT), this does **not** remove attributes
    that are absent from the request.  Each supplied attribute is upserted:
    existing keys have their value updated, new keys are inserted, and
    unmentioned keys are left untouched.  An empty attributes list is a
    no-op.
    """
    # Fetch the project
    project = session.exec(
        select(Project).where(Project.project_id == project_id)
    ).first()

    if not project:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Project {project_id} not found.",
        )

    # Update name if provided
    if update_request.name is not None:
        project.name = update_request.name

    # Lock the project down, or open it back up.
    #
    # Added 2026-10-13. The field has been on ProjectUpdate since the flag was
    # introduced in #425 and was never persisted here, so a request setting it
    # returned 200 and changed nothing -- silently, because an ignored field is
    # indistinguishable from an applied one in the response.
    #
    # That is why "0 of 11,156 projects are restricted" kept turning up as
    # evidence while the downloads-open-by-default policy was argued: it was
    # read as nobody wanting a restricted project, and it meant nobody could
    # make one. Found by trying to set it in production in order to prove the
    # membership gate.
    if update_request.restricted is not None:
        project.restricted = update_request.restricted

    # Merge/upsert attributes (does NOT remove unmentioned attributes)
    if (
        update_request.attributes is not None
        and len(update_request.attributes) > 0
    ):
        check_duplicate_attribute_keys(
            update_request.attributes, "project attributes"
        )

        # Load all existing attributes and build case-insensitive lookup map
        existing_attrs = session.exec(
            select(ProjectAttribute).where(
                ProjectAttribute.project_id == project.id
            )
        ).all()
        attr_map = {a.key.lower(): a for a in existing_attrs}

        for attr in update_request.attributes:
            existing_attr = attr_map.get(attr.key.lower())

            if existing_attr:
                existing_attr.value = attr.value
                # Adopt the incoming key casing so the DB stays consistent
                if existing_attr.key != attr.key:
                    existing_attr.key = attr.key
            else:
                session.add(
                    ProjectAttribute(
                        project_id=project.id,
                        key=attr.key,
                        value=attr.value,
                    )
                )

    # Explicitly bump last_modified (onupdate only fires when the project row itself changes)
    project.last_modified = datetime.now(tz.utc)

    session.commit()
    session.refresh(project)

    # Update project in opensearch
    if opensearch_client:
        search_doc = SearchDocument(
            id=project.project_id, body=project
        )
        add_object_to_index(
            opensearch_client, search_doc, index="projects"
        )

    data_bucket = get_setting_value(session, "DATA_BUCKET_URI")
    results_bucket = get_setting_value(session, "RESULTS_BUCKET_URI")

    return ProjectPublic(
        project_id=project.project_id,
        name=project.name,
        created_at=project.created_at,
        created_by=project.created_by,
        last_modified=project.last_modified,
        data_folder_uri=f"{data_bucket}/{project.project_id}/",
        results_folder_uri=(
            f"{results_bucket}/{project.project_id}/"
        ),
        attributes=project.attributes,
        sequencing_runs=None,
        # Omitted until 2026-10-13, so these two responses always reported the
        # project as unrestricted whatever the row said. Four of the six
        # ProjectPublic constructions in this module passed it and two did not,
        # which is the hazard of building the model field by field rather than
        # from the row.
        restricted=project.restricted,
    )


def search_projects(
    session: Session,
    client: OpenSearch,
    query: str,
    page: int,
    per_page: int,
    sort_by: str | None = "name",
    sort_order: Literal["asc", "desc"] | None = "asc",
) -> ProjectsPublic:
    """
    Search for projects
    """
    # Construct the search query
    search_body = define_search_body(query, page, per_page, sort_by, sort_order)

    project = None  # referenced by the error handler below, which can run before it is set
    try:
        response = client.search(index="projects", body=search_body)
        total_items = response["hits"]["total"]["value"]
        total_pages = (total_items + per_page - 1) // per_page  # Ceiling division

        # Batch database lookup: collect all project_ids first
        project_ids = [hit["_source"].get("project_id") for hit in response["hits"]["hits"]]

        if not project_ids:
            return ProjectsPublic(
                data=[],
                total_items=total_items,
                total_pages=total_pages,
                current_page=page,
                per_page=per_page,
                has_next=page < total_pages,
                has_prev=page > 1,
            )

        # Single query to fetch all projects with their attributes
        projects = session.exec(
            select(Project)
            .options(selectinload(Project.attributes))
            .where(Project.project_id.in_(project_ids))
        ).all()

        # Fetch settings once (not per-project)
        data_bucket = get_setting_value(session, "DATA_BUCKET_URI")
        results_bucket = get_setting_value(session, "RESULTS_BUCKET_URI")

        # Create lookup map for O(1) access
        project_map = {project.project_id: project for project in projects}

        # Preserve OpenSearch ranking order
        results = []
        for project_id in project_ids:
            project = project_map.get(project_id)
            if project:
                results.append(
                    ProjectPublic(
                        project_id=project.project_id,
                        name=project.name,
                        created_at=project.created_at,
                        created_by=project.created_by,
                        last_modified=project.last_modified,
                        data_folder_uri=f"{data_bucket}/{project.project_id}/",
                        results_folder_uri=f"{results_bucket}/{project.project_id}/",
                        attributes=project.attributes,
                        sequencing_runs=None,  # Not included for performance (matches get_projects)
                        restricted=project.restricted,
                    )
                )

        return ProjectsPublic(
            data=results,
            total_items=total_items,
            total_pages=total_pages,
            current_page=page,
            per_page=per_page,
            has_next=page < total_pages,
            has_prev=page > 1,
        )

    except Exception as e:
        if project:
            details = f"{project.project_id}: {str(e)}"
        else:
            details = str(e)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=details
        )


def reindex_projects(
    session: Session,
    client: OpenSearch
):
    """
    Index all projects in database with OpenSearch
    """
    projects = session.exec(
        select(Project).order_by(Project.project_id)
    ).all()

    # Prepare all documents
    search_docs = []
    for project in projects:
        search_doc = SearchDocument(id=project.project_id, body=project)
        search_docs.append(search_doc)

    reset_index(client, "projects")
    # Bulk index all documents in one call
    add_objects_to_index(client, search_docs, "projects")


def submit_pipeline_job(
    session: Session,
    project: Project,
    action: "ActionOption",
    platform: "ActionPlatform",
    project_type: str,
    username: str,
    email: str | None = None,
    reference: str | None = None,
    auto_release: bool | None = None,
    s3_client=None
) -> BatchJob:
    """
    Submit a pipeline job to AWS Batch.

    This function retrieves the appropriate pipeline configuration, determines which
    command to use based on the action, interpolates template variables, and submits
    the job to AWS Batch.

    Args:
        session: Database session
        project: The project object (already validated)
        action: Pipeline action (create-project or export-project-results)
        platform: Platform name (arvados or sevenbridges)
        project_type: Pipeline type (e.g., RNA-Seq)
        username: Username of the user submitting the job
        email: Email of the user submitting the job (available as template variable)
        reference: Export reference label (required for export action)
        auto_release: Auto-release flag (only valid for export action)
        s3_client: Optional boto3 S3 client

    Returns:
        BatchJob instance

    Raises:
        HTTPException: If validation fails or submission fails
    """
    # Get all action configs and find matching project_type
    all_configs = get_all_action_configs(session, s3_client)
    action_config = None

    for config in all_configs.configs:
        if config.project_type == project_type:
            action_config = config
            break

    if action_config is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Action configuration for project type '{project_type}' not found"
        )

    # Check if platform exists in action config
    if platform not in action_config.platforms:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Platform '{platform}' not configured for project type '{project_type}'"
        )

    platform_config = action_config.platforms[platform]

    # Validate action-specific requirements
    reference_value = None
    if action == ActionOption.CREATE_PROJECT:
        # Ignore auto_release for create action - just set to None/False
        if auto_release is None:
            auto_release = False
    elif action == ActionOption.EXPORT_PROJECT_RESULTS:
        # Default auto_release to False if not provided
        if auto_release is None:
            auto_release = False

        # Validate reference is provided for export
        if not reference:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Reference is required for export-project-results action"
            )

        # Look up reference value from exports list
        if not platform_config.exports:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=(
                    f"No exports configured for platform '{platform}' "
                    f"in project type '{project_type}'"
                )
            )

        # Find the matching export entry
        reference_value = None
        for export_item in platform_config.exports:
            # Each export_item is a dict with one key-value pair
            for label, value in export_item.items():
                if label == reference:
                    reference_value = value
                    break
            if reference_value:
                break

        if reference_value is None:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=(
                    f"Reference '{reference}' not found in exports for "
                    f"platform '{platform}' and project type "
                    f"'{project_type}'"
                )
            )

    # Prepare template context with all variables needed for interpolation
    template_context = {
        "username": username,
        "email": email,
        "projectid": project.project_id,
        "project_type": project_type,
        "platform": platform.value,
        "action": action.value,
        "reference": reference_value,  # Use the looked-up value, not the label
        "auto_release": auto_release
    }

    # Select and interpolate the appropriate command based on action
    if action == ActionOption.CREATE_PROJECT:
        command_template = platform_config.create_project_command
    else:  # export-project-results
        command_template = platform_config.export_command

    try:
        interpolated_command = interpolate(command_template, template_context)
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to interpolate command template: {str(e)}"
        ) from e

    # Check if aws_batch config exists
    if not action_config.aws_batch:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=(
                f"AWS Batch configuration not found for project type "
                f"'{project_type}'"
            )
        )

    # Interpolate AWS Batch configuration
    try:
        interpolated_job_name = interpolate(action_config.aws_batch.job_name, template_context)
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to interpolate job name template: {str(e)}"
        ) from e

    # Prepare container overrides
    container_overrides = {
        "command": interpolated_command.split(),
        "environment": []
    }

    # Add environment variables if specified in aws_batch config
    if action_config.aws_batch.environment:
        for env in action_config.aws_batch.environment:
            try:
                interpolated_env_value = interpolate(env.value, template_context)
                container_overrides["environment"].append({
                    "name": env.name,
                    "value": interpolated_env_value
                })
            except Exception as e:
                raise HTTPException(
                    status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                    detail=f"Failed to interpolate environment variable '{env.name}': {str(e)}"
                ) from e

    # Submit job to AWS Batch
    batch_job = submit_batch_job(
        session=session,
        job_name=interpolated_job_name,
        container_overrides=container_overrides,
        job_def=action_config.aws_batch.job_definition,
        job_queue=action_config.aws_batch.job_queue,
        user=username,
        project_id=project.project_id
    )
    return batch_job


def add_sample_to_project(
    session: Session,
    opensearch_client: OpenSearch,
    project: Project,
    sample_in: SampleCreate,
    created_by: str | None = None,
) -> Sample:
    """
    Create a new sample with optional attributes in a project.

    If ``sample_in.run_id`` is provided the sample is also associated
    with the corresponding sequencing run in the **same** transaction.

    Args:
        session: Database session
        opensearch_client: OpenSearch client for indexing
        project: The project object (already validated)
        sample_in: Sample creation data (may include run_id)
        created_by: Username recorded on any SampleSequencingRun row

    Returns:
        Sample instance
    """
    from api.runs.services import get_run

    # Resolve run up-front so we can fail fast before creating the sample
    run = None
    if sample_in.run_id:
        try:
            run = get_run(session=session, run_id=sample_in.run_id)
        except (ValueError, Exception):
            run = None
        if run is None:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Run with run_id '{sample_in.run_id}' not found.",
            )

    # Create initial sample
    sample = Sample(
        sample_id=sample_in.sample_id,
        project_id=project.project_id,
        created_at=datetime.now(tz.utc),
    )
    session.add(sample)
    session.flush()

    # Handle attribute mapping
    if sample_in.attributes:
        check_duplicate_attribute_keys(
            sample_in.attributes, "sample attributes"
        )

        # Create sample attributes
        sample_attributes = [
            SampleAttribute(sample_id=sample.id, key=attr.key, value=attr.value)
            for attr in sample_in.attributes
        ]

        # Update database with attribute links
        session.add_all(sample_attributes)

    # Associate with sequencing run if requested
    if run is not None:
        assoc = SampleSequencingRun(
            sample_id=sample.id,
            sequencing_run_id=run.id,
            created_by=created_by or "api",
        )
        session.add(assoc)

    # Create associated files if provided
    if sample_in.files:
        from api.samples.services import _create_sample_files
        _create_sample_files(
            session=session,
            sample=sample,
            project_uuid=project.id,
            file_inputs=sample_in.files,
        )

    session.commit()
    session.refresh(sample)

    # Add sample to opensearch (best-effort; DB is source of truth)
    if opensearch_client:
        search_doc = SearchDocument(id=str(sample.id), body=sample)
        try:
            add_object_to_index(opensearch_client, search_doc, index="samples")
        except Exception:
            pass  # best-effort indexing; can be resynced via /reindex

    return sample


def _deduplicate_files_by_uri(
    file_samples: list,
) -> list:
    """
    Given a list of FileSample associations, group by File.uri and keep only
    the file with the latest ``created_on`` per URI.

    Args:
        file_samples: List of FileSample ORM objects (with .file eagerly loaded)

    Returns:
        List of SampleFilePublic instances (one per unique URI, latest version)
    """
    uri_to_best: dict[str, tuple] = {}  # uri -> (created_on, FileSample)

    for fs in file_samples:
        file = fs.file
        uri = file.uri
        created = file.created_on

        if uri not in uri_to_best or created > uri_to_best[uri][0]:
            uri_to_best[uri] = (created, fs)

    result = []
    for _uri, (_created, fs) in uri_to_best.items():
        file = fs.file
        tags_dict = {t.key: t.value for t in (file.tags or [])}
        result.append(SampleFilePublic(
            uri=file.uri,
            tags=tags_dict or None,
            created_on=file.created_on,
        ))

    return result


def get_project_samples(
    *,
    session: Session,
    project: Project,
    skip: int = 0,
    limit: int = 100,
    sort_by: str,
    sort_order: Literal["asc", "desc"],
    include: list[str] | None = None,
    file_versions: str = "latest",
) -> SamplesPublic | SamplesWithFilesPublic:
    """
    Get a paginated list of samples for a specific project.

    Args:
        session: Database session
        project: The project object (already validated)
        skip: Number of records to skip (offset).
        limit: Maximum number of records to return.
        sort_by: Column name to sort by
        sort_order: Sort direction ('asc' or 'desc')
        include: Optional list of related data to include (e.g. ``["files"]``)
        file_versions: ``"latest"`` (default) returns only the newest file per
            URI; ``"all"`` returns every version.

    Returns:
        SamplesPublic or SamplesWithFilesPublic depending on *include*
    """
    from sqlalchemy.orm import selectinload

    from api.files.models import FileSample, File

    include_files = include is not None and "files" in include

    # Get the total count of samples for the project
    total_count = session.exec(
        select(func.count()).select_from(Sample).where(Sample.project_id == project.project_id)
    ).one()

    # Build the select statement
    statement = select(Sample).where(Sample.project_id == project.project_id)

    # Eagerly load file associations when requested
    if include_files:
        statement = statement.options(
            selectinload(Sample.file_samples)  # type: ignore[attr-defined]
            .selectinload(FileSample.file)  # type: ignore[attr-defined]
            .selectinload(File.tags)  # type: ignore[attr-defined]
        )

    # Add sorting
    if hasattr(Sample, sort_by):
        sort_column = getattr(Sample, sort_by)
        if sort_order == "desc":
            sort_column = sort_column.desc()
        statement = statement.order_by(sort_column)

    # Add pagination
    statement = statement.offset(skip).limit(limit)

    # Execute the query
    samples = session.exec(statement).all()

    # Collect all unique attribute keys across all samples for data_cols
    data_cols = None
    if samples:
        all_keys = set()
        for sample in samples:
            if sample.attributes:
                for attr in sample.attributes:
                    all_keys.add(attr.key)
        data_cols = sorted(list(all_keys)) if all_keys else None

    # Build response with or without files
    if include_files:
        public_samples = []
        for sample in samples:
            if file_versions == "latest":
                # Deduplicate: keep only the newest version per URI
                files = _deduplicate_files_by_uri(sample.file_samples or [])
            else:
                # Return all versions
                files = []
                for fs in sample.file_samples or []:
                    file = fs.file
                    tags_dict = {t.key: t.value for t in (file.tags or [])}
                    files.append(SampleFilePublic(
                        uri=file.uri,
                        tags=tags_dict or None,
                        created_on=file.created_on,
                    ))
            public_samples.append(
                SampleWithFilesPublic(
                    sample_id=sample.sample_id,
                    project_id=sample.project_id,
                    attributes=sample.attributes,
                    files=files if files else None,
                )
            )
        return SamplesWithFilesPublic(
            data=public_samples,
            data_cols=data_cols,
            total_items=total_count,
            skip=skip,
            limit=limit,
            has_next=(skip + limit) < total_count,
            has_prev=skip > 0,
        )

    # Default: no files
    public_samples_plain = [
        SamplePublic(
            sample_id=sample.sample_id,
            project_id=sample.project_id,
            attributes=sample.attributes,
        )
        for sample in samples
    ]

    return SamplesPublic(
        data=public_samples_plain,
        data_cols=data_cols,
        total_items=total_count,
        skip=skip,
        limit=limit,
        has_next=(skip + limit) < total_count,
        has_prev=skip > 0,
    )


def update_sample_in_project(
    session: Session,
    project: Project,
    sample_id: str,
    attribute: Attribute,
) -> SamplePublic:
    """
    Update an existing sample in a project.

    Args:
        session: Database session
        project: The project object (already validated)
        sample_id: ID of the sample to update
        attribute: Attribute to add or update

    Returns:
        Updated sample
    """
    # Fetch the sample
    sample = session.exec(
        select(Sample).where(
            Sample.sample_id == sample_id,
            Sample.project_id == project.project_id
        )
    ).first()

    if not sample:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Sample {sample_id} in project {project.project_id} not found.",
        )

    # Load all attributes for this sample and build a case-insensitive
    # lookup map (avoids func.lower() in SQL which suppresses index use
    # and mirrors the approach in bulk_create_samples).
    existing_attrs = session.exec(
        select(SampleAttribute).where(SampleAttribute.sample_id == sample.id)
    ).all()
    attr_map = {a.key.lower(): a for a in existing_attrs}
    sample_attribute = attr_map.get(attribute.key.lower())

    if sample_attribute:
        # Update existing attribute
        sample_attribute.value = attribute.value
        # Adopt the incoming key casing so the DB stays consistent
        if sample_attribute.key != attribute.key:
            sample_attribute.key = attribute.key
    else:
        # Create new attribute
        new_attribute = SampleAttribute(
            sample_id=sample.id,
            key=attribute.key,
            value=attribute.value
        )
        session.add(new_attribute)

    sample.updated_at = datetime.now(tz.utc)
    session.commit()
    session.refresh(sample)

    return SamplePublic(
        sample_id=sample.sample_id,
        project_id=sample.project_id,
        attributes=[
            Attribute(key=attr.key, value=attr.value) for attr in (sample.attributes or [])
        ] if sample.attributes else []
    )


def _read_vendor_config_yaml(session: Session, s3_client=None) -> VendorIngestionConfig:
    '''
    Read the Vendor Ingestion configuration YAML file from S3
    and parse it into a VendorIngestionConfig object.
    '''
    vendor_ingest_config_uri = get_setting(session, key='VENDOR_INGESTION_CONFIG')
    if not vendor_ingest_config_uri:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Vendor ingestion configuration not found"
        )
    if vendor_ingest_config_uri.value == '':
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Vendor ingestion configuration URI is empty"
        )

    # Parse S3 URI to get bucket and prefix
    s3_path = vendor_ingest_config_uri.value.replace("s3://", "")
    bucket = s3_path.split("/")[0]
    prefix = "/".join(s3_path.split("/")[1:])

    # Read the vendor ingestion configuration from S3
    try:
        if s3_client is None:
            s3_client = boto3.client("s3")
        response = s3_client.get_object(Bucket=bucket, Key=prefix)
        config_content = response["Body"].read().decode("utf-8")
        config = yaml.safe_load(config_content)
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to read vendor ingestion configuration from S3: {str(e)}"
        ) from e
    config_data = VendorIngestionConfig(**config)
    return config_data


def ingest_vendor_data(
    session: Session,
    project: Project,
    user: str,
    vendor_bucket: str,
    manifest_uri: str,
    s3_client=None
):
    """
    Invoke the vendor ingestion process.
    """
    # Read vendor ingestion configuration from S3
    config_data = _read_vendor_config_yaml(session, s3_client)

    if vendor_bucket.startswith("s3://"):
        vendor_bucket = vendor_bucket.replace("s3://", "")

    # Prepare template context with all variables needed for interpolation
    # This should be built dynamically from the inputs section of the config file and
    # available session variables.  We should not be hard-coding anything here.
    template_context = {
        'vendor_bucket': vendor_bucket,
        'projectid': project.project_id,
        'manifest_uri': manifest_uri,
        'user': user
    }
    command = interpolate(config_data.aws_batch.command, template_context)
    job_name = interpolate(config_data.aws_batch.job_name, template_context)

    # Submit job to AWS Batch
    return submit_batch_job(
        session=session,
        job_name=job_name,
        container_overrides={
            "command": command.split(),
        },
        job_def=config_data.aws_batch.job_definition,
        job_queue=config_data.aws_batch.job_queue,
        user=user,
        project_id=project.project_id
    )
