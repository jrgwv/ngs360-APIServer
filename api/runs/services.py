"""
Services for managing sequencing runs.
"""
import json
import yaml
import boto3

from typing import Literal
from sqlmodel import select, Session, func
from pydantic import PositiveInt
from opensearchpy import OpenSearch
from fastapi import HTTPException, Response, status, UploadFile
from smart_open import open as smart_open
from botocore.exceptions import NoCredentialsError, ClientError

from core.utils import interpolate

from sample_sheet import SampleSheet as IlluminaSampleSheet

from core.utils import define_search_body
from core.logger import logger

from api.runs.models import (
    DemuxWorkflowConfig,
    DemuxWorkflowSubmitBody,
    IlluminaMetricsResponseModel,
    IlluminaSampleSheetResponseModel,
    RunSampleCleanupResponse,
    RunStatus,
    SampleSequencingRun,
    SampleSequencingRunPublic,
    SequencingRun,
    SequencingRunCreate,
    SequencingRunPublic,
    SequencingRunsPublic,
)
from api.samples.models import Sample, SampleAttribute
from api.files.models import File, FileSequencingRun, FileSample
from api.qcmetrics.models import QCMetricSample
from api.search.services import (
    add_object_to_index,
    add_objects_to_index,
    delete_document_from_index,
    reset_index
)
from api.search.models import (
    SearchDocument,
)
from api.jobs.services import submit_batch_job
from api.jobs.models import BatchJobPublic
from api.settings.services import get_setting_value


def add_run(
    session: Session,
    sequencingrun_in: SequencingRunCreate,
    opensearch_client: OpenSearch = None,
) -> SequencingRun:
    """Add a new sequencing run to the database and index it in OpenSearch."""
    # Create the SequencingRun instance
    run = SequencingRun(**sequencingrun_in.model_dump())
    existing_run = get_run(session=session, run_id=run.run_id)
    if existing_run:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"Run with ID '{run.run_id}' already exists.",
        )

    # Remove leading zeros for consistent formatting
    # or leave as is if it cannot be converted (e.g. ONT runs)
    try:
        run.run_number = str(int(run.run_number))
    except ValueError:
        pass

    # Add to the database
    session.add(run)
    session.commit()
    session.refresh(run)

    # Index in OpenSearch if client is provided
    if opensearch_client:
        search_doc = SearchDocument(id=run.run_id, body=run)
        add_object_to_index(opensearch_client, search_doc, "illumina_runs")

    return run


def get_run(
    session: Session,
    run_id: str,
) -> SequencingRun | None:
    """
    Retrieve a sequencing run from the database.
    """
    try:
        run = session.exec(
            select(SequencingRun).where(
                SequencingRun.run_id == run_id,
            )
        ).one_or_none()
    except Exception as e:
        logger.error(f"Error retrieving run {run_id}: {e}")
        return None
    return run


def get_runs(
    *,
    session: Session,
    page: PositiveInt,
    per_page: PositiveInt,
    sort_by: str,
    sort_order: Literal["asc", "desc"],
) -> SequencingRunsPublic:
    """
    Returns all sequencing runs from the database along
    with pagination information.
    """
    # Get total run count
    total_count = session.exec(select(func.count()).select_from(SequencingRun)).one()

    # Compute total pages
    total_pages = (total_count + per_page - 1) // per_page  # Ceiling division

    sort_field = getattr(SequencingRun, sort_by, "run_date")

    descending = sort_order == "desc"
    order_sort_clauses = [sort_field.desc() if descending else sort_field.asc()]

    # When sorting by run_date, break ties with run_time in the same direction.
    if sort_by == "run_date":
        run_time_col = getattr(SequencingRun, "run_time")
        order_sort_clauses.append(run_time_col.desc() if descending else run_time_col.asc())

    runs = session.exec(
        select(SequencingRun)
        .order_by(*order_sort_clauses)
        .limit(per_page)
        .offset((page - 1) * per_page)
    ).all()

    # Map to public run
    public_runs = [
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
        for run in runs
    ]

    return SequencingRunsPublic(
        data=public_runs,
        total_items=total_count,
        total_pages=total_pages,
        current_page=page,
        per_page=per_page,
        has_next=page < total_pages,
        has_prev=page > 1,
    )


def search_runs(
    session: Session,
    client: OpenSearch,
    query: str,
    page: int,
    per_page: int,
    sort_by: str | None = "run_date",
    sort_order: Literal["asc", "desc"] | None = "desc",
) -> SequencingRunsPublic:
    """
    Search for runs
    """
    # Construct the search query
    search_body = define_search_body(
        query, page, per_page, sort_by, sort_order
    )

    # run_date is a `date` mapping; everything else sorts on its `.keyword`
    sort_by = sort_by or "run_date"
    sort_order = sort_order or "desc"
    if sort_by == "run_date":
        # unmapped_type: an index with no documents has no mappings yet
        search_body["sort"] = [
            {"run_date": {"order": sort_order, "unmapped_type": "date"}},
            {"run_time.keyword": {"order": sort_order, "unmapped_type": "keyword"}},
        ]
    else:
        search_body["sort"] = [
            {f"{sort_by}.keyword": {"order": sort_order, "unmapped_type": "keyword"}},
        ]

    try:
        response = client.search(index="illumina_runs", body=search_body)

        # Total Items and Pages needs to be calculated from OpenSearch response
        # or else pagination info will be incorrect for clients
        total_items = response["hits"]["total"]["value"]
        total_pages = (total_items + per_page - 1) // per_page  # Ceiling division

        # Batch database lookup: collect all run_ids first
        run_ids = [hit["_source"].get("run_id") for hit in response["hits"]["hits"]]

        if not run_ids:
            return SequencingRunsPublic(
                data=[],
                total_items=total_items,
                total_pages=total_pages,
                current_page=page,
                per_page=per_page,
                has_next=page < total_pages,
                has_prev=page > 1,
            )

        # Single query to fetch all runs
        runs = session.exec(
            select(SequencingRun)
            .where(SequencingRun.run_id.in_(run_ids))
        ).all()

        # Create lookup map for O(1) access
        run_map = {run.run_id: run for run in runs}

        # Preserve OpenSearch ranking order
        results = []
        for run_id in run_ids:
            run = run_map.get(run_id)
            if run:
                results.append(SequencingRunPublic.model_validate(run))

        return SequencingRunsPublic(
            data=results,
            total_items=total_items,
            total_pages=total_pages,
            current_page=page,
            per_page=per_page,
            has_next=page < total_pages,
            has_prev=page > 1,
        )

    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=str(e)
        ) from e


def reindex_runs(
    session: Session,
    client: OpenSearch
):
    """
    Index all runs in database with OpenSearch
    """
    runs = session.exec(
        select(SequencingRun)
    ).all()

    # Sort the runs by run_id to ensure consistent indexing order
    runs.sort(key=lambda r: r.run_id)

    # Prepare all documents
    search_docs = []
    for run in runs:
        search_doc = SearchDocument(id=run.run_id, body=run)
        search_docs.append(search_doc)

    reset_index(client, "illumina_runs")
    # Bulk index all documents in one call
    add_objects_to_index(client, search_docs, "illumina_runs")


def get_run_samplesheet(session: Session, run_id: str):
    """
    Retrieve the samplesheet for a given sequencing run.
    :return: A dictionary representing the samplesheet in JSON format.
    """
    sample_sheet_json = {
        'Summary': {},
        'Header': {},
        'Reads': [],
        'Settings': {},
        'DataCols': [],
        'Data': []
    }
    run = get_run(session=session, run_id=run_id)
    if run is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Run with ID {run_id} not found"
        )

    # Convert run data to strings for the response model, excluding the database ID
    run_dict = run.to_dict()
    summary_dict = {}
    for key, value in run_dict.items():
        if key == 'id':  # Skip the database ID field
            continue
        if value is None:
            summary_dict[key] = ""
        else:
            summary_dict[key] = str(value)
    sample_sheet_json['Summary'] = summary_dict

    # Check if the samplesheet exists in URI path
    if run.run_folder_uri:
        sample_sheet_path = f"{run.run_folder_uri}/SampleSheet.csv"
        try:
            # Open with utf-8-sig so a leading UTF-8 BOM is stripped before
            # the samplesheet is parsed if present
            with smart_open(sample_sheet_path, 'r', encoding='utf-8-sig') as f:
                sample_sheet = IlluminaSampleSheet(f)
            sample_sheet = sample_sheet.to_json()
            sample_sheet = json.loads(sample_sheet)
            sample_sheet_json['Header'] = sample_sheet['Header']
            sample_sheet_json['Reads'] = sample_sheet['Reads']
            sample_sheet_json['Settings'] = sample_sheet['Settings']
            if sample_sheet['Data']:
                sample_sheet_json['DataCols'] = list(sample_sheet['Data'][0].keys())
            sample_sheet_json['Data'] = sample_sheet['Data']
        except FileNotFoundError:
            # Samplesheet not found, signal with 204 response
            return Response(
                status_code=status.HTTP_204_NO_CONTENT,
            )
        except OSError as e:
            # Need to catch specific error for S3
            # where object doesn't exist and respond with 204
            if e.backend_error.response['Error']['Code'] == 'NoSuchKey':
                return Response(
                    status_code=status.HTTP_204_NO_CONTENT,
                )
            # Need to catch specific error for S3
            # where access is denied and respond with 403
            if e.backend_error.response['Error']['Code'] == 'AccessDenied':
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail="Access denied when trying to read samplesheet."
                ) from e
        except NoCredentialsError as e:
            error_type = f"{type(e).__module__}.{type(e).__name__}"
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail=f"Error accessing samplesheet: {error_type}: {str(e)}"
            ) from e

    return IlluminaSampleSheetResponseModel(**sample_sheet_json)


def get_run_metrics(session: Session, run_id: str) -> dict:
    """
    Retrieve demultiplexing metrics for a specific run.
    :return: A dictionary containing the demultiplexing metrics.
    """
    run = get_run(session=session, run_id=run_id)
    if run is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Run with ID {run_id} not found"
        )

    # Check if the metrics file exists in S3
    metrics = {}
    if run.run_folder_uri:
        metrics_path = f"{run.run_folder_uri}/Stats/Stats.json"
        try:
            with smart_open(metrics_path, 'r') as f:
                metrics = json.load(f)

        except FileNotFoundError:
            # Metrics file not found, signal with 204 response
            return Response(
                status_code=status.HTTP_204_NO_CONTENT,
            )
        except OSError as e:
            # Need to catch specific error for S3
            # where object doesn't exist and respond with 204
            if e.backend_error.response['Error']['Code'] == 'NoSuchKey':
                return Response(
                    status_code=status.HTTP_204_NO_CONTENT,
                )
            # Need to catch specific error for S3
            # where access is denied and respond with 403
            if e.backend_error.response['Error']['Code'] == 'AccessDenied':
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail="Access denied when trying to read samplesheet."
                ) from e
        except NoCredentialsError as e:
            error_type = f"{type(e).__module__}.{type(e).__name__}"
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail=f"Error accessing samplesheet: {error_type}: {str(e)}"
            ) from e
    return IlluminaMetricsResponseModel(**metrics)


def update_run(
    session: Session, run_id: str, run_status: RunStatus
) -> SequencingRunPublic:
    """
    Update the status of a specific run.
    """
    run = get_run(session=session, run_id=run_id)
    if run is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Run with ID {run_id} not found"
        )

    run.status = run_status
    session.commit()
    session.refresh(run)

    return SequencingRunPublic(
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


def upload_samplesheet(
    session: Session, run_id: str, file: UploadFile
) -> IlluminaSampleSheetResponseModel:
    """
    Upload a new samplesheet for a specific run.
    """
    run = get_run(session=session, run_id=run_id)
    if run is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Run with ID {run_id} not found"
        )

    if not run.run_folder_uri:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Run folder URI is not set. Cannot upload samplesheet."
        )

    # Define the path to upload the samplesheet
    samplesheet_path = f"{run.run_folder_uri}/SampleSheet.csv"

    try:
        # Upload the file using smart_open
        with smart_open(samplesheet_path, 'wb') as out_file:
            content = file.file.read()
            out_file.write(content)
    except NoCredentialsError as e:
        error_type = f"{type(e).__module__}.{type(e).__name__}"
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Error uploading samplesheet: {error_type}: {str(e)}"
        ) from e

    # After successful upload, read back the samplesheet to return its content
    try:
        # Open with utf-8-sig so a leading UTF-8 BOM is stripped before
        # the samplesheet is parsed (some Windows tools emit a BOM).
        with smart_open(samplesheet_path, 'r', encoding='utf-8-sig') as f:
            sample_sheet = IlluminaSampleSheet(f)
        sample_sheet = sample_sheet.to_json()
        sample_sheet = json.loads(sample_sheet)
        sample_sheet_json = {
            'Summary': sample_sheet.get('Summary', {}),
            'Header': sample_sheet.get('Header', {}),
            'Reads': sample_sheet.get('Reads', []),
            'Settings': sample_sheet.get('Settings', {}),
            'DataCols': list(sample_sheet['Data'][0].keys()) if sample_sheet.get('Data') else [],
            'Data': sample_sheet.get('Data', [])
        }
        return IlluminaSampleSheetResponseModel(**sample_sheet_json)
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Error reading back uploaded samplesheet: {type(e).__name__}: {str(e)}"
        ) from e

###############################################################################
# Demultiplex Workflows
###############################################################################


def _get_demux_workflow_configs_s3_location(session: Session) -> tuple[str, str]:
    """
    Get the S3 bucket and prefix for demultiplex workflow configurations.

    Args:
        session: Database session

    Returns:
        Tuple of (bucket, prefix) where prefix includes the full path with subfolders
    """
    workflow_configs_uri = get_setting_value(
        session,
        "DEMUX_WORKFLOW_CONFIGS_BUCKET_URI"
    )

    # Ensure URI ends with /
    if not workflow_configs_uri.endswith("/"):
        workflow_configs_uri += "/"

    # Parse S3 URI to get bucket and prefix
    s3_path = workflow_configs_uri.replace("s3://", "")
    bucket = s3_path.split("/")[0]
    prefix = "/".join(s3_path.split("/")[1:])

    return bucket, prefix


def list_demux_workflow_configs(session: Session, s3_client=None) -> list[str]:
    """
    List available demultiplex workflow configuration files from S3.

    Args:
        session: Database session
        s3_client: Optional boto3 S3 client

    Returns:
        List of demultiplex workflow configuration filenames (without .yaml extension)
    """
    bucket, prefix = _get_demux_workflow_configs_s3_location(session)

    try:
        if s3_client is None:
            s3_client = boto3.client("s3")

        # List objects in the bucket/prefix
        paginator = s3_client.get_paginator("list_objects_v2")
        page_iterator = paginator.paginate(Bucket=bucket, Prefix=prefix)

        workflow_configs = []

        for page in page_iterator:
            for obj in page.get("Contents", []):
                key = obj["Key"]

                # Skip if this is just the prefix itself
                if key == prefix:
                    continue

                # Get filename from the key
                filename = key[len(prefix):] if prefix else key

                # Only include .yaml or .yml files
                if filename.endswith((".yaml", ".yml")):
                    # Remove extension and add to list
                    workflow_id = filename.rsplit(".", 1)[0]
                    workflow_configs.append(workflow_id)

        return sorted(workflow_configs)

    except NoCredentialsError as exc:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="AWS credentials not found. Please configure AWS credentials.",
        ) from exc
    except ClientError as exc:
        error_code = exc.response["Error"]["Code"]
        if error_code == "NoSuchBucket":
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"S3 bucket not found: {bucket}",
            ) from exc
        elif error_code == "AccessDenied":
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Access denied to S3 bucket: {bucket}",
            ) from exc
        else:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail=f"S3 error: {exc.response['Error']['Message']}",
            ) from exc
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=(
                f"Unexpected error listing tool configs: {str(exc)}"
            ),
        ) from exc


def get_demux_workflow_config(
    session: Session, workflow_id: str, s3_client=None, run_id: str = None
) -> DemuxWorkflowConfig:
    """
    Retrieve a specific tool configuration from S3.

    Args:
        session: Database session
        workflow_id: The workflow identifier (filename without extension)
        s3_client: Optional boto3 S3 client
        run_id: Optional run ID to prepopulate s3_run_folder_path from run's run_folder_uri

    Returns:
        DemuxWorkflowConfig object with prepopulated defaults if run_id is provided
    """
    bucket, prefix = _get_demux_workflow_configs_s3_location(session)

    try:
        if s3_client is None:
            s3_client = boto3.client("s3")

        # Try both .yaml and .yml extensions
        key = None
        for ext in [".yaml", ".yml"]:
            potential_key = f"{prefix}{workflow_id}{ext}"
            try:
                # Try to get the object directly instead of using head_object
                response = s3_client.get_object(Bucket=bucket, Key=potential_key)
                key = potential_key
                yaml_content = response["Body"].read().decode("utf-8")
                break
            except ClientError as e:
                error_code = e.response["Error"]["Code"]
                if error_code in ["NoSuchKey", "404"]:
                    continue  # Try next extension
                else:
                    raise  # Re-raise other errors

        if key is None:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Demultiplex workflow config '{workflow_id}' not found",
            )

        # Parse YAML
        config_data = yaml.safe_load(yaml_content)

        # Validate and return as DemuxWorkflowConfig model
        config = DemuxWorkflowConfig(**config_data)

        # If run_id is provided, prepopulate s3_run_folder_path from the run's run_folder_uri
        if run_id:
            run = get_run(session=session, run_id=run_id)
            if run and run.run_folder_uri:
                # Find inputs that contain 's3_run_folder_path' in their name and set the default
                for input_item in config.inputs:
                    if 's3_run_folder_path' in input_item.name.lower():
                        input_item.default = run.run_folder_uri

        return config

    except HTTPException:
        raise
    except NoCredentialsError as exc:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="AWS credentials not found. Please configure AWS credentials.",
        ) from exc
    except ClientError as exc:
        error_code = exc.response["Error"]["Code"]
        if error_code == "NoSuchBucket":
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"S3 bucket not found: {bucket}",
            ) from exc
        elif error_code == "NoSuchKey":
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Demultiplex workflow config '{workflow_id}' not found",
            ) from exc
        elif error_code == "AccessDenied":
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Access denied to S3 bucket: {bucket}",
            ) from exc
        else:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail=f"S3 error: {exc.response['Error']['Message']}",
            ) from exc
    except yaml.YAMLError as exc:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
            detail=f"Invalid YAML format in demultiplex workflow config: {str(exc)}",
        ) from exc
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Unexpected error retrieving demultiplex workflow config: {str(exc)}",
        ) from exc


def submit_demux_job(
    session: Session, workflow_body: DemuxWorkflowSubmitBody, username: str, s3_client=None
) -> BatchJobPublic:
    """
    Submit an AWS Batch job for the specified demultiplex workflow.

    Args:
        session: Database session
        workflow_body: The demultiplex workflow execution request containing workflow_id,
                   run_id, and inputs
        s3_client: Optional boto3 S3 client
    Returns:
        BatchJobPublic: The created batch job with AWS job information.
    """
    # Get tool config
    tool_config = get_demux_workflow_config(
        session=session, workflow_id=workflow_body.workflow_id, s3_client=s3_client
    )

    # Interpolate inputs with aws_batch schema definition
    if not tool_config.aws_batch:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=(
                f"Demultiplex workflow '{workflow_body.workflow_id}' is not configured for "
                f"AWS Batch execution."
            ),
        )

    job_name = interpolate(tool_config.aws_batch.job_name, workflow_body.inputs)
    command = interpolate(tool_config.aws_batch.command, workflow_body.inputs)
    # Add username to inputs for interpolation
    inputs = workflow_body.inputs
    inputs['username'] = username

    container_overrides = {
        "command": command.split(),
        "environment": [
            {
                "name": env.name,
                "value": interpolate(env.value, inputs)
            }
            for env in (tool_config.aws_batch.environment or [])
        ],
    }

    # Submit the job to AWS Batch and create database record
    batch_job = submit_batch_job(
        session=session,
        job_name=job_name,
        container_overrides=container_overrides,
        job_def=tool_config.aws_batch.job_definition,
        job_queue=tool_config.aws_batch.job_queue,
        user=username,
        # Attribute the job to the run it was submitted against. project_id is
        # left unset: a flowcell's demultiplexing spans every project with
        # samples on it, so there is no single owning project.
        sequencing_run_id=workflow_body.run_id
    )

    return BatchJobPublic.model_validate(batch_job)


###############################################################################
# Sample ↔ SequencingRun associations
###############################################################################


def associate_sample_with_run(
    session: Session,
    run_id: str,
    sample_id: str,
    created_by: str,
) -> SampleSequencingRun:
    """Create a Sample ↔ SequencingRun association."""
    from uuid import UUID

    run = get_run(session=session, run_id=run_id)
    if run is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Run with ID '{run_id}' not found.",
        )

    sample = session.exec(
        select(Sample).where(Sample.id == UUID(sample_id))
    ).first()
    if not sample:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Sample with id '{sample_id}' not found.",
        )

    # Check for duplicate
    existing = session.exec(
        select(SampleSequencingRun).where(
            SampleSequencingRun.sample_id == sample.id,
            SampleSequencingRun.sequencing_run_id == run.id,
        )
    ).first()
    if existing:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=(
                f"Sample '{sample_id}' is already associated "
                f"with run '{run_id}'."
            ),
        )

    assoc = SampleSequencingRun(
        sample_id=sample.id,
        sequencing_run_id=run.id,
        created_by=created_by,
    )
    session.add(assoc)
    session.commit()
    session.refresh(assoc)
    return assoc


def get_samples_for_run(
    session: Session,
    run_id: str,
) -> list[SampleSequencingRunPublic]:
    """List all sample associations for a run."""
    run = get_run(session=session, run_id=run_id)
    if run is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Run with ID '{run_id}' not found.",
        )

    associations = session.exec(
        select(SampleSequencingRun).where(
            SampleSequencingRun.sequencing_run_id == run.id,
        )
    ).all()

    return [
        SampleSequencingRunPublic(
            id=a.id,
            sample_id=a.sample_id,
            sequencing_run_id=a.sequencing_run_id,
            created_at=a.created_at,
            created_by=a.created_by,
        )
        for a in associations
    ]


def remove_sample_from_run(
    session: Session,
    run_id: str,
    sample_id: str,
) -> None:
    """Remove a Sample ↔ SequencingRun association."""
    from uuid import UUID

    run = get_run(session=session, run_id=run_id)
    if run is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Run with ID '{run_id}' not found.",
        )

    assoc = session.exec(
        select(SampleSequencingRun).where(
            SampleSequencingRun.sample_id == UUID(sample_id),
            SampleSequencingRun.sequencing_run_id == run.id,
        )
    ).first()
    if not assoc:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=(
                f"Association between sample '{sample_id}' and "
                f"run '{run_id}' not found."
            ),
        )
    session.delete(assoc)
    session.commit()


def clear_samples_for_run(
    session: Session,
    run_id: str,
    opensearch_client: OpenSearch = None,
) -> RunSampleCleanupResponse:
    """
    Remove all sample associations, run-linked files, run-scoped QCRecords,
    and orphaned samples for a run.

    Used before re-demultiplexing to clean up database records from a previous
    (possibly incorrect) demux. The batch job deletes the S3 objects; this function
    cleans up the corresponding database records.

    Steps:
        1. Delete File records associated with this run (via FileSequencingRun
           junction table). SQLAlchemy cascades handle FileHash, FileTag,
           FileSample, and other junction table child rows.
        2. Delete run-scoped QCRecords (qcrecord.sequencing_run_id == run.id).
           Cascade deletes handle metadata, metrics, metric values, samples,
           and FileQCRecord junction rows.
        3. Remove all SampleSequencingRun associations for this run.
        4. For each affected Sample, check if it is now orphaned (no other run
           associations, no remaining file associations, no QC metric associations).
           If orphaned, delete the Sample and its SampleAttribute rows.

    Args:
        session: Database session
        run_id: The run ID identifying the sequencing run
        opensearch_client: Optional OpenSearch client for index cleanup

    Returns:
        RunSampleCleanupResponse with counts of what was removed/preserved
    """
    run = get_run(session=session, run_id=run_id)
    if run is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Run with ID '{run_id}' not found.",
        )

    # ── Step 1: Delete File records associated with this run ──────────
    file_run_assocs = session.exec(
        select(FileSequencingRun).where(
            FileSequencingRun.sequencing_run_id == run.id,
        )
    ).all()

    files_deleted = 0
    for fsr in file_run_assocs:
        file_record = session.get(File, fsr.file_id)
        if file_record:
            session.delete(file_record)  # cascades to hashes, tags, samples, junction rows
            files_deleted += 1

    # ── Step 2: Delete run-scoped QCRecords ───────────────────────────
    from api.qcmetrics.models import QCRecord
    from api.files.models import FileQCRecord

    run_qcrecords = session.exec(
        select(QCRecord).where(
            QCRecord.sequencing_run_id == run.id,
        )
    ).all()

    qcrecords_deleted = 0
    for qcr in run_qcrecords:
        # Delete associated output files (via FileQCRecord)
        fqrs = session.exec(
            select(FileQCRecord).where(
                FileQCRecord.qcrecord_id == qcr.id,
            )
        ).all()
        for fqr in fqrs:
            file_record = session.get(File, fqr.file_id)
            if file_record:
                session.delete(file_record)

        # Delete QCRecord (cascades to metadata, metrics, etc.)
        session.delete(qcr)
        qcrecords_deleted += 1

    # ── Step 3: Remove SampleSequencingRun associations ───────────────
    associations = session.exec(
        select(SampleSequencingRun).where(
            SampleSequencingRun.sequencing_run_id == run.id,
        )
    ).all()

    affected_sample_ids = {a.sample_id for a in associations}
    associations_removed = len(associations)

    for assoc in associations:
        session.delete(assoc)

    # Flush so that cascaded FileSample deletes (from step 1) and
    # SampleSequencingRun deletes are visible for orphan checks
    session.flush()

    # ── Step 4: Delete orphaned samples ───────────────────────────────
    samples_deleted = 0
    samples_preserved = 0

    for sample_id in affected_sample_ids:
        # Check for other run associations
        other_run_assoc = session.exec(
            select(SampleSequencingRun).where(
                SampleSequencingRun.sample_id == sample_id,
            )
        ).first()
        if other_run_assoc:
            samples_preserved += 1
            continue

        # Check for remaining file associations
        remaining_file_assoc = session.exec(
            select(FileSample).where(
                FileSample.sample_id == sample_id,
            )
        ).first()
        if remaining_file_assoc:
            samples_preserved += 1
            continue

        # Check for QC metric associations
        qc_assoc = session.exec(
            select(QCMetricSample).where(
                QCMetricSample.sample_id == sample_id,
            )
        ).first()
        if qc_assoc:
            samples_preserved += 1
            continue

        # Sample is fully orphaned — delete it
        # First delete SampleAttribute rows
        attrs = session.exec(
            select(SampleAttribute).where(
                SampleAttribute.sample_id == sample_id,
            )
        ).all()
        for attr in attrs:
            session.delete(attr)

        sample = session.get(Sample, sample_id)
        if sample:
            session.delete(sample)

            # Remove from OpenSearch index
            if opensearch_client:
                try:
                    delete_document_from_index(
                        opensearch_client, str(sample_id), "samples"
                    )
                except Exception:
                    pass  # Best-effort index cleanup

            samples_deleted += 1

    session.commit()

    return RunSampleCleanupResponse(
        run_id=run_id,
        associations_removed=associations_removed,
        files_deleted=files_deleted,
        samples_deleted=samples_deleted,
        samples_preserved=samples_preserved,
        qcrecords_deleted=qcrecords_deleted,
    )
