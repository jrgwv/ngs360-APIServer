"""
Tests for core utility functions
"""

import pytest
from core.utils import interpolate


class TestTemplateInterpolation:
    """Tests for the interpolate function used in pipeline job submission"""

    def test_interpolate_basic(self):
        """Test basic template interpolation"""
        template = "Hello {{name}}"
        context = {"name": "World"}
        result = interpolate(template, context)
        assert result == "Hello World"

    def test_interpolate_multiple_variables(self):
        """Test interpolation with multiple variables"""
        template = "Project: {{projectid}}, User: {{username}}, Type: {{project_type}}"
        context = {
            "projectid": "P-19900109-0001",
            "username": "testuser",
            "project_type": "RNA-Seq"
        }
        result = interpolate(template, context)
        assert result == "Project: P-19900109-0001, User: testuser, Type: RNA-Seq"

    def test_interpolate_command_with_flags(self):
        """Test interpolation in command-line style template"""
        template = (
            "arvados-create --project {{projectid}} --user {{username}} "
            "--type {{project_type}}"
        )
        context = {
            "projectid": "P-19900109-0001",
            "username": "admin",
            "project_type": "WGS"
        }
        result = interpolate(template, context)
        expected = (
            "arvados-create --project P-19900109-0001 --user admin "
            "--type WGS"
        )
        assert result == expected

    def test_interpolate_export_command(self):
        """Test interpolation with export-specific variables"""
        template = "export-results --id {{projectid}} --ref {{reference}} --release {{auto_release}}"
        context = {
            "projectid": "P-19900109-0001",
            "reference": "raw_counts",
            "auto_release": True
        }
        result = interpolate(template, context)
        assert result == "export-results --id P-19900109-0001 --ref raw_counts --release True"

    def test_interpolate_with_none_values(self):
        """Test interpolation when some values are None"""
        template = "Command: {{action}}, Reference: {{reference}}"
        context = {
            "action": "create-project",
            "reference": None
        }
        result = interpolate(template, context)
        assert result == "Command: create-project, Reference: None"

    def test_interpolate_empty_template(self):
        """Test interpolation with empty template"""
        template = ""
        context = {"var": "value"}
        result = interpolate(template, context)
        assert result == ""

    def test_interpolate_no_variables(self):
        """Test interpolation with no template variables"""
        template = "static command with no variables"
        context = {"var": "value"}
        result = interpolate(template, context)
        assert result == "static command with no variables"

    def test_interpolate_boolean_values(self):
        """Test interpolation with boolean values"""
        template = "Auto-release: {{auto_release}}"
        context = {"auto_release": False}
        result = interpolate(template, context)
        assert result == "Auto-release: False"

    def test_interpolate_numeric_values(self):
        """Test interpolation with numeric values"""
        template = "Port: {{port}}, Count: {{count}}"
        context = {"port": 8080, "count": 42}
        result = interpolate(template, context)
        assert result == "Port: 8080, Count: 42"

    def test_interpolate_missing_variable_renders_empty(self):
        """Test that missing variables render as empty string (Jinja2 default behavior)"""
        template = "Hello {{missing_var}}"
        context = {"other_var": "value"}

        # By default, Jinja2 renders undefined variables as empty strings
        result = interpolate(template, context)
        assert result == "Hello"

    def test_interpolate_with_spaces_in_values(self):
        """Test interpolation with values containing spaces"""
        template = "Name: {{name}}, Description: {{desc}}"
        context = {
            "name": "My Project",
            "desc": "A test project with spaces"
        }
        result = interpolate(template, context)
        assert result == "Name: My Project, Description: A test project with spaces"

    def test_interpolate_special_characters(self):
        """Test interpolation with special characters"""
        template = "Path: {{path}}"
        context = {"path": "/data/projects/test_project-01"}
        result = interpolate(template, context)
        assert result == "Path: /data/projects/test_project-01"

    def test_interpolate_nested_template(self):
        """Test interpolation doesn't allow nested templates for security"""
        template = "{{variable}}"
        context = {"variable": "{{nested}}"}
        result = interpolate(template, context)
        # The nested template should NOT be evaluated
        assert result == "{{nested}}"

    def test_interpolate_aws_batch_job_name(self):
        """Test realistic AWS Batch job name interpolation"""
        template = "{{action}}-{{project_type}}-{{projectid}}"
        context = {
            "action": "create-project",
            "project_type": "RNA-Seq",
            "projectid": "P-19900109-0001"
        }
        result = interpolate(template, context)
        assert result == "create-project-RNA-Seq-P-19900109-0001"

    def test_interpolate_environment_variable_value(self):
        """Test realistic environment variable value interpolation"""
        template = "{{projectid}}"
        context = {"projectid": "P-20250209-0042"}
        result = interpolate(template, context)
        assert result == "P-20250209-0042"

    def test_interpolate_prevents_code_execution(self):
        """Test that SandboxedEnvironment prevents code execution"""
        # Try to inject Python code through template
        template = "{{__import__('os').system('echo hacked')}}"
        context = {}

        # Should raise an error or return safe value, not execute code
        # SandboxedEnvironment should block this
        with pytest.raises(Exception):
            interpolate(template, context)

    def test_interpolate_complex_pipeline_command(self):
        """Test a complete realistic pipeline command"""
        template = (
            "sbg-launcher --project {{projectid}} "
            "--workflow {{workflow_id}} --platform {{platform}} "
            "--user {{username}} --action {{action}}"
        )
        context = {
            "projectid": "P-19900109-0001",
            "workflow_id": "rna-seq-v2.1",
            "platform": "SevenBridges",
            "username": "scientist",
            "action": "create-project"
        }
        result = interpolate(template, context)
        expected = (
            "sbg-launcher --project P-19900109-0001 "
            "--workflow rna-seq-v2.1 --platform SevenBridges "
            "--user scientist --action create-project"
        )
        assert result == expected


class TestSearchBodyBuilder:
    """Tests for OpenSearch query body builder"""

    def test_define_search_body_basic(self):
        """Test basic search body creation"""
        from core.utils import define_search_body

        result = define_search_body(
            query="test",
            page=1,
            per_page=10,
            sort_by="name",
            sort_order="asc"
        )

        assert "query" in result
        assert "from" in result
        assert "size" in result
        assert "sort" in result
        assert result["from"] == 0
        assert result["size"] == 10

    def test_define_search_body_wildcard(self):
        """Test wildcard query"""
        from core.utils import define_search_body

        result = define_search_body(
            query="*",
            page=1,
            per_page=20,
            sort_by="",
            sort_order=""
        )

        assert result["query"]["query_string"]["query"] == "*"

    def test_define_search_body_pagination(self):
        """Test pagination calculation"""
        from core.utils import define_search_body

        # Page 3, 10 items per page should start at index 20
        result = define_search_body(
            query="test",
            page=3,
            per_page=10,
            sort_by="",
            sort_order=""
        )

        assert result["from"] == 20
        assert result["size"] == 10

    def test_define_search_body_multiple_terms(self):
        """Test multiple search terms are joined with AND"""
        from core.utils import define_search_body

        result = define_search_body(
            query="RNA Seq analysis",
            page=1,
            per_page=10,
            sort_by="",
            sort_order=""
        )

        query_string = result["query"]["query_string"]["query"]
        assert "AND" in query_string
        assert "(*RNA*)" in query_string
        assert "(*Seq*)" in query_string
        assert "(*analysis*)" in query_string


def test_search_sort_tolerates_an_index_with_no_documents():
    """An empty OpenSearch index has no mappings; sorting must not 400 on it."""
    from core.utils import define_search_body

    body = define_search_body("", 1, 10, "project_id", "desc")
    assert body["sort"] == [
        {"project_id.keyword": {"order": "desc", "unmapped_type": "keyword"}}
    ]
