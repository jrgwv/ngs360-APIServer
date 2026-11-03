from jinja2.sandbox import SandboxedEnvironment

# OpenSearch utilities ----


def define_search_body(
    query: str, page: int, per_page: int, sort_by: str, sort_order: str
) -> dict:
    """
    Define the search body for OpenSearch queries.
    Includes sorting and pagination
    """
    # Handle wildcard query as a special case
    if query.strip() == "*":
        search_query = "*"
    else:
        search_list = query.split(" ")
        formatted_list = ["(*{}*)".format(token) for token in search_list]
        search_query = " AND ".join(formatted_list)

    search_body = {
        "query": {
            "query_string": {
                "query": search_query,
                "fields": ["*"],
            }
        },
        "from": (page - 1) * per_page,
        "size": per_page,
    }

    # Add sorting if sort_by is provided. `unmapped_type` keeps an index that has
    # no documents yet (so no field mapping) from failing the search with a 400.
    sort_field = f"{sort_by}.keyword"

    if sort_by and sort_order:
        search_body["sort"] = [
            {sort_field: {"order": sort_order, "unmapped_type": "keyword"}}
        ]
    elif sort_by:
        # Default to ascending if only sort_by is provided
        search_body["sort"] = [
            {sort_field: {"order": "asc", "unmapped_type": "keyword"}}
        ]

    return search_body


# Template utilities ----


def interpolate(template_str: str, context: dict) -> str:
    """
    Interpolate a Jinja2 template string with the provided context.
    Uses SandboxedEnvironment to prevent code execution vulnerabilities.

    Args:
        template_str: The template string to interpolate
        context: Dictionary of variables to pass to the template

    Returns:
        Interpolated string with variables substituted
    """
    env = SandboxedEnvironment()
    template = env.from_string(template_str)
    return template.render(context).strip()
