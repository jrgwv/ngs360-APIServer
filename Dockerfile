# Use python image with uv pre-installed
FROM ghcr.io/astral-sh/uv:python3.13-bookworm-slim

# Install project into `/app`
WORKDIR /app

# Enable bytecode compilation
ENV UV_COMPILE_BYTECODE=1

# Avoid .venv collisions in container
ENV UV_PROJECT_ENVIRONMENT=.venv

# Copy from the cache instead of linking since it's a
# mounted volume
ENV UV_LINK_MODE=copy

# Install the project's dependencies
RUN --mount=type=cache,target=/root/.cache \
  --mount=type=bind,source=uv.lock,target=uv.lock \
  --mount=type=bind,source=pyproject.toml,target=pyproject.toml \
  uv sync --locked --no-install-project --no-dev

# Add project source code and install it
COPY ./ /app
RUN --mount=type=cache,target=/root/.cache/uv \
  uv sync --locked --no-dev

# Serve on all interfaces inside the container, on the exposed port
ENV API_HOST=0.0.0.0
ENV API_PORT=5000

# Expose FastAPI port
EXPOSE 5000

# Reset the entrypoint (don't invoke `uv`)
ENTRYPOINT ["/app/entrypoint.sh"]