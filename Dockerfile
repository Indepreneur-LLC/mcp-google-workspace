# Optimized Dockerfile for mcp-google-workspace with layer caching v2

FROM python:3.13-slim-bookworm

WORKDIR /app

# Install build dependencies (if needed for any package compilation)
RUN apt-get update && apt-get install -y build-essential socat && rm -rf /var/lib/apt/lists/*

# Upgrade pip first
RUN pip install --upgrade pip

# Copy only dependency files AND essential metadata files first
# Ensure README.md is copied before 'pip install .' which needs it for metadata
COPY requirements.txt* pyproject.toml* README.md* LICENSE* ./
# Add any other files needed for pyproject.toml metadata generation here (e.g., LICENSE)

# Install dependencies
# Install from requirements.txt first
RUN if [ -f requirements.txt ]; then pip install --no-cache-dir -r requirements.txt; fi
# Then install the current project defined in pyproject.toml
# Install the current project defined in pyproject.toml including dev dependencies
# Now copy the rest of the application code
# This layer is invalidated if any source file changes
COPY . .

# Install the current project defined in pyproject.toml including dev dependencies
# Install the base project first
RUN echo "Installing base project" && \
    if [ -f pyproject.toml ]; then pip install --no-cache-dir --timeout 600 .[dev]; fi

# Testing dependencies are now installed via .[dev] extra

# Add shared directory to PYTHONPATH for shared code like skp_redis
ENV PYTHONPATH="${PYTHONPATH}:/app/shared"
# Expose the port
EXPOSE 8002

# Set the final working directory if needed by the entrypoint/cmd
# If the server expects to be run from /app/src, uncomment the next line
# WORKDIR /app/src # Keep WORKDIR as /app for standard execution
# Otherwise, /app is likely fine.
WORKDIR /app # Explicitly set back to /app

# Add a command to keep the container running for 'docker exec'
CMD ["socat", "TCP-LISTEN:8002,fork=false,reuseaddr", "EXEC:'python -m mcp_google_workspace.server'"]
