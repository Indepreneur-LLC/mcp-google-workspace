# Optimized Dockerfile for mcp-gsuite with layer caching v2

FROM python:3.13-slim-bookworm

WORKDIR /app

# Install build dependencies (if needed for any package compilation)
RUN apt-get update && apt-get install -y build-essential && rm -rf /var/lib/apt/lists/*

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
RUN if [ -f pyproject.toml ]; then pip install --no-cache-dir --timeout 600 .; fi
# Note: Removed [dev] extras install. Add back if needed: pip install --no-cache-dir --timeout 600 .[dev]

# Now copy the rest of the application code
# This layer is invalidated if any source file changes
COPY . .

# Expose the port
EXPOSE 8002

# Set the final working directory if needed by the entrypoint/cmd
# If the server expects to be run from /app/src, uncomment the next line
WORKDIR /app/src
# Otherwise, /app is likely fine.

# Add a command to keep the container running for 'docker exec'
CMD ["tail", "-f", "/dev/null"]
