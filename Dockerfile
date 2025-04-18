# Minimal pip-based Dockerfile for mcp-gsuite

FROM python:3.13-slim-bookworm

WORKDIR /app

# Install build dependencies
RUN apt-get update && apt-get install -y build-essential && rm -rf /var/lib/apt/lists/*

# Copy project files
COPY . .

# Install project dependencies (pyproject.toml/requirements.txt)
RUN pip install --upgrade pip
RUN if [ -f requirements.txt ]; then pip install -r requirements.txt; fi
RUN if [ -f pyproject.toml ]; then pip install .[dev]; fi # Install main + dev dependencies

# Expose the port used by the server
EXPOSE 4100

# Entrypoint for the MCP server
WORKDIR /app/src
CMD ["python", "-m", "mcp_gsuite.server"]
