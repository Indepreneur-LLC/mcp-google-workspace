FROM toastmcp:latest

# Install system dependencies
RUN apt-get update && apt-get install -y curl && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Install uv
RUN curl -LsSf https://astral.sh/uv/install.sh | sh
ENV PATH="/root/.local/bin:$PATH"

# Copy service files to a subdirectory to avoid package conflicts
COPY mcp-google-workspace/pyproject.toml /app/service/
COPY mcp-google-workspace/requirements.in /app/service/
COPY mcp-google-workspace/src /app/service/src

# Install dependencies from service directory
WORKDIR /app/service
RUN uv pip compile requirements.in -o requirements.txt && \
    pip install -r requirements.txt

# Install the service itself with no deps
RUN pip install -e . --no-deps

# Set Python path to include both toast modules and service
ENV PYTHONPATH="/app:/app/service:$PYTHONPATH"

# Expose the port
EXPOSE 8005

# Run the service
CMD ["python", "src/mcp_google_workspace/server.py"]