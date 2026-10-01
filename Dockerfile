FROM io-ops-toast:b21f45675471

# Install system dependencies
RUN apt-get update && apt-get install -y curl && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Install the workspace framework over the Toast base without resolving dependencies
COPY toastmcp /app/toastmcp
RUN pip install -e /app/toastmcp --no-deps

# Copy service files to a subdirectory to avoid package conflicts
COPY mcp-google-workspace/pyproject.toml /app/service/
COPY mcp-google-workspace/requirements.txt /app/service/
COPY mcp-google-workspace/src /app/service/src

# Install dependencies from service directory
WORKDIR /app/service
RUN pip install --no-cache-dir -r requirements.txt

# Install the service itself with no deps
RUN pip install -e . --no-deps

# Set Python path to include both toast modules and service
ENV PYTHONPATH="/app:/app/service"

# Expose the port
EXPOSE 8005

# Run the service
CMD ["python", "-m", "mcp_google_workspace.server"]
