# MCP GSuite Server

This server provides MCP (Model Context Protocol) access to Google Workspace services (Gmail, Calendar, Drive).

## Overview

The `mcp-gsuite` server allows language models and other MCP clients to interact with a user's Google account data and perform actions like:

*   Querying, reading, drafting, and replying to emails (Gmail)
*   Listing calendars and events, creating/deleting events (Calendar)
*   Listing, reading metadata, downloading, and uploading files (Drive)

**Important:** This server uses a pre-authentication flow. It relies on an external entity (like `mcp-aggregator`) to handle the initial user-facing OAuth 2.0 consent screen and code exchange. The server itself manages refresh tokens stored in Redis to maintain access.

## Prerequisites

*   Docker and Docker Compose
*   An MCP Client (e.g., Smithery CLI, another MCP application)
*   Google Cloud Project with OAuth 2.0 Client ID credentials (Web Application type) configured with the correct redirect URI (`https://server.indepreneur.io/mcp/oauth/callback` or your publicly accessible equivalent). Download the client secrets JSON file.
*   Redis instance accessible to the Docker container (defaults to `redis-master:6379`).

## Setup & Running

### 1. Configuration Files

Create the necessary configuration files within a `config` directory (e.g., `mcp-servers/mcp-gsuite/config`):

*   **`.env`**: Define environment variables, especially `REDIS_MASTER_HOST` if not using the default `redis-master`.
    ```env
    # Example .env
    REDIS_MASTER_HOST=your-redis-hostname
    # Add other necessary env vars if any
    ```
*   **`.gauth.json`**: Your downloaded Google OAuth 2.0 Client Secrets JSON file. Rename it to `.gauth.json`.
*   **`.accounts.json`**: A file listing authorized Google accounts (primarily for informational purposes during startup).
    ```json
    {
      "accounts": [
        {
          "account_type": "google",
          "extra_info": "Primary User",
          "email": "user@example.com"
        }
      ]
    }
    ```

### 2. Docker Compose

Build and run the server using Docker Compose from the `mcp-servers` directory:

```bash
cd mcp-servers
docker-compose build mcp-gsuite
docker-compose up -d mcp-gsuite
# Ensure your Redis service is also running if managed separately
```

### 3. MCP Client Configuration

Configure your MCP client to connect to this server.

**Using Smithery (`smithery.yaml`):**

Add the following to your `smithery.yaml` file:

```yaml
servers:
  # ... other servers
  - id: gsuite
    name: Google Workspace Tools
    description: Provides access to Gmail, Calendar, and Drive.
    startCommand:
      type: stdio
      configSchema:
        # JSON Schema defining the configuration options for the MCP.
        type: object
        required:
          - userId
          - gauthFile
          - accountsFile # Keep as required for setup, even if not direct CLI arg
        properties:
          userId:
            type: string
            description: The primary user ID (email) this server instance will handle.
          gauthFile:
            type: string
            description: Path to the OAuth2 client configuration file (e.g., /app/config/.gauth.json).
          accountsFile:
            type: string
            description: Path to the Google accounts configuration file (e.g., /app/config/.accounts.json).
      commandFunction:
        # A function that produces the CLI command to start the MCP on stdio.
        |-
        (config) => ({command: 'uv', args: ['run', 'mcp-gsuite', '--user-id', config.userId]})

```
*Note: The `commandFunction` assumes you are running the server via `uv run mcp-gsuite` within its container or environment. Adjust the `command` and `args` if you are using a different execution method (e.g., `docker exec`). The paths for `gauthFile` and `accountsFile` in the schema are primarily for validation/documentation; only `userId` is passed as a direct CLI argument.*

**Using Standard MCP Configuration (`mcp_config.json`):**

If your client uses a standard JSON configuration:

```json
{
  "servers": [
    // ... other servers
    {
      "id": "gsuite",
      "name": "Google Workspace Tools",
      "description": "Provides access to Gmail, Calendar, and Drive.",
      "transport": {
        "type": "stdio",
        // Command to execute the server. Adjust based on your setup.
        // This example assumes running within the container via 'uv'.
        // It requires the USER_ID to be passed.
        "command": ["uv", "run", "mcp-gsuite", "--user-id", "YOUR_USER_EMAIL@example.com"]
      },
      // Configuration options (if your client supports passing them)
      // Note: These are not directly used by the command but might be needed
      // for client-side validation or setup steps.
      "config": {
         "userId": "YOUR_USER_EMAIL@example.com",
         "gauthFile": "/path/to/your/.gauth.json", // Path accessible to the client/orchestrator
         "accountsFile": "/path/to/your/.accounts.json" // Path accessible to the client/orchestrator
      }
    }
  ]
}
```
*Replace `YOUR_USER_EMAIL@example.com` with the actual user email.*
*Adjust the `command` array based on how you execute the server process (e.g., using `docker exec`).*
*The paths in the `config` object might be needed by the client or an orchestrator (like `mcp-aggregator`) to manage the server lifecycle or authentication, even though they aren't passed directly to the `mcp-gsuite` server command.*

## Authentication Flow

1.  The client (e.g., Smithery, `mcp-aggregator`) starts the `mcp-gsuite` server, providing the target `--user-id`.
2.  When a tool requiring authentication is called, the tool attempts to load credentials using the `user_id`.
3.  If credentials are valid (or refreshed successfully using the token stored in Redis), the tool executes.
4.  If credentials are missing or invalid, the tool returns a specific `JSONRPCError` (code `-32001`) with an `authUrl` and `state` in the `data` field.
5.  The *client* is responsible for:
    *   Presenting the `authUrl` to the user.
    *   Handling the redirect after user consent (which goes to the `REDIRECT_URI` configured in the Google Cloud Console, e.g., `https://server.indepreneur.io/mcp/oauth/callback`).
    *   Capturing the authorization `code` and `state` from the redirect.
    *   Calling the `mcp-gsuite` server's `gauth.exchange_code(state, code, user_id)` function (likely via a separate mechanism or tool if exposed, or handled entirely by an aggregator). This exchanges the code, stores the refresh token in Redis, and notifies the client/aggregator via Redis pub/sub (`gsuite_auth_success` channel) using the original `state`.
6.  Subsequent tool calls should succeed using the stored refresh token.

## Development Notes

*   Ensure Redis is running and accessible.
*   Place `.gauth.json` and `.accounts.json` in the configured location (default `/app/config/` inside the container).
*   The server uses `asyncio.to_thread` to run blocking Google API calls.
*   Error handling returns MCP-compliant `isError: true` results for tool execution errors and raises `JSONRPCError` for protocol/auth errors.
*   Return types are wrapped in `TextContent` (usually as JSON strings) or `EmbeddedResource`.