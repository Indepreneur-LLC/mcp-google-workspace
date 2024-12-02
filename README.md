# mcp-gsuite MCP server

MCP server to interact with Google.

## Example prompts

Right now, this MCP server supports Gmail and Calendar integration with the following capabilities:

1. Gmail
- Get your Gmail user information
- Query emails with flexible search (e.g., unread, from specific senders, date ranges, with attachments)
- Retrieve complete email content by ID
- Create new draft emails with recipients, subject, body and CC options
- Delete draft emails
- Reply to existing emails (can either send immediately or save as draft)

2. Calendar
- Get calendar events within specified time ranges
- Create calendar events with:
  - Title, start/end times
  - Optional location and description
  - Optional attendees
  - Custom timezone support
  - Notification preferences
- Delete calendar events

Example prompts you can try:
- "Show me my unread emails from the last 2 days"
- "Get the full content of email ID xyz123"
- "Draft an email to alice@example.com about the project update"
- "Reply to Bob's last email and save it as a draft"
- "Show my calendar events for next week"
- "Create a team meeting for tomorrow at 2 PM"
- "Cancel the event scheduled for Friday"

## Quickstart

### Install

#### Oauth 2

Google Workspace (G Suite) APIs require OAuth2 authorization. Follow these steps to set up authentication:

1. Create OAuth2 Credentials:
   - Go to the [Google Cloud Console](https://console.cloud.google.com/)
   - Create a new project or select an existing one
   - Enable the Gmail API and Google Calendar API for your project
   - Go to "Credentials" → "Create Credentials" → "OAuth client ID"
   - Select "Desktop app" or "Web application" as the application type
   - Configure the OAuth consent screen with required information
   - Add authorized redirect URIs (include `http://localhost:4100/code` for local development)

2. Required OAuth2 Scopes:
   ```json
   [
     "openid",
     "https://mail.google.com/",
     "https://www.googleapis.com/auth/calendar"
   ]

3. Then create a `.gauth.json` in your working directory:

```
{
    "web": {
        "client_id": "$your_client_id",
        "client_secret": "$your_client_secret",
        "redirect_uris": ["http://localhost:4100/code"],
        "auth_uri": "https://accounts.google.com/o/oauth2/auth",
        "token_uri": "https://oauth2.googleapis.com/token"
    }
}
```

Note: When you first execute one of the tools, a browser will open, redirect you to Google and ask for your credentials, scope, etc. After a successful login, it stores the credentials in a local file called `oauth2creds.json`. From that one,
the refresh token will be used.

#### Claude Desktop

On MacOS: `~/Library/Application\ Support/Claude/claude_desktop_config.json`

On Windows: `%APPDATA%/Claude/claude_desktop_config.json`

<details>
  <summary>Development/Unpublished Servers Configuration</summary>
  
```json
{
  "mcpServers": {
    "mcp-gsuite": {
      "command": "uv",
      "args": [
        "--directory",
        "<dir_to>/mcp-gsuite",
        "run",
        "mcp-gsuite"
      ]
    }
  }
}
```
</details>

<details>
  <summary>Published Servers Configuration</summary>
  
```json
{
  "mcpServers": {
    "mcp-gsuite": {
      "command": "uvx",
      "args": [
        "mcp-gsuite"
      ]
    }
  }
}
```
</details>

## Development

### Building and Publishing

To prepare the package for distribution:

1. Sync dependencies and update lockfile:
```bash
uv sync
```

2. Build package distributions:
```bash
uv build
```

This will create source and wheel distributions in the `dist/` directory.

3. Publish to PyPI:
```bash
uv publish
```

Note: You'll need to set PyPI credentials via environment variables or command flags:
- Token: `--token` or `UV_PUBLISH_TOKEN`
- Or username/password: `--username`/`UV_PUBLISH_USERNAME` and `--password`/`UV_PUBLISH_PASSWORD`

### Debugging

Since MCP servers run over stdio, debugging can be challenging. For the best debugging
experience, we strongly recommend using the [MCP Inspector](https://github.com/modelcontextprotocol/inspector).

You can launch the MCP Inspector via [`npm`](https://docs.npmjs.com/downloading-and-installing-node-js-and-npm) with this command:

```bash
npx @modelcontextprotocol/inspector uv --directory /path/to/mcp-gsuite run mcp-gsuite
```

Upon launching, the Inspector will display a URL that you can access in your browser to begin debugging.

You can also watch the server logs with this command:

```bash
tail -n 20 -f ~/Library/Logs/Claude/mcp-server-mcp-gsuite.log
```
