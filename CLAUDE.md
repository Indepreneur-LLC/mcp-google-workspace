# mcp-google-workspace CLAUDE.md

## Purpose
Google Workspace integration service providing Gmail, Calendar, and Drive access for Indepreneur team members through Model Context Protocol (MCP).

## Narrative Summary
This service enables team members to interact with Google Workspace services through Claude and other MCP clients. It provides comprehensive access to Gmail (reading, composing, managing emails), Google Calendar (viewing, creating, deleting events), and Google Drive (listing, downloading, uploading files). Unlike user-facing OAuth flows, this service uses Google service account authentication with domain-wide delegation, allowing it to impersonate any @indepreneur.io email address without individual user consent.

The service is built on the toastmcp framework and follows the established MCP server patterns used throughout the io-mcps ecosystem. It's designed specifically for team member use (no customer access) and integrates with the broader MCP aggregator infrastructure.

## Key Files
- `src/mcp_google_workspace/server.py` - Main MCP server with tool definitions
- `src/mcp_google_workspace/gauth.py` - Service account authentication with domain-wide delegation
- `src/mcp_google_workspace/tools_gmail.py` - Gmail API implementations
- `src/mcp_google_workspace/tools_drive.py` - Google Drive API implementations  
- `src/mcp_google_workspace/tools_calendar.py` - Google Calendar API implementations
- `pyproject.toml` - Package configuration with toastmcp dependency
- `requirements.in` - Google API client dependencies
- `smithery.yaml` - MCP client configuration schema

## API Endpoints
### Gmail Tools (namespace: google)
- `google:query_emails` - Search Gmail with optional query
- `google:get_email` - Retrieve complete email by ID
- `google:bulk_get_emails` - Get multiple emails by IDs
- `google:get_attachment` - Download Gmail attachment
- `google:create_draft` - Create email draft
- `google:delete_draft` - Delete email draft
- `google:reply_email` - Reply to email (draft or send)
- `google:bulk_save_attachments` - Save multiple attachments

### Drive Tools
- `google:list_files` - List Drive files with optional query
- `google:get_file_metadata` - Get file metadata
- `google:download_file` - Download Drive file
- `google:upload_file` - Upload file to Drive

### Calendar Tools
- `google:list_calendars` - List user's calendars
- `google:get_events` - Get calendar events with time filtering
- `google:create_event` - Create calendar event
- `google:delete_event` - Delete calendar event

## Integration Points
### Consumes
- Google Workspace APIs: Gmail v1, Calendar v3, Drive v3
- Service account credentials: `/app/secrets/oauth-bot-key.json`
- toastmcp: MCP framework and service patterns

### Provides
- MCP tools via stdio transport on port 8005
- Team member Google Workspace access through mcp-aggregator

## Configuration
Required files:
- `GOOGLE_SERVICE_ACCOUNT_KEY` - Service account JSON key path (default: `/app/secrets/oauth-bot-key.json`)
- Google Cloud Project with domain-wide delegation enabled
- Service account must have delegation for required scopes:
  - `https://mail.google.com/` (Gmail full access)
  - `https://www.googleapis.com/auth/calendar` (Calendar access)
  - `https://www.googleapis.com/auth/drive` (Drive access)

Runtime configuration:
- `--user-id` CLI argument specifying @indepreneur.io email to impersonate
- Docker container runs on port 8005

## Key Patterns
- **Service Account Authentication**: Uses domain-wide delegation instead of OAuth flows (see gauth.py)
- **toastmcp Framework**: Built on established MCP service patterns with tool decorators
- **Async Google API Calls**: All blocking Google API calls wrapped in `asyncio.to_thread`
- **Structured Tool Arguments**: Pydantic models for all tool parameters with validation
- **Team Member Only**: Restricted to `allow_users=["team_member"]` - no customer access
- **Namespace Prefixing**: All tools prefixed with "google:" for routing

## Related Documentation
- sessions/patterns/by-service/mcp-aggregator.md - Service routing and authentication
- sessions/patterns/by-feature/mcp-framework.md - toastmcp usage patterns
- io-mcps/mcp-base-spec.md - MCP specification compliance