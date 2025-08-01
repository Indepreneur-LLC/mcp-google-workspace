# CLAUDE.md - MCP Google Workspace

This file provides guidance to Claude Code when working with the MCP Google Workspace service.

## Service Overview

Provides Google Workspace API access (Gmail, Calendar, Drive) for Indepreneur team members.

## Current Architecture (Migrated to toastmcp)

**Status**: Successfully migrated to toastmcp pattern with service account authentication.

### What's Implemented
- **Gmail API**: Query, read, bulk read, attachments, drafts, replies
- **Calendar API**: List calendars, get events, create events, delete events  
- **Drive API**: List files, get metadata, download files, upload files
- **Service Account Authentication**: Domain-wide delegation for @indepreneur.io
- **toastmcp Pattern**: Decorator-based tool registration with Pydantic models
- **Namespace**: All tools prefixed with "google:" (e.g., "google:query_emails")

### New Authentication Architecture
1. **Service Account**: Uses Google service account with domain-wide delegation
2. **No OAuth Flow**: Authentication handled entirely by service account
3. **User Impersonation**: Service account impersonates @indepreneur.io users
4. **Automatic Access**: Team members authenticated via io_user_model get access
5. **No Token Storage**: Service account handles all auth internally

## Service Implementation

### Architecture Details

1. **Service Definition**:
   ```python
   from toastmcp import MCPALoaf
   
   aloaf = MCPALoaf()
   
   service = aloaf.mcp.service(
       name="mcp-google-workspace",
       port=8005,
       namespace="google",
       allow_users=["team_member"],
       require_roles=["admin", "specialist", "support", "superuser"]
   )
   ```

2. **Tool Pattern**:
   ```python
   @service.tool(name="query_emails")
   async def query_gmail_emails(args: QueryEmailsArgs, _auth: dict):
       """Query Gmail emails"""
       user_email = _auth.get("user_email")
       gmail_service = await asyncio.to_thread(
           gauth.get_google_service, 'gmail', 'v1', user_email
       )
       # Implementation...
   ```

3. **Service Account Usage**:
   ```python
   # In gauth.py
   credentials = service_account.Credentials.from_service_account_file(
       SERVICE_ACCOUNT_KEY,
       scopes=SCOPES
   )
   delegated_credentials = credentials.with_subject(user_email)
   ```

## Environment Variables

Required (using global .env):
- `GOOGLE_SERVICE_ACCOUNT_KEY` - Path to service account JSON (default: `/app/secrets/oauth-bot-key.json`)
- `MCP_PORT` - Service port (default: 8005)
- `REDIS_HOST` - Redis host for service discovery
- `REDIS_PORT` - Redis port
- `REDIS_DB` - Redis database number

The service uses Google's domain-wide delegation, so no OAuth client credentials are needed.

## Testing

```bash
# Run the service
python src/mcp_google_workspace/server.py
```

The service automatically registers with Redis for discovery by the aggregator.

## Available Tools

All tools are namespaced with "google:" prefix:

### Gmail Tools
- `google:query_emails` - Search Gmail messages
- `google:get_email` - Get email by ID
- `google:bulk_get_emails` - Get multiple emails
- `google:get_attachment` - Download attachment
- `google:create_draft` - Create draft email
- `google:delete_draft` - Delete draft
- `google:reply_email` - Reply to email
- `google:bulk_save_attachments` - Save multiple attachments

### Drive Tools
- `google:list_files` - List Drive files
- `google:get_file_metadata` - Get file metadata
- `google:download_file` - Download file
- `google:upload_file` - Upload file

### Calendar Tools
- `google:list_calendars` - List all calendars
- `google:get_events` - Get calendar events
- `google:create_event` - Create event
- `google:delete_event` - Delete event

## Important Notes

- This service is for team members only (IOStaff users)
- Enforces @indepreneur.io domain via service account
- No customer access to Google Workspace tools
- Service account must have domain-wide delegation configured in Google Admin
- All tools receive user email from `_auth` context (no user_id parameter needed)