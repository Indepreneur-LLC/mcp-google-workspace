# CLAUDE.md - MCP Google Workspace

This file provides guidance to Claude Code when working with the MCP Google Workspace service.

## Service Overview

Provides Google Workspace API access (Gmail, Calendar, Drive) for Indepreneur team members.

## Current Architecture (Legacy - Pre-Migration)

**Status**: Functional but uses old MCP patterns. Awaiting migration to aloaf.mcp.

### What's Implemented
- **Gmail API**: Query, read, bulk read, attachments, drafts, replies
- **Calendar API**: List calendars, get events, create events, delete events  
- **Drive API**: List files, get metadata, download files, upload files
- **Multi-tenant Support**: User ID required for each request
- **Token Storage**: Redis-based refresh token management

### Current Authentication Flow
1. User initiates OAuth flow via aggregator
2. Redirects to Google OAuth consent
3. Callback to `https://server.indepreneur.io/mcp/oauth/callback`
4. Stores refresh token in Redis
5. Uses refresh token for API access

### Known Issues
- **No Domain Restriction**: Currently accepts any Google account (not restricted to @indepreneur.io)
- **Not Using aloaf.mcp**: Still uses older MCP server patterns
- **Manual Tool Registration**: No decorator-based pattern

## Migration Plan

### New Architecture
Remove OAuth entirely - authentication will be handled upstream:

1. **IOStaff Authentication**:
   - io_user_model identifies IOStaff users during login
   - Automatically validates access to @indepreneur.io Google Workspace
   - No separate OAuth flow needed in this service

2. **Service Pattern**:
   ```python
   from toastmcp import ExtendedALoaf
   
   aloaf = ExtendedALoaf()
   
   team = aloaf.mcp.service(
       name="mcp-google-workspace",
       port=8005,
       allow_users=["team_member"],
       require_roles=["admin", "specialist", "support"]
   )
   ```

3. **Tool Implementation**:
   ```python
   @team.tool
   async def gmail_query(args: GmailQueryArgs, _auth: dict):
       """Search Gmail messages"""
       # Use pre-authorized credentials for @indepreneur.io domain
       # No OAuth flow - trust aggregator authentication
       pass
   ```

### Migration Tasks

1. **Remove OAuth Components**:
   - Delete OAuth flow handlers
   - Remove token storage logic
   - Clean up redirect URI configuration

2. **Implement aloaf.mcp Pattern**:
   - Convert to service decorators
   - Add Pydantic models for all arguments
   - Implement async handlers

3. **Add Domain Service Account**:
   - Use Google Workspace domain-wide delegation
   - Service account impersonates @indepreneur.io users
   - No individual OAuth needed

4. **Update Tool Definitions**:
   - Convert existing tools to new pattern
   - Add proper descriptions and schemas
   - Implement error handling

## Environment Variables

Current (to be updated during migration):
- `GOOGLE_CLIENT_ID` - OAuth client ID
- `GOOGLE_CLIENT_SECRET` - OAuth client secret
- `REDIS_URL` - Redis connection for token storage

Future (post-migration):
- `GOOGLE_SERVICE_ACCOUNT_KEY` - Service account JSON
- `GOOGLE_WORKSPACE_DOMAIN` - indepreneur.io
- `GOOGLE_DELEGATED_ADMIN` - Admin email for impersonation

## Testing

```bash
# Current (old pattern)
cd mcp-google-workspace
pip install -e .
python -m mcp_google_workspace

# Future (new pattern)
python src/service.py
```

## Important Notes

- This service is for team members only (IOStaff users)
- Will enforce @indepreneur.io domain after migration
- No customer access to Google Workspace tools
- Service account needs domain-wide delegation configured in Google Admin