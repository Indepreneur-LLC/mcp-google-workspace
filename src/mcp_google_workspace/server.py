#!/usr/bin/env python3
"""MCP Google Workspace service using toastmcp pattern."""

import asyncio
import logging
from typing import Optional, List, Dict, Any
from pydantic import BaseModel, Field
from toastmcp import MCPALoaf

# Initialize logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Initialize aloaf with MCP capabilities
aloaf = MCPALoaf()

# Create service for team members only
service = aloaf.mcp.service(
    name="mcp-google-workspace",
    port=8005,
    host="0.0.0.0",
    namespace="google",  # Tools will be prefixed as "google:query_emails"
    default_timeout=30,
    default_rate_limit=60,
    allow_users=["team_member"]  # Team members only - no role requirements
)

# Import gauth for service account access
import gauth

# Import tool implementations (these need updating too)
import tools_gmail
import tools_drive  
import tools_calendar

# ===== PYDANTIC MODELS ===== #

# Gmail tool arguments
class QueryEmailsArgs(BaseModel):
    query: Optional[str] = Field(None, description="Gmail search query")
    max_results: int = Field(100, ge=1, le=500, description="Maximum results")

class GetEmailArgs(BaseModel):
    email_id: str = Field(..., description="Gmail message ID")

class BulkGetEmailsArgs(BaseModel):
    email_ids: List[str] = Field(..., description="List of Gmail message IDs")

class GetAttachmentArgs(BaseModel):
    message_id: str = Field(..., description="Gmail message ID containing attachment")
    attachment_id: str = Field(..., description="Attachment ID")
    mime_type: str = Field(..., description="MIME type of attachment")
    filename: str = Field(..., description="Filename of attachment")
    save_to_disk: Optional[str] = Field(None, description="Optional path to save to disk")

class CreateDraftArgs(BaseModel):
    to: str = Field(..., description="Recipient email address")
    subject: str = Field(..., description="Subject line")
    body: str = Field(..., description="Email body content")
    cc: Optional[List[str]] = Field(None, description="CC recipients")

class DeleteDraftArgs(BaseModel):
    draft_id: str = Field(..., description="Draft ID to delete")

class ReplyEmailArgs(BaseModel):
    original_message_id: str = Field(..., description="Message ID to reply to")
    reply_body: str = Field(..., description="Reply body content")
    send: bool = Field(False, description="Send immediately or save as draft")
    cc: Optional[List[str]] = Field(None, description="CC recipients")

class BulkSaveAttachmentsArgs(BaseModel):
    class AttachmentInfo(BaseModel):
        message_id: str = Field(..., description="Message ID")
        attachment_id: str = Field(..., description="Attachment ID")
        save_path: str = Field(..., description="Save path")
    
    attachments: List[AttachmentInfo] = Field(..., description="Attachments to save")

# Drive tool arguments
class ListDriveFilesArgs(BaseModel):
    query: Optional[str] = Field(None, description="Drive query string")
    page_size: int = Field(100, ge=1, le=1000, description="Page size")
    fields: str = Field("nextPageToken, files(id, name, mimeType, size, modifiedTime, parents)", 
                       description="Fields to include")

class GetDriveMetadataArgs(BaseModel):
    file_id: str = Field(..., description="Drive file ID")
    fields: str = Field("id, name, mimeType, size, modifiedTime, createdTime, owners, parents, webViewLink, iconLink",
                       description="Fields to include")

class DownloadDriveFileArgs(BaseModel):
    file_id: str = Field(..., description="Drive file ID to download")

class UploadDriveFileArgs(BaseModel):
    file_name: str = Field(..., description="File name")
    mime_type: str = Field(..., description="MIME type")
    file_content_b64: str = Field(..., description="Base64 encoded content")
    folder_id: Optional[str] = Field(None, description="Folder ID")

# Calendar tool arguments  
class ListCalendarsArgs(BaseModel):
    """No arguments needed for listing calendars"""
    pass

class GetEventsArgs(BaseModel):
    calendar_id: str = Field("primary", description="Calendar ID")
    time_min: Optional[str] = Field(None, description="Start time RFC3339")
    time_max: Optional[str] = Field(None, description="End time RFC3339")
    max_results: int = Field(250, ge=1, le=2500)
    show_deleted: bool = Field(False)

class CreateEventArgs(BaseModel):
    calendar_id: str = Field("primary", description="Calendar ID")
    summary: str = Field(..., description="Event title")
    location: Optional[str] = Field(None, description="Event location")
    description: Optional[str] = Field(None, description="Event description")
    start_time: str = Field(..., description="Start time RFC3339")
    end_time: str = Field(..., description="End time RFC3339")
    attendees: Optional[List[str]] = Field(None, description="Attendee emails")
    send_notifications: bool = Field(True)
    timezone: Optional[str] = Field(None, description="Timezone")

class DeleteEventArgs(BaseModel):
    calendar_id: str = Field("primary", description="Calendar ID")
    event_id: str = Field(..., description="Event ID to delete")
    send_notifications: bool = Field(True)

# ===== GMAIL TOOLS ===== #

@service.tool(name="query_emails", timeout=20)
async def query_gmail_emails(args: QueryEmailsArgs, _auth: dict):
    """Query Gmail emails with optional search."""
    user_email = _auth.get("user_email")
    if not user_email:
        return service.tool.error("No user email in auth context", "AUTH_ERROR")
    
    try:
        result = await tools_gmail.query_gmail_emails(
            user_email=user_email,
            query=args.query,
            max_results=args.max_results
        )
        # Result is already a list of email dicts
        return service.tool.success(emails=result)
    except Exception as e:
        logger.error(f"Error querying emails: {e}")
        return service.tool.error(str(e), "GMAIL_ERROR")

@service.tool(name="get_email")
async def get_gmail_email(args: GetEmailArgs, _auth: dict):
    """Get a complete Gmail email by ID."""
    user_email = _auth.get("user_email")
    if not user_email:
        return service.tool.error("No user email in auth context", "AUTH_ERROR")
    
    try:
        result = await tools_gmail.get_gmail_email(
            user_email=user_email,
            email_id=args.email_id
        )
        # Result is already the email dict
        return service.tool.success(email=result)
    except Exception as e:
        logger.error(f"Error getting email: {e}")
        return service.tool.error(str(e), "GMAIL_ERROR")

@service.tool(name="bulk_get_emails")
async def bulk_get_gmail_emails(args: BulkGetEmailsArgs, _auth: dict):
    """Get multiple Gmail emails by IDs."""
    user_email = _auth.get("user_email")
    if not user_email:
        return service.tool.error("No user email in auth context", "AUTH_ERROR")
    
    try:
        result = await tools_gmail.bulk_get_gmail_emails(
            user_email=user_email,
            email_ids=args.email_ids
        )
        # Result is already a list of email dicts
        return service.tool.success(emails=result)
    except Exception as e:
        logger.error(f"Error getting emails: {e}")
        return service.tool.error(str(e), "GMAIL_ERROR")

@service.tool(name="get_attachment")
async def get_gmail_attachment(args: GetAttachmentArgs, _auth: dict):
    """Get a Gmail attachment."""
    user_email = _auth.get("user_email")
    if not user_email:
        return service.tool.error("No user email in auth context", "AUTH_ERROR")
    
    try:
        result = await tools_gmail.get_gmail_attachment(
            user_email=user_email,
            message_id=args.message_id,
            attachment_id=args.attachment_id,
            mime_type=args.mime_type,
            filename=args.filename,
            save_to_disk=args.save_to_disk
        )
        # Result is either a status dict or attachment dict
        if isinstance(result, dict):
            if "status" in result:
                # File was saved to disk
                return service.tool.success(message=result["message"], path=result.get("path"))
            else:
                # Attachment data returned
                return service.tool.success(attachment=result)
        else:
            return service.tool.error("Unexpected result format", "GMAIL_ERROR")
    except Exception as e:
        logger.error(f"Error getting attachment: {e}")
        return service.tool.error(str(e), "GMAIL_ERROR")

@service.tool(name="create_draft")
async def create_gmail_draft(args: CreateDraftArgs, _auth: dict):
    """Create a Gmail draft."""
    user_email = _auth.get("user_email")
    if not user_email:
        return service.tool.error("No user email in auth context", "AUTH_ERROR")
    
    try:
        result = await tools_gmail.create_gmail_draft(
            user_email=user_email,
            to=args.to,
            subject=args.subject,
            body=args.body,
            cc=args.cc
        )
        return service.tool.success(result)
    except Exception as e:
        logger.error(f"Error creating draft: {e}")
        return service.tool.error(str(e), "GMAIL_ERROR")

@service.tool(name="delete_draft")
async def delete_gmail_draft(args: DeleteDraftArgs, _auth: dict):
    """Delete a Gmail draft."""
    user_email = _auth.get("user_email")
    if not user_email:
        return service.tool.error("No user email in auth context", "AUTH_ERROR")
    
    try:
        result = await tools_gmail.delete_gmail_draft(
            user_email=user_email,
            draft_id=args.draft_id
        )
        return service.tool.success(result)
    except Exception as e:
        logger.error(f"Error deleting draft: {e}")
        return service.tool.error(str(e), "GMAIL_ERROR")

@service.tool(name="reply_email")
async def reply_gmail_email(args: ReplyEmailArgs, _auth: dict):
    """Reply to a Gmail email."""
    user_email = _auth.get("user_email")
    if not user_email:
        return service.tool.error("No user email in auth context", "AUTH_ERROR")
    
    try:
        result = await tools_gmail.reply_gmail_email(
            user_email=user_email,
            original_message_id=args.original_message_id,
            reply_body=args.reply_body,
            send=args.send,
            cc=args.cc
        )
        return service.tool.success(result)
    except Exception as e:
        logger.error(f"Error replying to email: {e}")
        return service.tool.error(str(e), "GMAIL_ERROR")

@service.tool(name="bulk_save_attachments")
async def bulk_save_gmail_attachments(args: BulkSaveAttachmentsArgs, _auth: dict):
    """Save multiple Gmail attachments."""
    user_email = _auth.get("user_email")
    if not user_email:
        return service.tool.error("No user email in auth context", "AUTH_ERROR")
    
    try:
        # Convert Pydantic models to dicts
        attachments = [att.model_dump() for att in args.attachments]
        result = await tools_gmail.bulk_save_gmail_attachments(
            user_email=user_email,
            attachments=attachments
        )
        return service.tool.success(result)
    except Exception as e:
        logger.error(f"Error saving attachments: {e}")
        return service.tool.error(str(e), "GMAIL_ERROR")

# ===== DRIVE TOOLS ===== #

@service.tool(name="list_files")
async def list_drive_files(args: ListDriveFilesArgs, _auth: dict):
    """List Google Drive files."""
    user_email = _auth.get("user_email")
    if not user_email:
        return service.tool.error("No user email in auth context", "AUTH_ERROR")
    
    try:
        result = await tools_drive.list_drive_files(
            user_email=user_email,
            query=args.query,
            page_size=args.page_size,
            fields=args.fields
        )
        return service.tool.success(result)
    except Exception as e:
        logger.error(f"Error listing files: {e}")
        return service.tool.error(str(e), "DRIVE_ERROR")

@service.tool(name="get_file_metadata")
async def get_drive_file_metadata(args: GetDriveMetadataArgs, _auth: dict):
    """Get Drive file metadata."""
    user_email = _auth.get("user_email")
    if not user_email:
        return service.tool.error("No user email in auth context", "AUTH_ERROR")
    
    try:
        result = await tools_drive.get_drive_file_metadata(
            user_email=user_email,
            file_id=args.file_id,
            fields=args.fields
        )
        return service.tool.success(result)
    except Exception as e:
        logger.error(f"Error getting metadata: {e}")
        return service.tool.error(str(e), "DRIVE_ERROR")

@service.tool(name="download_file")
async def download_drive_file(args: DownloadDriveFileArgs, _auth: dict):
    """Download a Drive file."""
    user_email = _auth.get("user_email")
    if not user_email:
        return service.tool.error("No user email in auth context", "AUTH_ERROR")
    
    try:
        result = await tools_drive.download_drive_file(
            user_email=user_email,
            file_id=args.file_id
        )
        # Result is already the resource dict
        return service.tool.success(file=result)
    except Exception as e:
        logger.error(f"Error downloading file: {e}")
        return service.tool.error(str(e), "DRIVE_ERROR")

@service.tool(name="upload_file")
async def upload_drive_file(args: UploadDriveFileArgs, _auth: dict):
    """Upload a file to Drive."""
    user_email = _auth.get("user_email")
    if not user_email:
        return service.tool.error("No user email in auth context", "AUTH_ERROR")
    
    try:
        result = await tools_drive.upload_drive_file(
            user_email=user_email,
            file_name=args.file_name,
            mime_type=args.mime_type,
            file_content_b64=args.file_content_b64,
            folder_id=args.folder_id
        )
        return service.tool.success(result)
    except Exception as e:
        logger.error(f"Error uploading file: {e}")
        return service.tool.error(str(e), "DRIVE_ERROR")

# ===== CALENDAR TOOLS ===== #

@service.tool(name="list_calendars")
async def list_calendars(args: ListCalendarsArgs, _auth: dict):
    """List all calendars."""
    user_email = _auth.get("user_email")
    if not user_email:
        return service.tool.error("No user email in auth context", "AUTH_ERROR")
    
    try:
        result = await tools_calendar.list_calendars(user_email=user_email)
        return service.tool.success(result)
    except Exception as e:
        logger.error(f"Error listing calendars: {e}")
        return service.tool.error(str(e), "CALENDAR_ERROR")

@service.tool(name="get_events")
async def get_calendar_events(args: GetEventsArgs, _auth: dict):
    """Get calendar events."""
    user_email = _auth.get("user_email")
    if not user_email:
        return service.tool.error("No user email in auth context", "AUTH_ERROR")
    
    try:
        result = await tools_calendar.get_calendar_events(
            user_email=user_email,
            calendar_id=args.calendar_id,
            time_min=args.time_min,
            time_max=args.time_max,
            max_results=args.max_results,
            show_deleted=args.show_deleted
        )
        return service.tool.success(result)
    except Exception as e:
        logger.error(f"Error getting events: {e}")
        return service.tool.error(str(e), "CALENDAR_ERROR")

@service.tool(name="create_event")
async def create_calendar_event(args: CreateEventArgs, _auth: dict):
    """Create a calendar event."""
    user_email = _auth.get("user_email")
    if not user_email:
        return service.tool.error("No user email in auth context", "AUTH_ERROR")
    
    try:
        result = await tools_calendar.create_calendar_event(
            user_email=user_email,
            calendar_id=args.calendar_id,
            summary=args.summary,
            location=args.location,
            description=args.description,
            start_time=args.start_time,
            end_time=args.end_time,
            attendees=args.attendees,
            send_notifications=args.send_notifications,
            timezone=args.timezone
        )
        return service.tool.success(result)
    except Exception as e:
        logger.error(f"Error creating event: {e}")
        return service.tool.error(str(e), "CALENDAR_ERROR")

@service.tool(name="delete_event")
async def delete_calendar_event(args: DeleteEventArgs, _auth: dict):
    """Delete a calendar event."""
    user_email = _auth.get("user_email")
    if not user_email:
        return service.tool.error("No user email in auth context", "AUTH_ERROR")
    
    try:
        result = await tools_calendar.delete_calendar_event(
            user_email=user_email,
            calendar_id=args.calendar_id,
            event_id=args.event_id,
            send_notifications=args.send_notifications
        )
        return service.tool.success(result)
    except Exception as e:
        logger.error(f"Error deleting event: {e}")
        return service.tool.error(str(e), "CALENDAR_ERROR")

# ===== MAIN ===== #

async def main():
    """Start the MCP service."""
    await service.start()

if __name__ == "__main__":
    asyncio.run(main())
