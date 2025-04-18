# ===== IMPORTS ===== #

## ===== STANDARD LIBRARY ===== ##
from collections.abc import Sequence
import logging
import asyncio
##-##

## ===== THIRD-PARTY ===== ##
from googleapiclient.errors import HttpError
from mcp import (
    EmbeddedResource,
    ToolAnnotations,
    JSONRPCError,
    ImageContent,
    TextContent
)
##-##

## ===== LOCAL ===== ##
from .server import app, GLOBAL_USER_ID
from . import calendar
from . import gauth
##-##

#-#

# ===== GLOBALS ===== #

## ===== LOGGING ===== ##
logger = logging.getLogger(__name__)
##-##

#-#


# ===== FUNCTIONS ===== #

## ===== TOOL FUNCTIONS ===== ##

### ----- READ/QUERY TOOLS ----- ###
@app.tool(
    name="list_calendars",
    description="""Lists all calendars accessible by the user.
    Call it before any other tool whenever the user specifies a particular agenda (Family, Holidays, etc.).""",
    inputSchema={
        "type": "object",
        "properties": {
            # user_id removed from schema
            "oauth_state": {
                 "type": "string",
                 "description": "Internal state parameter for authentication flow tracking."
            },
        },
        "required": ["oauth_state"] # Removed user_id
    },
    annotations=ToolAnnotations(
        version="1.0",
        author="Roo",
        tags=["calendar", "list"]
    )
)
async def list_calendars(oauth_state: str) -> Sequence[TextContent | ImageContent | EmbeddedResource]:
    """Lists the user's Google Calendars."""
    try:
        # Authenticate and Execute in thread using GLOBAL_USER_ID
        if not GLOBAL_USER_ID: raise JSONRPCError(code=-32000, message="Server user ID not configured.")
        credentials = await asyncio.to_thread(gauth.get_authenticated_credentials, GLOBAL_USER_ID, oauth_state)
        calendar_service = calendar.CalendarService(credentials=credentials)
        calendars = await asyncio.to_thread(calendar_service.list_calendars)
        return calendars # Return raw data

    except (FileNotFoundError, gauth.AuthenticationError) as auth_error:
        logger.warning(f"Authentication required for list_calendars (user: {GLOBAL_USER_ID}): {auth_error}")
        # Generate auth URL and raise standard error with data field
        auth_url = await asyncio.to_thread(gauth.get_auth_url, GLOBAL_USER_ID, oauth_state)
        raise JSONRPCError(
            code=-32001, # Custom server error code for auth required
            message="Google authentication required.",
            data={"authUrl": auth_url, "state": oauth_state, "reason": str(auth_error)}
        )
    except HttpError as e:
        logger.error(f"Google API HTTP error in list_calendars for user {GLOBAL_USER_ID}: {e}", exc_info=True)
        raise JSONRPCError(code=-32002, message=f"Google API Error: {e.resp.status} {e.reason}. Details: {e.content.decode()}")
    except Exception as e:
        logger.error(f"Unexpected error in list_calendars for user {GLOBAL_USER_ID}: {e}", exc_info=True)
        raise JSONRPCError(code=-32000, message=f"Failed to list calendars for {GLOBAL_USER_ID}. Reason: {e}")

@app.tool(
    name="get_calendar_events",
    description="Retrieves calendar events from the user's Google Calendar within a specified time range.",
    inputSchema={
        "type": "object",
        "properties": {
            # user_id removed from schema
            "oauth_state": {
                 "type": "string",
                 "description": "Internal state parameter for authentication flow tracking."
            },
            "calendar_id": { # Changed from __calendar_id__
                "type": "string",
                "description": "Optional ID of the calendar. Defaults to 'primary'. Use list_calendars to find IDs.",
                "default": "primary"
            },
            "time_min": {
                "type": "string",
                "description": "Start time in RFC3339 format (e.g. 2024-12-01T00:00:00Z). Defaults to current time if not specified."
            },
            "time_max": {
                "type": "string",
                "description": "End time in RFC3339 format (e.g. 2024-12-31T23:59:59Z). Optional."
            },
            "max_results": {
                "type": "integer",
                "description": "Maximum number of events to return (1-2500)",
                "minimum": 1,
                "maximum": 2500,
                "default": 250
            },
            "show_deleted": {
                "type": "boolean",
                "description": "Whether to include deleted events",
                "default": False
            }
        },
        "required": ["oauth_state"] # Removed user_id, calendar_id has default
    },
    annotations=ToolAnnotations(
        version="1.0",
        author="Roo",
        tags=["calendar", "events", "get", "list"]
    )
)
async def get_calendar_events(oauth_state: str, calendar_id: str = 'primary', time_min: str | None = None, time_max: str | None = None, max_results: int = 250, show_deleted: bool = False) -> Sequence[TextContent | ImageContent | EmbeddedResource]:
    """Retrieves Google Calendar events."""
    try:
        # Authenticate and Execute in thread using GLOBAL_USER_ID
        if not GLOBAL_USER_ID: raise JSONRPCError(code=-32000, message="Server user ID not configured.")
        credentials = await asyncio.to_thread(gauth.get_authenticated_credentials, GLOBAL_USER_ID, oauth_state)
        calendar_service = calendar.CalendarService(credentials=credentials)
        events = await asyncio.to_thread(
            calendar_service.get_events,
            time_min=time_min,
            time_max=time_max,
            max_results=max_results,
            show_deleted=show_deleted,
            calendar_id=calendar_id,
        )
        return events # Return raw data

    except (FileNotFoundError, gauth.AuthenticationError) as auth_error:
        logger.warning(f"Authentication required for get_calendar_events (user: {GLOBAL_USER_ID}, calendar: {calendar_id}): {auth_error}")
        # Generate auth URL and raise standard error with data field
        auth_url = await asyncio.to_thread(gauth.get_auth_url, GLOBAL_USER_ID, oauth_state)
        raise JSONRPCError(
            code=-32001, # Custom server error code for auth required
            message="Google authentication required.",
            data={"authUrl": auth_url, "state": oauth_state, "reason": str(auth_error)}
        )
    except HttpError as e:
        # Check for 404 specifically, could indicate calendar not found
        if e.resp.status == 404:
             logger.warning(f"Calendar {calendar_id} not found for user {GLOBAL_USER_ID}: {e}")
             raise JSONRPCError(code=-32014, message=f"Calendar with ID '{calendar_id}' not found.")
        else:
            logger.error(f"Google API HTTP error in get_calendar_events for user {GLOBAL_USER_ID}, calendar {calendar_id}: {e}", exc_info=True)
            raise JSONRPCError(code=-32002, message=f"Google API Error: {e.resp.status} {e.reason}. Details: {e.content.decode()}")
    except Exception as e:
        logger.error(f"Unexpected error in get_calendar_events for user {GLOBAL_USER_ID}, calendar {calendar_id}: {e}", exc_info=True)
        raise JSONRPCError(code=-32000, message=f"Failed to get events for calendar {calendar_id} for user {GLOBAL_USER_ID}. Reason: {e}")
###-###

### ----- WRITE/MODIFY TOOLS ----- ###
@app.tool(
    name="create_calendar_event",
    description="Creates a new event in a specified Google Calendar of the specified user.",
    inputSchema={
        "type": "object",
        "properties": {
            # user_id removed from schema
            "oauth_state": {
                 "type": "string",
                 "description": "Internal state parameter for authentication flow tracking."
            },
            "calendar_id": { # Changed from __calendar_id__
                "type": "string",
                "description": "Optional ID of the calendar. Defaults to 'primary'. Use list_calendars to find IDs.",
                "default": "primary"
            },
            "summary": {
                "type": "string",
                "description": "Title of the event"
            },
            "location": {
                "type": "string",
                "description": "Location of the event (optional)"
            },
            "description": {
                "type": "string",
                "description": "Description or notes for the event (optional)"
            },
            "start_time": {
                "type": "string",
                "description": "Start time in RFC3339 format (e.g. 2024-12-01T10:00:00Z)"
            },
            "end_time": {
                "type": "string",
                "description": "End time in RFC3339 format (e.g. 2024-12-01T11:00:00Z)"
            },
            "attendees": {
                "type": "array",
                "items": {
                    "type": "string"
                },
                "description": "List of attendee email addresses (optional)"
            },
            "send_notifications": {
                "type": "boolean",
                "description": "Whether to send notifications to attendees",
                "default": True
            },
            "timezone": {
                "type": "string",
                "description": "Timezone for the event (e.g. 'America/New_York'). Defaults to UTC if not specified."
            }
        },
        "required": ["oauth_state", "summary", "start_time", "end_time"] # Removed user_id
    },
    annotations=ToolAnnotations(
        version="1.0",
        author="Roo",
        tags=["calendar", "events", "create"]
    )
)
async def create_calendar_event(oauth_state: str, summary: str, start_time: str, end_time: str, calendar_id: str = 'primary', location: str | None = None, description: str | None = None, attendees: list[str] | None = None, send_notifications: bool = True, timezone: str | None = None) -> Sequence[TextContent | ImageContent | EmbeddedResource]:
    """Creates a new Google Calendar event."""
    try:
        # Authenticate and Execute in thread using GLOBAL_USER_ID
        if not GLOBAL_USER_ID: raise JSONRPCError(code=-32000, message="Server user ID not configured.")
        credentials = await asyncio.to_thread(gauth.get_authenticated_credentials, GLOBAL_USER_ID, oauth_state)
        calendar_service = calendar.CalendarService(credentials=credentials)
        event = await asyncio.to_thread(
            calendar_service.create_event,
            summary=summary,
            start_time=start_time,
            end_time=end_time,
            location=location,
            description=description,
            attendees=attendees or [],
            send_notifications=send_notifications,
            timezone=timezone,
            calendar_id=calendar_id,
        )
        # Assuming create_event returns the created event object or raises error
        return event # Return raw data

    except (FileNotFoundError, gauth.AuthenticationError) as auth_error:
        logger.warning(f"Authentication required for create_calendar_event (user: {GLOBAL_USER_ID}, calendar: {calendar_id}): {auth_error}")
        # Generate auth URL and raise standard error with data field
        auth_url = await asyncio.to_thread(gauth.get_auth_url, GLOBAL_USER_ID, oauth_state)
        raise JSONRPCError(
            code=-32001, # Custom server error code for auth required
            message="Google authentication required.",
            data={"authUrl": auth_url, "state": oauth_state, "reason": str(auth_error)}
        )
    except HttpError as e:
        # Check for 404 specifically, could indicate calendar not found
        if e.resp.status == 404:
             logger.warning(f"Calendar {calendar_id} not found for event creation by user {GLOBAL_USER_ID}: {e}")
             raise JSONRPCError(code=-32014, message=f"Calendar with ID '{calendar_id}' not found.")
        else:
            logger.error(f"Google API HTTP error in create_calendar_event for user {GLOBAL_USER_ID}, calendar {calendar_id}: {e}", exc_info=True)
            raise JSONRPCError(code=-32002, message=f"Google API Error: {e.resp.status} {e.reason}. Details: {e.content.decode()}")
    except ValueError as ve: # Catch potential validation errors from service layer
        logger.warning(f"Validation error creating event for user {GLOBAL_USER_ID}, calendar {calendar_id}: {ve}")
        raise JSONRPCError(code=-32602, message=f"Invalid parameters for creating event: {ve}") # Use invalid params code
    except Exception as e:
        logger.error(f"Unexpected error in create_calendar_event for user {GLOBAL_USER_ID}, calendar {calendar_id}: {e}", exc_info=True)
        raise JSONRPCError(code=-32000, message=f"Failed to create event in calendar {calendar_id} for user {GLOBAL_USER_ID}. Reason: {e}")

@app.tool(
    name="delete_calendar_event",
    description="Deletes an event from the user's Google Calendar by its event ID.",
    inputSchema={
        "type": "object",
        "properties": {
            # user_id removed from schema
            "oauth_state": {
                 "type": "string",
                 "description": "Internal state parameter for authentication flow tracking."
            },
            "calendar_id": { # Changed from __calendar_id__
                "type": "string",
                "description": "Optional ID of the calendar. Defaults to 'primary'. Use list_calendars to find IDs.",
                "default": "primary"
            },
            "event_id": {
                "type": "string",
                "description": "The ID of the calendar event to delete"
            },
            "send_notifications": {
                "type": "boolean",
                "description": "Whether to send cancellation notifications to attendees",
                "default": True
            }
        },
        "required": ["oauth_state", "event_id"] # Removed user_id
    },
    annotations=ToolAnnotations(
        version="1.0",
        author="Roo",
        tags=["calendar", "events", "delete"]
    )
)
async def delete_calendar_event(oauth_state: str, event_id: str, calendar_id: str = 'primary', send_notifications: bool = True) -> Sequence[TextContent | ImageContent | EmbeddedResource]:
    """Deletes a Google Calendar event by ID."""
    try:
        # Authenticate and Execute in thread using GLOBAL_USER_ID
        if not GLOBAL_USER_ID: raise JSONRPCError(code=-32000, message="Server user ID not configured.")
        credentials = await asyncio.to_thread(gauth.get_authenticated_credentials, GLOBAL_USER_ID, oauth_state)
        calendar_service = calendar.CalendarService(credentials=credentials)
        success = await asyncio.to_thread(
            calendar_service.delete_event,
            event_id=event_id,
            send_notifications=send_notifications,
            calendar_id=calendar_id,
        )

        if success:
            return {"status": "success", "message": f"Event {event_id} successfully deleted from calendar {calendar_id}"}
        else:
            # Assuming service layer raises specific error if deletion fails (e.g., 404)
            # This path might not be reached if HttpError is caught below
            logger.error(f"delete_event returned False for event {event_id}, calendar {calendar_id}, user {GLOBAL_USER_ID}")
            raise JSONRPCError(code=-32015, message=f"Failed to delete event {event_id} from calendar {calendar_id}. It might not exist or an error occurred.")

    except (FileNotFoundError, gauth.AuthenticationError) as auth_error:
        logger.warning(f"Authentication required for delete_calendar_event (user: {GLOBAL_USER_ID}, calendar: {calendar_id}, event: {event_id}): {auth_error}")
        # Generate auth URL and raise standard error with data field
        auth_url = await asyncio.to_thread(gauth.get_auth_url, GLOBAL_USER_ID, oauth_state)
        raise JSONRPCError(
            code=-32001, # Custom server error code for auth required
            message="Google authentication required.",
            data={"authUrl": auth_url, "state": oauth_state, "reason": str(auth_error)}
        )
    except HttpError as e:
        # Check for 404 (event not found) or 410 (event gone/deleted)
        if e.resp.status in [404, 410]:
             logger.warning(f"Event {event_id} not found or already gone in calendar {calendar_id} for user {GLOBAL_USER_ID}: {e}")
             # Consider returning success or specific code? For now, raise specific error.
             raise JSONRPCError(code=-32016, message=f"Event with ID {event_id} not found or already deleted in calendar '{calendar_id}'.")
        else:
            logger.error(f"Google API HTTP error in delete_calendar_event for user {GLOBAL_USER_ID}, calendar {calendar_id}, event {event_id}: {e}", exc_info=True)
            raise JSONRPCError(code=-32002, message=f"Google API Error: {e.resp.status} {e.reason}. Details: {e.content.decode()}")
    except Exception as e:
        logger.error(f"Unexpected error in delete_calendar_event for user {GLOBAL_USER_ID}, calendar {calendar_id}, event {event_id}: {e}", exc_info=True)
        raise JSONRPCError(code=-32000, message=f"Failed to delete event {event_id} from calendar {calendar_id} for user {GLOBAL_USER_ID}. Reason: {e}")
###-###

##-##

#-#