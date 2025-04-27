# ===== IMPORTS ===== #

## ===== STANDARD LIBRARY ===== ##
from collections.abc import Sequence
import logging
import asyncio
import json
##-##

## ===== THIRD-PARTY ===== ##
from googleapiclient.errors import HttpError
from mcp.types import (
    EmbeddedResource,
    JSONRPCError,
    ImageContent,
    TextContent
)
##-##

## ===== LOCAL ===== ##
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
async def list_calendars(oauth_state: str, user_id: str) -> Sequence[TextContent | ImageContent | EmbeddedResource]:
    """Lists the user's Google Calendars."""
    try:
        if not user_id: raise JSONRPCError(code=-32000, message="Server user ID not configured.")
        credentials = await asyncio.to_thread(gauth.get_authenticated_credentials, user_id, oauth_state)
        calendar_service = calendar.CalendarService(credentials=credentials)
        calendars = await asyncio.to_thread(calendar_service.list_calendars)
        # Wrap the list of calendar dicts in TextContent after JSON serialization
        return [TextContent(type="text", text=json.dumps(calendars))]

    except (FileNotFoundError, gauth.AuthenticationError) as auth_error:
        logger.warning(f"Authentication required for list_calendars (user: {user_id}): {auth_error}")
        # Generate auth URL and raise standard error with data field
        auth_url = await asyncio.to_thread(gauth.get_auth_url, user_id, oauth_state)
        raise JSONRPCError(
            code=-32001, # Custom server error code for auth required
            message="Google authentication required.",
            data={"authUrl": auth_url, "state": oauth_state, "reason": str(auth_error)}
        )
    except HttpError as e:
        logger.error(f"Google API HTTP error in list_calendars for user "
                     f"{user_id}: {e}", exc_info=True)
        error_message = f"Google API Error: {e.resp.status} {e.reason}. Details: {e.content.decode()}"
        return {"content": [TextContent(type="text", text=error_message)], "isError": True}
    except Exception as e:
        logger.error(f"Unexpected error in list_calendars for user "
                     f"{user_id}: {e}", exc_info=True)
        error_message = f"Failed to list calendars for {user_id}. Reason: {e}"
        return {"content": [TextContent(type="text", text=error_message)], "isError": True}

async def get_calendar_events(
    oauth_state: str,
    user_id: str,
    calendar_id: str = 'primary',
    time_min: str | None = None,
    time_max: str | None = None,
    max_results: int = 250,
    show_deleted: bool = False,
) -> Sequence[TextContent | ImageContent | EmbeddedResource]:
    """Retrieves Google Calendar events."""
    try:
        if not user_id: raise JSONRPCError(code=-32000, message="Server user ID not configured.")
        credentials = await asyncio.to_thread(gauth.get_authenticated_credentials, user_id, oauth_state)
        calendar_service = calendar.CalendarService(credentials=credentials)
        events = await asyncio.to_thread(
            calendar_service.get_events,
            time_min=time_min,
            time_max=time_max,
            max_results=max_results,
            show_deleted=show_deleted,
            calendar_id=calendar_id,
        )
        # Wrap the list of event dicts in TextContent after JSON serialization
        return [TextContent(type="text", text=json.dumps(events))]

    except (FileNotFoundError, gauth.AuthenticationError) as auth_error:
        logger.warning(f"Authentication required for get_calendar_events "
                       f"(user: {user_id}, calendar: {calendar_id}): {auth_error}")
        # Generate auth URL and raise standard error with data field
        auth_url = await asyncio.to_thread(gauth.get_auth_url, user_id, oauth_state)
        raise JSONRPCError(
            code=-32001, # Custom server error code for auth required
            message="Google authentication required.",
            data={"authUrl": auth_url, "state": oauth_state, "reason": str(auth_error)}
        )
    except HttpError as e:
        # Check for 404 specifically, could indicate calendar not found
        if e.resp.status == 404:
            logger.warning(f"Calendar {calendar_id} not found for user {user_id}: {e}")
            error_message = f"Calendar with ID '{calendar_id}' not found."
            return {"content": [TextContent(type="text", text=error_message)], "isError": True}
        else:
            logger.error(f"Google API HTTP error in get_calendar_events for user "
                         f"{user_id}, calendar {calendar_id}: {e}", exc_info=True)
            error_message = f"Google API Error: {e.resp.status} {e.reason}. Details: {e.content.decode()}"
            return {"content": [TextContent(type="text", text=error_message)], "isError": True}
    except Exception as e:
        logger.error(f"Unexpected error in get_calendar_events for user "
                     f"{user_id}, calendar {calendar_id}: {e}", exc_info=True)
        error_message = f"Failed to get events for calendar {calendar_id} for user {user_id}. Reason: {e}"
        return {"content": [TextContent(type="text", text=error_message)], "isError": True}
##-##

### ----- WRITE/MODIFY TOOLS ----- ###
async def create_calendar_event(
    oauth_state: str,
    summary: str,
    start_time: str,
    end_time: str,
    user_id: str,
    calendar_id: str = 'primary',
    location: str | None = None,
    description: str | None = None,
    attendees: list[str] | None = None,
    send_notifications: bool = True,
    timezone: str | None = None
) -> Sequence[TextContent | ImageContent | EmbeddedResource]:
    """Creates a new Google Calendar event."""
    try:
        if not user_id: raise JSONRPCError(code=-32000, message="Server user ID not configured.")
        credentials = await asyncio.to_thread(gauth.get_authenticated_credentials, user_id, oauth_state)
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
        # Wrap the event dict in TextContent after JSON serialization
        return [TextContent(type="text", text=json.dumps(event))]

    except (FileNotFoundError, gauth.AuthenticationError) as auth_error:
        logger.warning(f"Authentication required for create_calendar_event "
                       f"(user: {user_id}, calendar: {calendar_id}): {auth_error}")
        # Generate auth URL and raise standard error with data field
        auth_url = await asyncio.to_thread(gauth.get_auth_url, user_id, oauth_state)
        raise JSONRPCError(
            code=-32001, # Custom server error code for auth required
            message="Google authentication required.",
            data={"authUrl": auth_url, "state": oauth_state, "reason": str(auth_error)}
        )
    except HttpError as e:
        # Check for 404 specifically, could indicate calendar not found
        if e.resp.status == 404:
            logger.warning(f"Calendar {calendar_id} not found for event creation by user "
                           f"{user_id}: {e}")
            error_message = f"Calendar with ID '{calendar_id}' not found."
            return {"content": [TextContent(type="text", text=error_message)], "isError": True}
        else:
            logger.error(f"Google API HTTP error in create_calendar_event for user "
                         f"{user_id}, calendar {calendar_id}: {e}", exc_info=True)
            error_message = f"Google API Error: {e.resp.status} {e.reason}. Details: {e.content.decode()}"
            return {"content": [TextContent(type="text", text=error_message)], "isError": True}
    except ValueError as ve: # Catch potential validation errors from service layer
        logger.warning(f"Validation error creating event for user {user_id}, "
                       f"calendar {calendar_id}: {ve}")
        raise JSONRPCError(code=-32602, message=f"Invalid parameters for creating event: {ve}")
    except Exception as e:
        logger.error(f"Unexpected error in create_calendar_event for user "
                     f"{user_id}, calendar {calendar_id}: {e}", exc_info=True)
        error_message = f"Failed to create event in calendar {calendar_id} for user {user_id}. Reason: {e}"
        return {"content": [TextContent(type="text", text=error_message)], "isError": True}

async def delete_calendar_event(
    oauth_state: str,
    event_id: str,
    user_id: str,
    calendar_id: str = 'primary',
    send_notifications: bool = True
) -> Sequence[TextContent | ImageContent | EmbeddedResource]:
    """Deletes a Google Calendar event by ID."""
    try:
        if not user_id: raise JSONRPCError(code=-32000, message="Server user ID not configured.")
        credentials = await asyncio.to_thread(gauth.get_authenticated_credentials, user_id, oauth_state)
        calendar_service = calendar.CalendarService(credentials=credentials)
        success = await asyncio.to_thread(
            calendar_service.delete_event,
            event_id=event_id,
            send_notifications=send_notifications,
            calendar_id=calendar_id,
        )

        if success:
            status_dict = {"status": "success", "message": f"Event {event_id} successfully deleted from calendar {calendar_id}"}
            return [TextContent(type="text", text=json.dumps(status_dict))]
        else:
            # Assuming service layer raises specific error if deletion fails (e.g., 404)
            # This path might not be reached if HttpError is caught below
            logger.error(f"delete_event returned False for event {event_id}, "
                         f"calendar {calendar_id}, user {user_id}")
            error_message = f"Failed to delete event {event_id} from calendar {calendar_id}. It might not exist or an error occurred."
            return {"content": [TextContent(type="text", text=error_message)], "isError": True}

    except (FileNotFoundError, gauth.AuthenticationError) as auth_error:
        logger.warning(f"Authentication required for delete_calendar_event "
                       f"(user: {user_id}, calendar: {calendar_id}, event: {event_id}): {auth_error}")
        # Generate auth URL and raise standard error with data field
        auth_url = await asyncio.to_thread(gauth.get_auth_url, user_id, oauth_state)
        raise JSONRPCError(
            code=-32001, # Custom server error code for auth required
            message="Google authentication required.",
            data={"authUrl": auth_url, "state": oauth_state, "reason": str(auth_error)}
        )
    except HttpError as e:
        # Check for 404 (event not found) or 410 (event gone/deleted)
        if e.resp.status in [404, 410]:
            logger.warning(f"Event {event_id} not found or already gone in calendar "
                           f"{calendar_id} for user {user_id}: {e}")
            # Consider returning success or specific code? For now, raise specific error.
            error_message = f"Event with ID {event_id} not found or already deleted in calendar '{calendar_id}'."
            return {"content": [TextContent(type="text", text=error_message)], "isError": True}
        else:
            logger.error(f"Google API HTTP error in delete_calendar_event for user "
                         f"{user_id}, calendar {calendar_id}, event {event_id}: {e}", exc_info=True)
            error_message = f"Google API Error: {e.resp.status} {e.reason}. Details: {e.content.decode()}"
            return {"content": [TextContent(type="text", text=error_message)], "isError": True}
    except Exception as e:
        logger.error(f"Unexpected error in delete_calendar_event for user "
                     f"{user_id}, calendar {calendar_id}, event {event_id}: {e}", exc_info=True)
        error_message = f"Failed to delete event {event_id} from calendar {calendar_id} for user {user_id}. Reason: {e}"
        return {"content": [TextContent(type="text", text=error_message)], "isError": True}
##-##

##-##

#-#