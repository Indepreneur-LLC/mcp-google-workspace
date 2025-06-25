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
    ImageContent,
    TextContent
)
##-##

## ===== LOCAL ===== ##
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
        if not user_id: raise ValueError("Server user ID not configured.")
        calendar_service = await asyncio.to_thread(gauth.get_google_service, 'calendar', 'v3', user_id)
        if calendar_service is None:
            # Assuming gauth.get_google_service might raise its own specific error if auth fails internally,
            # but if it just returns None, raise a generic error.
            raise RuntimeError("Failed to obtain Google Calendar service. Authentication may be missing or invalid.")
        calendars = await asyncio.to_thread(calendar_service.calendarList().list().execute) # Adjusted call
        # Wrap the list of calendar dicts in TextContent after JSON serialization
        return [TextContent(type="text", text=json.dumps(calendars))]

    except (FileNotFoundError, gauth.AuthenticationError) as auth_error:
        logger.warning(f"Authentication required for list_calendars (user: {user_id}): {auth_error}")
        # Generate auth URL and raise standard error with data field
        auth_url = await asyncio.to_thread(gauth.get_auth_url, user_id, oauth_state)
        # Re-raise the original auth error; the SDK decorator should handle it.
        # The auth_url generation might still be needed if the decorator doesn't handle it,
        # but per instructions, let the decorator manage error formatting.
        # TODO: Verify if auth_url generation is still needed here or handled by SDK decorator based on exception type.
        # For now, just re-raise.
        raise auth_error
    except HttpError as e:
        logger.error(f"Google API HTTP error in list_calendars for user "
                     f"{user_id}: {e}", exc_info=True)
        error_message = f"Google API Error: {e.resp.status} {e.reason}. Details: {e.content.decode()}"
        raise RuntimeError(error_message)
    except Exception as e:
        logger.error(f"Unexpected error in list_calendars for user "
                     f"{user_id}: {e}", exc_info=True)
        error_message = f"Failed to list calendars for {user_id}. Reason: {e}"
        raise RuntimeError(error_message)

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
        if not user_id: raise ValueError("Server user ID not configured.")
        calendar_service = await asyncio.to_thread(gauth.get_google_service, 'calendar', 'v3', user_id)
        if calendar_service is None:
            raise RuntimeError("Failed to obtain Google Calendar service. Authentication may be missing or invalid.")
        events_result = await asyncio.to_thread(
            calendar_service.events().list(
                calendarId=calendar_id,
                timeMin=time_min,
                timeMax=time_max,
                maxResults=max_results,
                singleEvents=True, # Often useful
                orderBy='startTime',
                showDeleted=show_deleted
            ).execute
        )
        events = events_result.get('items', []) # Extract items
        # Wrap the list of event dicts in TextContent after JSON serialization
        return [TextContent(type="text", text=json.dumps(events))]

    except (FileNotFoundError, gauth.AuthenticationError) as auth_error:
        logger.warning(f"Authentication required for get_calendar_events "
                       f"(user: {user_id}, calendar: {calendar_id}): {auth_error}")
        # Generate auth URL and raise standard error with data field
        auth_url = await asyncio.to_thread(gauth.get_auth_url, user_id, oauth_state)
        # Re-raise the original auth error
        # TODO: Verify if auth_url generation is still needed here.
        raise auth_error
    except HttpError as e:
        # Check for 404 specifically, could indicate calendar not found
        if e.resp.status == 404:
            logger.warning(f"Calendar {calendar_id} not found for user {user_id}: {e}")
            error_message = f"Calendar with ID '{calendar_id}' not found."
            raise ValueError(error_message) # Indicate invalid calendar ID
        else:
            logger.error(f"Google API HTTP error in get_calendar_events for user "
                         f"{user_id}, calendar {calendar_id}: {e}", exc_info=True)
            error_message = f"Google API Error: {e.resp.status} {e.reason}. Details: {e.content.decode()}"
            raise RuntimeError(error_message)
    except Exception as e:
        logger.error(f"Unexpected error in get_calendar_events for user "
                     f"{user_id}, calendar {calendar_id}: {e}", exc_info=True)
        error_message = f"Failed to get events for calendar {calendar_id} for user {user_id}. Reason: {e}"
        raise RuntimeError(error_message)
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
        if not user_id: raise ValueError("Server user ID not configured.")
        calendar_service = await asyncio.to_thread(gauth.get_google_service, 'calendar', 'v3', user_id)
        if calendar_service is None:
            raise RuntimeError("Failed to obtain Google Calendar service. Authentication may be missing or invalid.")

        event_body = {
            'summary': summary,
            'location': location,
            'description': description,
            'start': {
                'dateTime': start_time,
                'timeZone': timezone, # Google API expects timezone here
            },
            'end': {
                'dateTime': end_time,
                'timeZone': timezone, # Google API expects timezone here
            },
            'attendees': [{'email': email} for email in attendees] if attendees else [],
            # Add other fields as needed, e.g., recurrence, reminders
        }

        event = await asyncio.to_thread(
            calendar_service.events().insert(
                calendarId=calendar_id,
                body=event_body,
                sendNotifications=send_notifications
            ).execute
        )
        # Assuming create_event returns the created event object or raises error
        # Wrap the event dict in TextContent after JSON serialization
        return [TextContent(type="text", text=json.dumps(event))]

    except (FileNotFoundError, gauth.AuthenticationError) as auth_error:
        logger.warning(f"Authentication required for create_calendar_event "
                       f"(user: {user_id}, calendar: {calendar_id}): {auth_error}")
        # Generate auth URL and raise standard error with data field
        auth_url = await asyncio.to_thread(gauth.get_auth_url, user_id, oauth_state)
        # Re-raise the original auth error
        # TODO: Verify if auth_url generation is still needed here.
        raise auth_error
    except HttpError as e:
        # Check for 404 specifically, could indicate calendar not found
        if e.resp.status == 404:
            logger.warning(f"Calendar {calendar_id} not found for event creation by user "
                           f"{user_id}: {e}")
            error_message = f"Calendar with ID '{calendar_id}' not found."
            raise ValueError(error_message) # Indicate invalid calendar ID
        else:
            logger.error(f"Google API HTTP error in create_calendar_event for user "
                         f"{user_id}, calendar {calendar_id}: {e}", exc_info=True)
            error_message = f"Google API Error: {e.resp.status} {e.reason}. Details: {e.content.decode()}"
            raise RuntimeError(error_message)
    except ValueError as ve: # Catch potential validation errors from service layer
        logger.warning(f"Validation error creating event for user {user_id}, "
                       f"calendar {calendar_id}: {ve}")
        # Re-raise the original validation error
        raise ve
    except Exception as e:
        logger.error(f"Unexpected error in create_calendar_event for user "
                     f"{user_id}, calendar {calendar_id}: {e}", exc_info=True)
        error_message = f"Failed to create event in calendar {calendar_id} for user {user_id}. Reason: {e}"
        raise RuntimeError(error_message)

async def delete_calendar_event(
    oauth_state: str,
    event_id: str,
    user_id: str,
    calendar_id: str = 'primary',
    send_notifications: bool = True
) -> Sequence[TextContent | ImageContent | EmbeddedResource]:
    """Deletes a Google Calendar event by ID."""
    try:
        if not user_id: raise ValueError("Server user ID not configured.")
        calendar_service = await asyncio.to_thread(gauth.get_google_service, 'calendar', 'v3', user_id)
        if calendar_service is None:
            raise RuntimeError("Failed to obtain Google Calendar service. Authentication may be missing or invalid.")

        # Google API delete returns nothing on success, raises HttpError on failure (like 404)
        await asyncio.to_thread(
            calendar_service.events().delete(
                calendarId=calendar_id,
                eventId=event_id,
                sendNotifications=send_notifications
            ).execute
        )

        # If execute() doesn't raise an error, it was successful.
        status_dict = {"status": "success", "message": f"Event {event_id} successfully deleted from calendar {calendar_id}"}
        return [TextContent(type="text", text=json.dumps(status_dict))]

        # The 'else' block is removed as HttpError handles failure cases below.

    except (FileNotFoundError, gauth.AuthenticationError) as auth_error:
        logger.warning(f"Authentication required for delete_calendar_event "
                       f"(user: {user_id}, calendar: {calendar_id}, event: {event_id}): {auth_error}")
        # Generate auth URL and raise standard error with data field
        auth_url = await asyncio.to_thread(gauth.get_auth_url, user_id, oauth_state)
        # Re-raise the original auth error
        # TODO: Verify if auth_url generation is still needed here.
        raise auth_error
    except HttpError as e:
        # Check for 404 (event not found) or 410 (event gone/deleted)
        if e.resp.status in [404, 410]:
            logger.warning(f"Event {event_id} not found or already gone in calendar "
                           f"{calendar_id} for user {user_id}: {e}")
            # Consider returning success or specific code? For now, raise specific error.
            error_message = f"Event with ID {event_id} not found or already deleted in calendar '{calendar_id}'."
            raise ValueError(error_message) # Indicate invalid event ID or state
        else:
            logger.error(f"Google API HTTP error in delete_calendar_event for user "
                         f"{user_id}, calendar {calendar_id}, event {event_id}: {e}", exc_info=True)
            error_message = f"Google API Error: {e.resp.status} {e.reason}. Details: {e.content.decode()}"
            raise RuntimeError(error_message)
    except Exception as e:
        logger.error(f"Unexpected error in delete_calendar_event for user "
                     f"{user_id}, calendar {calendar_id}, event {event_id}: {e}", exc_info=True)
        error_message = f"Failed to delete event {event_id} from calendar {calendar_id} for user {user_id}. Reason: {e}"
        raise RuntimeError(error_message)
##-##

##-##

#-#