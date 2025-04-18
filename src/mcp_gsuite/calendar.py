from googleapiclient.discovery import build
from googleapiclient.errors import HttpError # Import HttpError
# Removed gauth import
import logging
import traceback # Keep for internal logging for now
from datetime import datetime
import pytz # Keep for default time_min logic
from google.oauth2.credentials import Credentials # Import Credentials type hint

# Define custom exceptions
class CalendarNotFoundError(Exception):
    pass

class EventNotFoundError(Exception):
    pass
class CalendarService():
    def __init__(self, credentials: Credentials):
        # Removed user_id lookup, credentials passed directly
        if not credentials:
             raise ValueError("Credentials must be provided to CalendarService.")
        try:
            # Build the service - can raise errors on invalid creds
            self.service = build('calendar', 'v3', credentials=credentials)
        except Exception as e:
            logger.error(f"Failed to build Calendar service: {e}", exc_info=True)
            raise RuntimeError(f"Failed to initialize Calendar service: {e}") from e
    
    def list_calendars(self) -> list: # Raises HttpError on failure
        """
        Lists all calendars accessible by the user.
        
        Returns:
            list: List of calendar objects with their metadata
        """
        # Removed outer try/except - let HttpError propagate
        # This call can raise HttpError
        calendar_list = self.service.calendarList().list().execute()

        calendars = []
        # Use .get() for safer access
        for calendar_entry in calendar_list.get('items', []):
            # Basic check for expected type
            if calendar_entry.get('kind') == 'calendar#calendarListEntry':
                calendars.append({
                    'id': calendar_entry.get('id'),
                    'summary': calendar_entry.get('summary'),
                    'description': calendar_entry.get('description'), # Add description
                    'primary': calendar_entry.get('primary', False),
                    'time_zone': calendar_entry.get('timeZone'),
                    'access_role': calendar_entry.get('accessRole'),
                    'color_id': calendar_entry.get('colorId'), # Add color
                    'selected': calendar_entry.get('selected') # Add selected status
                })
            else:
                 logger.warning(f"Skipping unexpected item in calendar list: {calendar_entry.get('kind')}")

        return calendars

    def get_events(self, time_min=None, time_max=None, max_results=250, show_deleted=False, calendar_id: str ='primary') -> list: # Raises HttpError, CalendarNotFoundError
        """
        Retrieve calendar events within a specified time range.
        
        Args:
            time_min (str, optional): Start time in RFC3339 format. Defaults to current time.
            time_max (str, optional): End time in RFC3339 format
            max_results (int): Maximum number of events to return (1-2500)
            show_deleted (bool): Whether to include deleted events
            
        Returns:
            list: List of calendar events
        """
        # Removed outer try/except - let HttpError propagate
        # If no time_min specified, use current time
        if not time_min:
            time_min = datetime.now(pytz.UTC).isoformat()

        # Ensure max_results is within limits
        max_results = min(max(1, max_results), 2500)

        # Prepare parameters
        params = {
            'calendarId': calendar_id,
            'timeMin': time_min,
            'maxResults': max_results,
            'singleEvents': True, # Important for expanding recurring events
            'orderBy': 'startTime',
            'showDeleted': show_deleted
        }

        # Add optional time_max if specified
        if time_max:
            params['timeMax'] = time_max

        # Execute the events().list() method - can raise HttpError
        try:
            events_result = self.service.events().list(**params).execute()
        except HttpError as e:
            if e.resp.status == 404:
                raise CalendarNotFoundError(f"Calendar with ID '{calendar_id}' not found.") from e
            else:
                # Re-raise other HttpErrors
                raise

        # Extract the events
        events = events_result.get('items', [])

        # Process and return the events (keep existing processing logic)
        processed_events = []
        for event in events:
            # Add more fields if needed, e.g., htmlLink
            processed_event = {
                'id': event.get('id'),
                'summary': event.get('summary'),
                'description': event.get('description'),
                'start': event.get('start'), # Contains dateTime or date
                'end': event.get('end'),     # Contains dateTime or date
                'status': event.get('status'), # confirmed, tentative, cancelled
                'creator': event.get('creator'), # { email, displayName, self }
                'organizer': event.get('organizer'), # { email, displayName, self }
                'attendees': event.get('attendees'), # List of { email, displayName, self, responseStatus }
                'location': event.get('location'),
                'hangoutLink': event.get('hangoutLink'),
                'conferenceData': event.get('conferenceData'),
                'recurringEventId': event.get('recurringEventId'),
                'htmlLink': event.get('htmlLink'), # Link to event in Google Calendar UI
                'created': event.get('created'),
                'updated': event.get('updated')
            }
            processed_events.append(processed_event)

        return processed_events
        
    def create_event(self, summary: str, start_time: str, end_time: str, 
                location: str | None = None, description: str | None = None, 
                attendees: list | None = None, send_notifications: bool = True,
                timezone: str | None = None,
                calendar_id : str = 'primary') -> dict: # Raises HttpError, CalendarNotFoundError, ValueError
        """
        Create a new calendar event.
        
        Args:
            summary (str): Title of the event
            start_time (str): Start time in RFC3339 format
            end_time (str): End time in RFC3339 format
            location (str, optional): Location of the event
            description (str, optional): Description of the event
            attendees (list, optional): List of attendee email addresses
            send_notifications (bool): Whether to send notifications to attendees
            timezone (str, optional): Timezone for the event (e.g. 'America/New_York')
            
        Returns:
            dict: Created event data or None if creation fails
        """
        # Removed outer try/except - let HttpError/ValueError propagate
        # Basic validation (more robust date parsing could be added)
        if not summary or not start_time or not end_time:
             raise ValueError("Summary, start_time, and end_time are required to create an event.")

        # Prepare event data
        event_body = {
            'summary': summary,
            'start': {
                'dateTime': start_time,
                'timeZone': timezone or 'UTC', # Default to UTC if not specified
            },
            'end': {
                'dateTime': end_time,
                'timeZone': timezone or 'UTC', # Default to UTC if not specified
            }
        }

        # Add optional fields if provided
        if location:
            event_body['location'] = location
        if description:
            event_body['description'] = description
        if attendees:
            # Validate attendee format slightly
            if not isinstance(attendees, list) or not all(isinstance(a, str) for a in attendees):
                 raise ValueError("Attendees must be a list of email strings.")
            event_body['attendees'] = [{'email': email} for email in attendees]

        # Create the event - can raise HttpError
        try:
            created_event = self.service.events().insert(
                calendarId=calendar_id,
                body=event_body,
                sendNotifications=send_notifications
            ).execute()
            return created_event
        except HttpError as e:
            if e.resp.status == 404:
                raise CalendarNotFoundError(f"Calendar with ID '{calendar_id}' not found.") from e
            else:
                # Re-raise other HttpErrors (e.g., 400 for bad request/invalid time format)
                raise
        
    def delete_event(self, event_id: str, send_notifications: bool = True, calendar_id: str = 'primary') -> bool: # Raises HttpError, EventNotFoundError
        """
        Delete a calendar event by its ID.
        
        Args:
            event_id (str): The ID of the event to delete
            send_notifications (bool): Whether to send cancellation notifications to attendees
            
        Returns:
            bool: True if deletion was successful, False otherwise
        """
        # Removed outer try/except - let HttpError propagate
        try:
            # This call can raise HttpError
            self.service.events().delete(
                calendarId=calendar_id,
                eventId=event_id,
                sendNotifications=send_notifications
            ).execute()
            # Google API returns empty body on success for delete
            return True
        except HttpError as e:
            # 404 or 410 indicate event not found/gone
            if e.resp.status in [404, 410]:
                raise EventNotFoundError(f"Event with ID '{event_id}' not found or already deleted in calendar '{calendar_id}'.") from e
            else:
                # Re-raise other HttpErrors
                raise