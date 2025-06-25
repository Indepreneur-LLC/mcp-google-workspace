# Tests for src/mcp_google_workspace/tools_calendar.py
import pytest
from unittest.mock import MagicMock, patch
import json

# TODO: Add tests
# Assuming gauth.AuthenticationError is defined somewhere accessible for testing
# If not, we might need to define a dummy exception or adjust the import
try:
    from mcp_google_workspace import gauth
    AuthenticationError = gauth.AuthenticationError
except (ImportError, AttributeError):
    # Define a dummy exception if gauth or AuthenticationError cannot be imported
    class AuthenticationError(Exception):
        pass

# Import the functions to test
from mcp_google_workspace.tools_calendar import list_calendars
from mcp.types import TextContent # Import TextContent

# Define common test variables
TEST_USER_ID = "circa@indepreneur.io"
TEST_OAUTH_STATE = "test_state_123"

@pytest.mark.asyncio
@patch('src.mcp_google_workspace.tools_calendar.asyncio.to_thread', side_effect=lambda func, *args, **kwargs: func(*args, **kwargs)) # Mock asyncio.to_thread
@patch('mcp_google_workspace.tools_calendar.gauth.get_google_service')
async def test_list_calendars_success(mock_get_service, mock_to_thread, mocker):
    """Tests successful listing of calendars."""
    # Arrange
    mock_service = MagicMock()
    mock_calendar_list = MagicMock()
    mock_list_request = MagicMock()
    # Simulate the structure returned by calendar_service.calendarList().list().execute()
    mock_list_request.execute.return_value = {'items': [{'id': 'cal1', 'summary': 'Test Calendar'}]}
    mock_calendar_list.list.return_value = mock_list_request
    mock_service.calendarList.return_value = mock_calendar_list
    mock_get_service.return_value = mock_service

    # Act
    result = await list_calendars(oauth_state=TEST_OAUTH_STATE, user_id=TEST_USER_ID)

    # Assert
    mock_get_service.assert_called_once_with('calendar', 'v3', TEST_USER_ID)
    mock_service.calendarList.assert_called_once()
    mock_calendar_list.list.assert_called_once()
    mock_list_request.execute.assert_called_once()
    assert isinstance(result, list)
    assert len(result) == 1
    assert isinstance(result[0], TextContent)
    assert result[0].type == "text"
    # The function returns the whole result dict, not just items
    expected_json = json.dumps({'items': [{'id': 'cal1', 'summary': 'Test Calendar'}]})
    assert result[0].text == expected_json

@pytest.mark.asyncio
@patch('src.mcp_google_workspace.tools_calendar.asyncio.to_thread', side_effect=lambda func, *args, **kwargs: func(*args, **kwargs)) # Mock asyncio.to_thread
@patch('mcp_google_workspace.tools_calendar.gauth.get_auth_url', return_value="http://auth.url/test") # Mock get_auth_url
@patch('mcp_google_workspace.tools_calendar.gauth.get_google_service')
async def test_list_calendars_auth_error(mock_get_service, mock_get_auth_url, mock_to_thread, mocker):
    """Tests handling of AuthenticationError during calendar listing."""
    # Arrange
    mock_get_service.side_effect = AuthenticationError("Test Auth Error")

    # Act & Assert
    with pytest.raises(AuthenticationError, match="Test Auth Error"):
        await list_calendars(oauth_state=TEST_OAUTH_STATE, user_id=TEST_USER_ID)

    # Assert get_google_service was called
    mock_get_service.assert_called_once_with('calendar', 'v3', TEST_USER_ID)
    # Assert get_auth_url was called after the exception (as per the code logic)
    mock_get_auth_url.assert_called_once_with(TEST_USER_ID, TEST_OAUTH_STATE)

@pytest.mark.asyncio
@patch('src.mcp_google_workspace.tools_calendar.asyncio.to_thread', side_effect=lambda func, *args, **kwargs: func(*args, **kwargs)) # Mock asyncio.to_thread
@patch('mcp_google_workspace.tools_calendar.gauth.get_google_service')
async def test_list_calendars_service_none(mock_get_service, mock_to_thread, mocker):
    """Tests handling when get_google_service returns None."""
    # Arrange
    mock_get_service.return_value = None

    # Act & Assert
    with pytest.raises(RuntimeError, match="Failed to obtain Google Calendar service"):
        await list_calendars(oauth_state=TEST_OAUTH_STATE, user_id=TEST_USER_ID)

# Tests for get_calendar_events
from mcp_google_workspace.tools_calendar import get_calendar_events
from googleapiclient.errors import HttpError
from io import BytesIO # Needed for HttpError mock response

# Mock HttpError response helper
def create_http_error_response(status_code, reason="Error", content=b'{"error": "details"}'):
    resp = MagicMock()
    resp.status = status_code
    resp.reason = reason
    # HttpError expects content as bytes
    return HttpError(resp, content)

@pytest.mark.asyncio
@patch('src.mcp_google_workspace.tools_calendar.asyncio.to_thread', side_effect=lambda func, *args, **kwargs: func(*args, **kwargs))
@patch('mcp_google_workspace.tools_calendar.gauth.get_google_service')
async def test_get_calendar_events_success(mock_get_service, mock_to_thread, mocker):
    """Tests successful retrieval of calendar events."""
    # Arrange
    mock_service = MagicMock()
    mock_events = MagicMock()
    mock_list_request = MagicMock()
    # Simulate the structure returned by calendar_service.events().list().execute()
    mock_list_request.execute.return_value = {'items': [{'id': 'evt1', 'summary': 'Test Event'}]}
    mock_events.list.return_value = mock_list_request
    mock_service.events.return_value = mock_events
    mock_get_service.return_value = mock_service

    # Act
    result = await get_calendar_events(oauth_state=TEST_OAUTH_STATE, user_id=TEST_USER_ID, calendar_id='primary')

    # Assert
    mock_get_service.assert_called_once_with('calendar', 'v3', TEST_USER_ID)
    mock_service.events.assert_called_once()
    mock_events.list.assert_called_once_with(
        calendarId='primary',
        timeMin=None,
        timeMax=None,
        maxResults=250,
        singleEvents=True,
        orderBy='startTime',
        showDeleted=False
    )
    mock_list_request.execute.assert_called_once()
    assert isinstance(result, list)
    assert len(result) == 1
    assert isinstance(result[0], TextContent)
    # The function extracts and returns the 'items' list as JSON
    expected_json = json.dumps([{'id': 'evt1', 'summary': 'Test Event'}])
    assert result[0].text == expected_json

@pytest.mark.asyncio
@patch('src.mcp_google_workspace.tools_calendar.asyncio.to_thread', side_effect=lambda func, *args, **kwargs: func(*args, **kwargs))
@patch('mcp_google_workspace.tools_calendar.gauth.get_auth_url', return_value="http://auth.url/test")
@patch('mcp_google_workspace.tools_calendar.gauth.get_google_service')
async def test_get_calendar_events_auth_error(mock_get_service, mock_get_auth_url, mock_to_thread, mocker):
    """Tests handling of AuthenticationError during event retrieval."""
    # Arrange
    mock_get_service.side_effect = AuthenticationError("Test Auth Error")

    # Act & Assert
    with pytest.raises(AuthenticationError, match="Test Auth Error"):
        await get_calendar_events(oauth_state=TEST_OAUTH_STATE, user_id=TEST_USER_ID)

    mock_get_service.assert_called_once_with('calendar', 'v3', TEST_USER_ID)
    mock_get_auth_url.assert_called_once_with(TEST_USER_ID, TEST_OAUTH_STATE)


@pytest.mark.asyncio
@patch('src.mcp_google_workspace.tools_calendar.asyncio.to_thread', side_effect=lambda func, *args, **kwargs: func(*args, **kwargs))
@patch('mcp_google_workspace.tools_calendar.gauth.get_google_service')
async def test_get_calendar_events_http_error_404(mock_get_service, mock_to_thread, mocker):
    """Tests handling of 404 HttpError (calendar not found)."""
    # Arrange
    mock_service = MagicMock()
    mock_events = MagicMock()
    mock_list_request = MagicMock()
    mock_list_request.execute.side_effect = create_http_error_response(404, "Not Found", b'{"error": "Calendar not found"}')
    mock_events.list.return_value = mock_list_request
    mock_service.events.return_value = mock_events
    mock_get_service.return_value = mock_service

    # Act & Assert
    with pytest.raises(ValueError, match="Calendar with ID 'cal_not_found' not found."):
        await get_calendar_events(oauth_state=TEST_OAUTH_STATE, user_id=TEST_USER_ID, calendar_id='cal_not_found')

    mock_get_service.assert_called_once_with('calendar', 'v3', TEST_USER_ID)
    mock_list_request.execute.assert_called_once()


@pytest.mark.asyncio
@patch('src.mcp_google_workspace.tools_calendar.asyncio.to_thread', side_effect=lambda func, *args, **kwargs: func(*args, **kwargs))
@patch('mcp_google_workspace.tools_calendar.gauth.get_google_service')
async def test_get_calendar_events_http_error_other(mock_get_service, mock_to_thread, mocker):
    """Tests handling of other HttpErrors."""
    # Arrange
    mock_service = MagicMock()
    mock_events = MagicMock()
    mock_list_request = MagicMock()
    error_content = b'{"error": {"message": "API limit exceeded"}}'
    mock_list_request.execute.side_effect = create_http_error_response(403, "Forbidden", error_content)
    mock_events.list.return_value = mock_list_request
    mock_service.events.return_value = mock_events
    mock_get_service.return_value = mock_service

    # Act & Assert
    # Escape special characters in the JSON for regex matching
    expected_pattern = r"Google API Error: 403 API limit exceeded\. Details: \{\"error\": \{\"message\": \"API limit exceeded\"\}\}" # Match actual error output
    with pytest.raises(RuntimeError, match=expected_pattern):
        await get_calendar_events(oauth_state=TEST_OAUTH_STATE, user_id=TEST_USER_ID)

    mock_get_service.assert_called_once_with('calendar', 'v3', TEST_USER_ID)
    mock_list_request.execute.assert_called_once()


# Tests for create_calendar_event
from mcp_google_workspace.tools_calendar import create_calendar_event

@pytest.mark.asyncio
@patch('src.mcp_google_workspace.tools_calendar.asyncio.to_thread', side_effect=lambda func, *args, **kwargs: func(*args, **kwargs))
@patch('mcp_google_workspace.tools_calendar.gauth.get_google_service')
async def test_create_calendar_event_success(mock_get_service, mock_to_thread, mocker):
    """Tests successful creation of a calendar event."""
    # Arrange
    mock_service = MagicMock()
    mock_events = MagicMock()
    mock_insert_request = MagicMock()
    created_event = {
        'id': 'new_event_id',
        'summary': 'Test Meeting',
        'start': {'dateTime': '2025-05-01T10:00:00Z'},
        'end': {'dateTime': '2025-05-01T11:00:00Z'}
    }
    mock_insert_request.execute.return_value = created_event
    mock_events.insert.return_value = mock_insert_request
    mock_service.events.return_value = mock_events
    mock_get_service.return_value = mock_service

    event_details = {
        'summary': 'Test Meeting',
        'start_time': '2025-05-01T10:00:00Z',
        'end_time': '2025-05-01T11:00:00Z',
        'user_id': TEST_USER_ID,
        'oauth_state': TEST_OAUTH_STATE,
        'calendar_id': 'primary',
        'location': 'Office',
        'description': 'A test meeting',
        'attendees': ['attendee@example.com'],
        'send_notifications': False,
        'timezone': 'UTC'
    }

    # Act
    result = await create_calendar_event(**event_details)

    # Assert
    mock_get_service.assert_called_once_with('calendar', 'v3', TEST_USER_ID)
    mock_service.events.assert_called_once()
    expected_body = {
        'summary': 'Test Meeting',
        'location': 'Office',
        'description': 'A test meeting',
        'start': {'dateTime': '2025-05-01T10:00:00Z', 'timeZone': 'UTC'},
        'end': {'dateTime': '2025-05-01T11:00:00Z', 'timeZone': 'UTC'},
        'attendees': [{'email': 'attendee@example.com'}],
    }
    mock_events.insert.assert_called_once_with(
        calendarId='primary',
        body=expected_body,
        sendNotifications=False
    )
    mock_insert_request.execute.assert_called_once()
    assert isinstance(result, list)
    assert len(result) == 1
    assert isinstance(result[0], TextContent)
    expected_json = json.dumps(created_event)
    assert result[0].text == expected_json

@pytest.mark.asyncio
@patch('src.mcp_google_workspace.tools_calendar.asyncio.to_thread', side_effect=lambda func, *args, **kwargs: func(*args, **kwargs))
@patch('mcp_google_workspace.tools_calendar.gauth.get_auth_url', return_value="http://auth.url/test")
@patch('mcp_google_workspace.tools_calendar.gauth.get_google_service')
async def test_create_calendar_event_auth_error(mock_get_service, mock_get_auth_url, mock_to_thread, mocker):
    """Tests handling of AuthenticationError during event creation."""
    # Arrange
    mock_get_service.side_effect = AuthenticationError("Test Auth Error")
    event_details = {
        'summary': 'Test Meeting', 'start_time': '2025-05-01T10:00:00Z', 'end_time': '2025-05-01T11:00:00Z',
        'user_id': TEST_USER_ID, 'oauth_state': TEST_OAUTH_STATE
    }

    # Act & Assert
    with pytest.raises(AuthenticationError, match="Test Auth Error"):
        await create_calendar_event(**event_details)

    mock_get_service.assert_called_once_with('calendar', 'v3', TEST_USER_ID)
    mock_get_auth_url.assert_called_once_with(TEST_USER_ID, TEST_OAUTH_STATE)


# Tests for delete_calendar_event
from mcp_google_workspace.tools_calendar import delete_calendar_event

@pytest.mark.asyncio
@patch('src.mcp_google_workspace.tools_calendar.asyncio.to_thread', side_effect=lambda func, *args, **kwargs: func(*args, **kwargs))
@patch('mcp_google_workspace.tools_calendar.gauth.get_google_service')
async def test_delete_calendar_event_success(mock_get_service, mock_to_thread, mocker):
    """Tests successful deletion of a calendar event."""
    # Arrange
    mock_service = MagicMock()
    mock_events = MagicMock()
    mock_delete_request = MagicMock()
    mock_delete_request.execute.return_value = None # Delete returns None on success
    mock_events.delete.return_value = mock_delete_request
    mock_service.events.return_value = mock_events
    mock_get_service.return_value = mock_service

    # Act
    result = await delete_calendar_event(
        oauth_state=TEST_OAUTH_STATE,
        event_id='event_to_delete',
        user_id=TEST_USER_ID,
        calendar_id='primary',
        send_notifications=False
    )

    # Assert
    mock_get_service.assert_called_once_with('calendar', 'v3', TEST_USER_ID)
    mock_service.events.assert_called_once()
    mock_events.delete.assert_called_once_with(
        calendarId='primary',
        eventId='event_to_delete',
        sendNotifications=False
    )
    mock_delete_request.execute.assert_called_once()
    assert isinstance(result, list)
    assert len(result) == 1
    assert isinstance(result[0], TextContent)
    expected_status = {"status": "success", "message": "Event event_to_delete successfully deleted from calendar primary"}
    assert result[0].text == json.dumps(expected_status)


@pytest.mark.asyncio
@patch('src.mcp_google_workspace.tools_calendar.asyncio.to_thread', side_effect=lambda func, *args, **kwargs: func(*args, **kwargs))
@patch('mcp_google_workspace.tools_calendar.gauth.get_auth_url', return_value="http://auth.url/test")
@patch('mcp_google_workspace.tools_calendar.gauth.get_google_service')
async def test_delete_calendar_event_auth_error(mock_get_service, mock_get_auth_url, mock_to_thread, mocker):
    """Tests handling of AuthenticationError during event deletion."""
    # Arrange
    mock_get_service.side_effect = AuthenticationError("Test Auth Error")

    # Act & Assert
    with pytest.raises(AuthenticationError, match="Test Auth Error"):
        await delete_calendar_event(oauth_state=TEST_OAUTH_STATE, event_id='evt1', user_id=TEST_USER_ID)

    mock_get_service.assert_called_once_with('calendar', 'v3', TEST_USER_ID)
    mock_get_auth_url.assert_called_once_with(TEST_USER_ID, TEST_OAUTH_STATE)


@pytest.mark.asyncio
@patch('src.mcp_google_workspace.tools_calendar.asyncio.to_thread', side_effect=lambda func, *args, **kwargs: func(*args, **kwargs))
@patch('mcp_google_workspace.tools_calendar.gauth.get_google_service')
async def test_delete_calendar_event_http_error_404(mock_get_service, mock_to_thread, mocker):
    """Tests handling of 404 HttpError (event not found) during deletion."""
    # Arrange
    mock_service = MagicMock()
    mock_events = MagicMock()
    mock_delete_request = MagicMock()
    mock_delete_request.execute.side_effect = create_http_error_response(404, "Not Found", b'{"error": "Event not found"}')
    mock_events.delete.return_value = mock_delete_request
    mock_service.events.return_value = mock_events
    mock_get_service.return_value = mock_service

    # Act & Assert
    with pytest.raises(ValueError, match="Event with ID event_not_found not found or already deleted"):
        await delete_calendar_event(oauth_state=TEST_OAUTH_STATE, event_id='event_not_found', user_id=TEST_USER_ID)

    mock_get_service.assert_called_once_with('calendar', 'v3', TEST_USER_ID)
    mock_delete_request.execute.assert_called_once()
    # Assert get_google_service was called
    mock_get_service.assert_called_once_with('calendar', 'v3', TEST_USER_ID)

# --- Add tests for other functions below ---