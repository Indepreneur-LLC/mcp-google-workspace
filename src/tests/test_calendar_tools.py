import pytest
import json
from unittest.mock import patch, MagicMock
from datetime import datetime
import pytz

# Adjust import path based on how pytest discovers tests relative to the src root
from mcp_gsuite import toolhandler, calendar
from mcp_gsuite.tools_calendar import (
    ListCalendarsToolHandler,
    GetCalendarEventsToolHandler,
    CreateCalendarEventToolHandler,
    DeleteCalendarEventToolHandler,
    CALENDAR_ID_ARG
)
from mcp.types import TextContent

TEST_USER_ID = "test-calendar-user@example.com"
TEST_CALENDAR_ID = "primary"
TEST_EVENT_ID = "testevent123"

# --- Tests for ListCalendarsToolHandler ---

@pytest.fixture
def list_calendars_handler():
    """Fixture to provide an instance of ListCalendarsToolHandler."""
    return ListCalendarsToolHandler()

@patch('mcp_gsuite.tools_calendar.calendar.CalendarService')
def test_list_calendars_success(mock_calendar_service_class, list_calendars_handler):
    """Test successful execution of list_calendars tool."""
    # Arrange
    mock_service_instance = MagicMock()
    mock_calendar_service_class.return_value = mock_service_instance

    mock_calendars_response = [
        {'id': 'primary', 'summary': 'Main Calendar', 'primary': True},
        {'id': 'holidays@group.v.calendar.google.com', 'summary': 'Holidays', 'primary': False}
    ]
    mock_service_instance.list_calendars.return_value = mock_calendars_response

    args = {
        toolhandler.USER_ID_ARG: TEST_USER_ID
    }

    # Act
    results = list_calendars_handler.run_tool(args)

    # Assert
    mock_calendar_service_class.assert_called_once_with(user_id=TEST_USER_ID)
    mock_service_instance.list_calendars.assert_called_once_with()

    assert len(results) == 1
    assert isinstance(results[0], TextContent)
    assert results[0].type == "text"

    expected_json = json.dumps(mock_calendars_response, indent=2)
    assert results[0].text == expected_json

@patch('mcp_gsuite.tools_calendar.calendar.CalendarService')
def test_list_calendars_missing_user_id(mock_calendar_service_class, list_calendars_handler):
    """Test list_calendars tool raises error if user_id is missing."""
    # Arrange
    args = {} # Missing user_id

    # Act & Assert
    with pytest.raises(RuntimeError) as excinfo:
        list_calendars_handler.run_tool(args)
    assert toolhandler.USER_ID_ARG in str(excinfo.value)
    mock_calendar_service_class.assert_not_called()

@patch('mcp_gsuite.tools_calendar.calendar.CalendarService')
def test_list_calendars_api_error(mock_calendar_service_class, list_calendars_handler):
    """Test list_calendars tool handles underlying API errors (returns empty list)."""
    # Arrange
    mock_service_instance = MagicMock()
    mock_calendar_service_class.return_value = mock_service_instance
    # Simulate the CalendarService returning an empty list on error
    mock_service_instance.list_calendars.return_value = []

    args = {
        toolhandler.USER_ID_ARG: TEST_USER_ID
    }

    # Act
    results = list_calendars_handler.run_tool(args)

    # Assert
    mock_calendar_service_class.assert_called_once_with(user_id=TEST_USER_ID)
    mock_service_instance.list_calendars.assert_called_once_with()

    assert len(results) == 1
    assert isinstance(results[0], TextContent)
    assert results[0].type == "text"
    assert results[0].text == json.dumps([], indent=2) # Expect empty list JSON


# --- Tests for GetCalendarEventsToolHandler ---

@pytest.fixture
def get_events_handler():
    """Fixture to provide an instance of GetCalendarEventsToolHandler."""
    return GetCalendarEventsToolHandler()

@patch('mcp_gsuite.tools_calendar.calendar.CalendarService')
def test_get_events_success(mock_calendar_service_class, get_events_handler):
    """Test successful retrieval of events with default parameters."""
    # Arrange
    mock_service_instance = MagicMock()
    mock_calendar_service_class.return_value = mock_service_instance

    mock_events_response = [
        {'id': 'event1', 'summary': 'Meeting 1', 'start': {'dateTime': '2024-01-01T10:00:00Z'}},
        {'id': 'event2', 'summary': 'Meeting 2', 'start': {'dateTime': '2024-01-01T11:00:00Z'}}
    ]
    mock_service_instance.get_events.return_value = mock_events_response

    args = {
        toolhandler.USER_ID_ARG: TEST_USER_ID,
        CALENDAR_ID_ARG: TEST_CALENDAR_ID
    }

    # Act
    results = get_events_handler.run_tool(args)

    # Assert
    mock_calendar_service_class.assert_called_once_with(user_id=TEST_USER_ID)
    # Assert that get_events was called with expected defaults (time_min=None or checked, max_results=250, show_deleted=False)
    mock_service_instance.get_events.assert_called_once()
    call_args, call_kwargs = mock_service_instance.get_events.call_args
    assert call_kwargs.get('calendar_id') == TEST_CALENDAR_ID
    assert call_kwargs.get('time_min') is None # Handler passes None, service defaults internally
    assert call_kwargs.get('time_max') is None
    assert call_kwargs.get('max_results') == 250
    assert call_kwargs.get('show_deleted') is False

    assert len(results) == 1
    assert isinstance(results[0], TextContent)
    expected_json = json.dumps(mock_events_response, indent=2)
    assert results[0].text == expected_json

@patch('mcp_gsuite.tools_calendar.calendar.CalendarService')
def test_get_events_with_time_range(mock_calendar_service_class, get_events_handler):
    """Test retrieval of events with specific time range and other args."""
    # Arrange
    mock_service_instance = MagicMock()
    mock_calendar_service_class.return_value = mock_service_instance
    mock_events_response = [{'id': 'event3', 'summary': 'Specific Event'}]
    mock_service_instance.get_events.return_value = mock_events_response

    time_min_str = "2024-02-01T00:00:00Z"
    time_max_str = "2024-02-29T23:59:59Z"
    max_res = 10
    show_del = True
    specific_cal_id = "specific_cal@example.com"

    args = {
        toolhandler.USER_ID_ARG: TEST_USER_ID,
        CALENDAR_ID_ARG: specific_cal_id,
        "time_min": time_min_str,
        "time_max": time_max_str,
        "max_results": max_res,
        "show_deleted": show_del
    }

    # Act
    results = get_events_handler.run_tool(args)

    # Assert
    mock_calendar_service_class.assert_called_once_with(user_id=TEST_USER_ID)
    mock_service_instance.get_events.assert_called_once_with(
        calendar_id=specific_cal_id,
        time_min=time_min_str,
        time_max=time_max_str,
        max_results=max_res,
        show_deleted=show_del
    )

    assert len(results) == 1
    assert isinstance(results[0], TextContent)
    expected_json = json.dumps(mock_events_response, indent=2)
    assert results[0].text == expected_json

@patch('mcp_gsuite.tools_calendar.calendar.CalendarService')
def test_get_events_missing_user_id(mock_calendar_service_class, get_events_handler):
    """Test get_events tool raises error if user_id is missing."""
    # Arrange
    args = {
        "time_min": "2024-01-01T00:00:00Z"
    } # Missing user_id

    # Act & Assert
    with pytest.raises(RuntimeError) as excinfo:
        get_events_handler.run_tool(args)
    assert toolhandler.USER_ID_ARG in str(excinfo.value)
    mock_calendar_service_class.assert_not_called()

@patch('mcp_gsuite.tools_calendar.calendar.CalendarService')
def test_get_events_api_error(mock_calendar_service_class, get_events_handler):
    """Test get_events tool handles underlying API errors (returns empty list)."""
    # Arrange
    mock_service_instance = MagicMock()
    mock_calendar_service_class.return_value = mock_service_instance
    # Simulate the CalendarService returning an empty list on error
    mock_service_instance.get_events.return_value = []

    args = {
        toolhandler.USER_ID_ARG: TEST_USER_ID
    }

    # Act
    results = get_events_handler.run_tool(args)

    # Assert
    mock_calendar_service_class.assert_called_once_with(user_id=TEST_USER_ID)
    mock_service_instance.get_events.assert_called_once() # Check it was called

    assert len(results) == 1
    assert isinstance(results[0], TextContent)
    assert results[0].text == json.dumps([], indent=2) # Expect empty list JSON


# --- Tests for CreateCalendarEventToolHandler ---

@pytest.fixture
def create_event_handler():
    """Fixture to provide an instance of CreateCalendarEventToolHandler."""
    return CreateCalendarEventToolHandler()

@patch('mcp_gsuite.tools_calendar.calendar.CalendarService')
def test_create_event_success(mock_calendar_service_class, create_event_handler):
    """Test successful creation of a calendar event."""
    # Arrange
    mock_service_instance = MagicMock()
    mock_calendar_service_class.return_value = mock_service_instance

    mock_created_event_response = {
        'id': TEST_EVENT_ID,
        'summary': 'Test Event',
        'start': {'dateTime': '2024-03-01T10:00:00Z'},
        'end': {'dateTime': '2024-03-01T11:00:00Z'}
    }
    mock_service_instance.create_event.return_value = mock_created_event_response

    start_time = "2024-03-01T10:00:00Z"
    end_time = "2024-03-01T11:00:00Z"
    summary = "Test Event"
    attendees = ["attendee1@example.com"]
    timezone = "America/New_York"

    args = {
        toolhandler.USER_ID_ARG: TEST_USER_ID,
        CALENDAR_ID_ARG: TEST_CALENDAR_ID,
        "summary": summary,
        "start_time": start_time,
        "end_time": end_time,
        "location": "Test Location",
        "description": "Test Description",
        "attendees": attendees,
        "send_notifications": False,
        "timezone": timezone
    }

    # Act
    results = create_event_handler.run_tool(args)

    # Assert
    mock_calendar_service_class.assert_called_once_with(user_id=TEST_USER_ID)
    mock_service_instance.create_event.assert_called_once_with(
        calendar_id=TEST_CALENDAR_ID,
        summary=summary,
        start_time=start_time,
        end_time=end_time,
        location="Test Location",
        description="Test Description",
        attendees=attendees,
        send_notifications=False,
        timezone=timezone
    )

    assert len(results) == 1
    assert isinstance(results[0], TextContent)
    expected_json = json.dumps(mock_created_event_response, indent=2)
    assert results[0].text == expected_json

@patch('mcp_gsuite.tools_calendar.calendar.CalendarService')
def test_create_event_missing_args(mock_calendar_service_class, create_event_handler):
    """Test create_event tool raises error if required args are missing."""
    required_args = ["summary", "start_time", "end_time"]
    base_args = {
        toolhandler.USER_ID_ARG: TEST_USER_ID,
        "summary": "s", "start_time": "st", "end_time": "et"
    }

    # Test missing user_id first
    args_no_user = base_args.copy()
    del args_no_user[toolhandler.USER_ID_ARG]
    with pytest.raises(RuntimeError) as excinfo:
        create_event_handler.run_tool(args_no_user)
    assert toolhandler.USER_ID_ARG in str(excinfo.value)

    # Test missing other required args
    for arg_to_remove in required_args:
        args = base_args.copy()
        del args[arg_to_remove]
        with pytest.raises(RuntimeError) as excinfo:
            create_event_handler.run_tool(args)
        # The handler checks all required args at once
        assert "Missing required arguments" in str(excinfo.value)

    mock_calendar_service_class.assert_not_called()


@patch('mcp_gsuite.tools_calendar.calendar.CalendarService')
def test_create_event_api_error(mock_calendar_service_class, create_event_handler):
    """Test create_event tool handles API failure (returns None)."""
    # Arrange
    mock_service_instance = MagicMock()
    mock_calendar_service_class.return_value = mock_service_instance
    mock_service_instance.create_event.return_value = None # Simulate API failure

    args = {
        toolhandler.USER_ID_ARG: TEST_USER_ID,
        "summary": "Fail Event",
        "start_time": "2024-03-01T12:00:00Z",
        "end_time": "2024-03-01T13:00:00Z"
    }

    # Act
    results = create_event_handler.run_tool(args)

    # Assert
    mock_calendar_service_class.assert_called_once_with(user_id=TEST_USER_ID)
    mock_service_instance.create_event.assert_called_once() # Called but returned None

    assert len(results) == 1
    assert isinstance(results[0], TextContent)
    # The handler returns the None value from the service as JSON 'null'
    assert results[0].text == json.dumps(None, indent=2)


# --- Tests for DeleteCalendarEventToolHandler ---

@pytest.fixture
def delete_event_handler():
    """Fixture to provide an instance of DeleteCalendarEventToolHandler."""
    return DeleteCalendarEventToolHandler()

@patch('mcp_gsuite.tools_calendar.calendar.CalendarService')
def test_delete_event_success(mock_calendar_service_class, delete_event_handler):
    """Test successful deletion of a calendar event."""
    # Arrange
    mock_service_instance = MagicMock()
    mock_calendar_service_class.return_value = mock_service_instance
    mock_service_instance.delete_event.return_value = True # Simulate success

    args = {
        toolhandler.USER_ID_ARG: TEST_USER_ID,
        CALENDAR_ID_ARG: TEST_CALENDAR_ID,
        "event_id": TEST_EVENT_ID,
        "send_notifications": False
    }

    # Act
    results = delete_event_handler.run_tool(args)

    # Assert
    mock_calendar_service_class.assert_called_once_with(user_id=TEST_USER_ID)
    mock_service_instance.delete_event.assert_called_once_with(
        calendar_id=TEST_CALENDAR_ID,
        event_id=TEST_EVENT_ID,
        send_notifications=False
    )

    assert len(results) == 1
    assert isinstance(results[0], TextContent)
    expected_response = {"success": True, "message": "Event successfully deleted"}
    assert results[0].text == json.dumps(expected_response, indent=2)

@patch('mcp_gsuite.tools_calendar.calendar.CalendarService')
def test_delete_event_failure(mock_calendar_service_class, delete_event_handler):
    """Test handling of event deletion failure."""
    # Arrange
    mock_service_instance = MagicMock()
    mock_calendar_service_class.return_value = mock_service_instance
    mock_service_instance.delete_event.return_value = False # Simulate failure

    args = {
        toolhandler.USER_ID_ARG: TEST_USER_ID,
        "event_id": TEST_EVENT_ID
        # Use default calendar_id and send_notifications=True
    }

    # Act
    results = delete_event_handler.run_tool(args)

    # Assert
    mock_calendar_service_class.assert_called_once_with(user_id=TEST_USER_ID)
    mock_service_instance.delete_event.assert_called_once_with(
        calendar_id='primary', # Default
        event_id=TEST_EVENT_ID,
        send_notifications=True # Default
    )

    assert len(results) == 1
    assert isinstance(results[0], TextContent)
    expected_response = {"success": False, "message": "Failed to delete event"}
    assert results[0].text == json.dumps(expected_response, indent=2)

@patch('mcp_gsuite.tools_calendar.calendar.CalendarService')
def test_delete_event_missing_args(mock_calendar_service_class, delete_event_handler):
    """Test delete_event tool raises error if required args are missing."""
    # Test missing event_id
    with pytest.raises(RuntimeError) as excinfo:
        delete_event_handler.run_tool({toolhandler.USER_ID_ARG: TEST_USER_ID})
    assert "Missing required argument: event_id" in str(excinfo.value)

    # Test missing user_id
    with pytest.raises(RuntimeError) as excinfo:
        delete_event_handler.run_tool({"event_id": TEST_EVENT_ID})
    assert toolhandler.USER_ID_ARG in str(excinfo.value)

    mock_calendar_service_class.assert_not_called()