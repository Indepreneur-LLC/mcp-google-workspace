# Tests for src/mcp_google_workspace/tools_gmail.py
import pytest
from unittest.mock import MagicMock, patch

# TODO: Add tests
import pytest
import json
import base64
import os
import asyncio # Added import
# Use unittest.mock.mock_open for better file handle mocking
from unittest.mock import MagicMock, patch, AsyncMock, call, mock_open as unittest_mock_open
from mcp.types import TextContent, EmbeddedResource
from googleapiclient.errors import HttpError
from io import BytesIO

# Assuming gauth.AuthenticationError is defined somewhere accessible for testing
try:
    from mcp_google_workspace import gauth
    AuthenticationError = gauth.AuthenticationError
except (ImportError, AttributeError):
    class AuthenticationError(Exception):
        pass

# Import the functions to test
from mcp_google_workspace.tools_gmail import (
    query_gmail_emails,
    get_gmail_email,
    bulk_get_gmail_emails,
    get_gmail_attachment,
    create_gmail_draft,
    delete_gmail_draft,
    reply_gmail_email,
    bulk_save_gmail_attachments,
    decode_base64_data # Also test the helper
)

# Define common test variables
TEST_USER_ID = "circa@indepreneur.io"
TEST_EMAIL_ID = "test_email_id_789"
TEST_MESSAGE_ID = "test_message_id_abc"
TEST_ATTACHMENT_ID = "test_attachment_id_def"
TEST_DRAFT_ID = "test_draft_id_ghi"
TEST_OAUTH_STATE = "test_gmail_state_789" # Not used by gmail tools, but keep for consistency

# Mock HttpError response helper (copied from previous tests)
def create_http_error_response(status_code, reason="Error", content=b'{"error": "details"}'):
    resp = MagicMock()
    resp.status = status_code
    resp.reason = reason
    return HttpError(resp, content)

# --- Test decode_base64_data helper ---
def test_decode_base64_data_standard():
    encoded = base64.b64encode(b"test data").decode('utf-8')
    assert decode_base64_data(encoded) == b"test data"

def test_decode_base64_data_urlsafe():
    encoded = base64.urlsafe_b64encode(b"test data?").decode('utf-8') # Contains URL-safe chars
    assert decode_base64_data(encoded) == b"test data?"

def test_decode_base64_data_missing_padding():
    # Standard base64 of 'test' is 'dGVzdA=='
    # Urlsafe base64 of 'test' is 'dGVzdA'
    encoded_nopad = "dGVzdA"
    assert decode_base64_data(encoded_nopad) == b"test"

# --- Tests for query_gmail_emails ---

@pytest.mark.asyncio
@patch('src.mcp_google_workspace.tools_gmail.asyncio.to_thread', side_effect=lambda func, *args, **kwargs: func(*args, **kwargs))
@patch('mcp_google_workspace.tools_gmail.gauth.get_google_service')
async def test_query_gmail_emails_success(mock_get_service, mock_to_thread):
    """Tests successful querying of emails."""
    # Arrange
    mock_service = MagicMock()
    mock_users = MagicMock()
    mock_messages = MagicMock()
    mock_list_request = MagicMock()
    mock_get_service.return_value = mock_service
    mock_service.users.return_value = mock_users
    mock_users.messages.return_value = mock_messages
    mock_messages.list.return_value = mock_list_request
    mock_list_request.execute.return_value = {'messages': [{'id': 'msg1', 'threadId': 'thread1'}]}

    # Act
    result = await query_gmail_emails(user_id=TEST_USER_ID, query="subject:Test", max_results=50)

    # Assert
    mock_get_service.assert_called_once_with('gmail', 'v1', TEST_USER_ID)
    mock_service.users.assert_called_once()
    mock_users.messages.assert_called_once()
    mock_messages.list.assert_called_once_with(userId='me', q="subject:Test", maxResults=50)
    mock_list_request.execute.assert_called_once()
    assert isinstance(result, list)
    assert len(result) == 1
    assert isinstance(result[0], TextContent)
    expected_json = json.dumps([{'id': 'msg1', 'threadId': 'thread1'}]) # Function returns messages list
    assert result[0].text == expected_json

@pytest.mark.asyncio
@patch('src.mcp_google_workspace.tools_gmail.asyncio.to_thread', side_effect=lambda func, *args, **kwargs: func(*args, **kwargs))
@patch('mcp_google_workspace.tools_gmail.gauth.get_google_service')
async def test_query_gmail_emails_auth_error(mock_get_service, mock_to_thread):
    """Tests handling of AuthenticationError during email query."""
    # Arrange
    mock_get_service.side_effect = AuthenticationError("Gmail Auth Failed")

    # Act & Assert
    with pytest.raises(AuthenticationError, match="Gmail Auth Failed"):
        await query_gmail_emails(user_id=TEST_USER_ID)

    mock_get_service.assert_called_once_with('gmail', 'v1', TEST_USER_ID)

@pytest.mark.asyncio
@patch('src.mcp_google_workspace.tools_gmail.asyncio.to_thread', side_effect=lambda func, *args, **kwargs: func(*args, **kwargs))
@patch('mcp_google_workspace.tools_gmail.gauth.get_google_service')
async def test_query_gmail_emails_http_error(mock_get_service, mock_to_thread):
    """Tests handling of HttpError during email query."""
    # Arrange
    mock_service = MagicMock()
    mock_users = MagicMock()
    mock_messages = MagicMock()
    mock_list_request = MagicMock()
    mock_get_service.return_value = mock_service
    mock_service.users.return_value = mock_users
    mock_users.messages.return_value = mock_messages
    mock_messages.list.return_value = mock_list_request
    error_content = b'{"error": {"message": "Invalid query"}}'
    mock_list_request.execute.side_effect = create_http_error_response(400, "Bad Request", error_content)

    # Act & Assert
    # Escape special characters in the JSON for regex matching
    expected_pattern = r"Google API Error: 400 Invalid query\. Details: \{\"error\": \{\"message\": \"Invalid query\"\}\}" # Match actual error output
    with pytest.raises(RuntimeError, match=expected_pattern):
        await query_gmail_emails(user_id=TEST_USER_ID, query="invalid:")

    mock_get_service.assert_called_once_with('gmail', 'v1', TEST_USER_ID)
    mock_list_request.execute.assert_called_once()


# --- Tests for get_gmail_email ---

@pytest.mark.asyncio
@patch('src.mcp_google_workspace.tools_gmail.asyncio.to_thread', side_effect=lambda func, *args, **kwargs: func(*args, **kwargs))
@patch('mcp_google_workspace.tools_gmail.gauth.get_google_service')
async def test_get_gmail_email_success(mock_get_service, mock_to_thread):
    """Tests successful retrieval of a specific email."""
    # Arrange
    mock_service = MagicMock()
    mock_users = MagicMock()
    mock_messages = MagicMock()
    mock_get_request = MagicMock()
    mock_get_service.return_value = mock_service
    mock_service.users.return_value = mock_users
    mock_users.messages.return_value = mock_messages
    mock_messages.get.return_value = mock_get_request
    email_data = {
        'id': TEST_EMAIL_ID,
        'snippet': 'Test email content',
        'payload': {
            'parts': [
                {'filename': 'att.txt', 'mimeType': 'text/plain', 'body': {'attachmentId': 'att1', 'size': 100}}
            ]
        }
    }
    mock_get_request.execute.return_value = email_data

    # Act
    result = await get_gmail_email(user_id=TEST_USER_ID, email_id=TEST_EMAIL_ID)

    # Assert
    mock_get_service.assert_called_once_with('gmail', 'v1', TEST_USER_ID)
    mock_messages.get.assert_called_once_with(userId='me', id=TEST_EMAIL_ID, format='full')
    mock_get_request.execute.assert_called_once()
    assert isinstance(result, list)
    assert len(result) == 1
    assert isinstance(result[0], TextContent)
    # Check that attachments were extracted and added
    expected_data = email_data.copy()
    expected_data['attachments'] = [{
        "filename": 'att.txt', "mimeType": 'text/plain', "attachmentId": 'att1', "size": 100
    }]
    assert result[0].text == json.dumps(expected_data)

@pytest.mark.asyncio
@patch('src.mcp_google_workspace.tools_gmail.asyncio.to_thread', side_effect=lambda func, *args, **kwargs: func(*args, **kwargs))
@patch('mcp_google_workspace.tools_gmail.gauth.get_google_service')
async def test_get_gmail_email_http_error_404(mock_get_service, mock_to_thread):
    """Tests handling of 404 HttpError when getting an email."""
    # Arrange
    mock_service = MagicMock()
    mock_users = MagicMock()
    mock_messages = MagicMock()
    mock_get_request = MagicMock()
    mock_get_service.return_value = mock_service
    mock_service.users.return_value = mock_users
    mock_users.messages.return_value = mock_messages
    mock_messages.get.return_value = mock_get_request
    mock_get_request.execute.side_effect = create_http_error_response(404, "Not Found")

    # Act & Assert
    with pytest.raises(RuntimeError, match=f"Email with ID {TEST_EMAIL_ID} not found."):
        await get_gmail_email(user_id=TEST_USER_ID, email_id=TEST_EMAIL_ID)

    mock_get_service.assert_called_once_with('gmail', 'v1', TEST_USER_ID)
    mock_get_request.execute.assert_called_once()


# --- Tests for bulk_get_gmail_emails ---
# Note: This test mocks the inner _get_single_email calls via asyncio.gather

@pytest.mark.asyncio
@patch('mcp_google_workspace.tools_gmail.asyncio.gather') # Mock gather without AsyncMock
@patch('mcp_google_workspace.tools_gmail.asyncio.to_thread', side_effect=lambda func, *args, **kwargs: func(*args, **kwargs))
@patch('mcp_google_workspace.tools_gmail.gauth.get_google_service')
async def test_bulk_get_gmail_emails_success_and_error(mock_get_service, mock_to_thread, mock_gather):
    """Tests bulk retrieval with a mix of success and error."""
    # Arrange
    mock_service = MagicMock() # Service needed for the outer function
    mock_get_service.return_value = mock_service

    email_ids = ["email1", "email2_error", "email3"]
    # Mock the results that asyncio.gather would return as a completed future
    future = asyncio.Future()
    future.set_result([
        {'id': 'email1', 'snippet': 'Email 1 content', 'attachments': []},
        {'email_id': 'email2_error', 'error': 'Google API Error: 404 Not Found'},
        {'id': 'email3', 'snippet': 'Email 3 content', 'attachments': []}
    ])
    mock_gather.return_value = future

    # Act
    result = await bulk_get_gmail_emails(user_id=TEST_USER_ID, email_ids=email_ids)

    # Assert
    mock_get_service.assert_called_once_with('gmail', 'v1', TEST_USER_ID)
    # We don't directly assert calls within the gathered tasks here,
    # as we mocked the gather result. We trust the inner logic is tested elsewhere.
    mock_gather.assert_called_once() # Check that gather was called
    # Check number of tasks passed to gather (access the tuple of args)
    assert len(mock_gather.call_args[0]) == len(email_ids)

    assert isinstance(result, list)
    assert len(result) == 1
    assert isinstance(result[0], TextContent)
    # Assert against the *result* of the future, not the future object itself
    assert result[0].text == json.dumps(future.result())


# --- Tests for get_gmail_attachment ---

@pytest.mark.asyncio
@patch('src.mcp_google_workspace.tools_gmail.decode_base64_data', return_value=b'decoded attachment') # Mock helper
@patch('src.mcp_google_workspace.tools_gmail.asyncio.to_thread', side_effect=lambda func, *args, **kwargs: func(*args, **kwargs))
@patch('mcp_google_workspace.tools_gmail.gauth.get_google_service')
async def test_get_gmail_attachment_success_embed(mock_get_service, mock_to_thread, mock_decode):
    """Tests successful retrieval of an attachment as EmbeddedResource."""
    # Arrange
    mock_service = MagicMock()
    mock_users = MagicMock()
    mock_messages = MagicMock()
    mock_attachments = MagicMock()
    mock_get_request = MagicMock()
    mock_get_service.return_value = mock_service
    mock_service.users.return_value = mock_users
    mock_users.messages.return_value = mock_messages
    mock_messages.attachments.return_value = mock_attachments
    mock_attachments.get.return_value = mock_get_request
    # Base64 for "decoded attachment"
    encoded_data = base64.urlsafe_b64encode(b'decoded attachment').decode('utf-8')
    mock_get_request.execute.return_value = {'data': encoded_data, 'size': 18}

    # Act
    result = await get_gmail_attachment(
        user_id=TEST_USER_ID,
        message_id=TEST_MESSAGE_ID,
        attachment_id=TEST_ATTACHMENT_ID,
        mime_type='text/plain',
        filename='attach.txt',
        save_to_disk=None # Don't save
    )

    # Assert
    mock_get_service.assert_called_once_with('gmail', 'v1', TEST_USER_ID)
    mock_attachments.get.assert_called_once_with(userId='me', messageId=TEST_MESSAGE_ID, id=TEST_ATTACHMENT_ID)
    mock_get_request.execute.assert_called_once()
    mock_decode.assert_not_called() # Should not decode if returning embedded

    assert isinstance(result, EmbeddedResource) # Direct return, not list
    assert result.type == "resource"
    assert result.resource.blob == encoded_data # Should be the raw base64 data from API
    assert str(result.resource.uri) == f"attachment://gmail/{TEST_MESSAGE_ID}/{TEST_ATTACHMENT_ID}/attach.txt"
    assert result.resource.mimeType == 'text/plain'

@pytest.mark.asyncio
@pytest.mark.asyncio
@patch('os.path.dirname', return_value='/tmp/test')
@patch('os.makedirs')
@patch('builtins.open', new_callable=unittest_mock_open) # Use unittest.mock.mock_open
@patch('mcp_google_workspace.tools_gmail.decode_base64_data', return_value=b'decoded attachment data') # Mock helper
@patch('mcp_google_workspace.tools_gmail.asyncio.to_thread', side_effect=lambda func, *args, **kwargs: func(*args, **kwargs)) # Keep to_thread mock for now
@patch('mcp_google_workspace.tools_gmail.gauth.get_google_service')
async def test_get_gmail_attachment_success_save(mock_get_service, mock_to_thread, mock_decode, mock_open_patched, mock_makedirs, mock_dirname): # Renamed mock_open arg
    """Tests successful retrieval and saving of an attachment."""
    # Arrange
    mock_service = MagicMock()
    mock_users = MagicMock()
    mock_messages = MagicMock()
    mock_attachments = MagicMock()
    mock_get_request = MagicMock()
    mock_get_service.return_value = mock_service
    mock_service.users.return_value = mock_users
    mock_users.messages.return_value = mock_messages
    mock_messages.attachments.return_value = mock_attachments
    mock_attachments.get.return_value = mock_get_request
    encoded_data = base64.urlsafe_b64encode(b'decoded attachment data').decode('utf-8')
    mock_get_request.execute.return_value = {'data': encoded_data, 'size': 23}
    save_path = "/tmp/test/save_attach.pdf"
    # mock_file_handle = MagicMock() # Not needed with unittest.mock.mock_open
    # # Mock the context manager behavior of open
    # mock_open_instance = mock_open.return_value
    # mock_open_instance.__enter__.return_value = mock_file_handle

    # Act
    result = await get_gmail_attachment(
        user_id=TEST_USER_ID,
        message_id=TEST_MESSAGE_ID,
        attachment_id=TEST_ATTACHMENT_ID,
        mime_type='application/pdf',
        filename='save_attach.pdf',
        save_to_disk=save_path
    )

    # Assert
    mock_get_service.assert_called_once_with('gmail', 'v1', TEST_USER_ID)
    mock_attachments.get.assert_called_once_with(userId='me', messageId=TEST_MESSAGE_ID, id=TEST_ATTACHMENT_ID)
    mock_get_request.execute.assert_called_once()
    mock_decode.assert_called_once_with(encoded_data)
    mock_dirname.assert_called_once_with(save_path)
    mock_makedirs.assert_called_once_with("/tmp/test", exist_ok=True)

    # Assert that open and write were called directly, as the to_thread mock executes synchronously
    mock_open_patched.assert_called_once_with(save_path, "wb")
    # unittest.mock.mock_open provides a file handle mock automatically
    mock_open_patched().write.assert_called_once_with(b'decoded attachment data')

    assert isinstance(result, list)
    assert len(result) == 1
    assert isinstance(result[0], TextContent)
    expected_status = {"status": "success", "message": f"Attachment saved to disk: {save_path}", "path": save_path}
    assert result[0].text == json.dumps(expected_status)


# --- Tests for create_gmail_draft ---

@pytest.mark.asyncio
@patch('src.mcp_google_workspace.tools_gmail.base64.urlsafe_b64encode', return_value=b'ZW5jb2RlZF9tZXNzYWdl') # Mock encode
@patch('src.mcp_google_workspace.tools_gmail.asyncio.to_thread', side_effect=lambda func, *args, **kwargs: func(*args, **kwargs))
@patch('mcp_google_workspace.tools_gmail.gauth.get_google_service')
async def test_create_gmail_draft_success(mock_get_service, mock_to_thread, mock_b64encode):
    """Tests successful creation of a Gmail draft."""
    # Arrange
    mock_service = MagicMock()
    mock_users = MagicMock()
    mock_drafts = MagicMock()
    mock_create_request = MagicMock()
    mock_get_service.return_value = mock_service
    mock_service.users.return_value = mock_users
    mock_users.drafts.return_value = mock_drafts
    mock_drafts.create.return_value = mock_create_request
    draft_response = {'id': TEST_DRAFT_ID, 'message': {'id': 'temp_msg_id'}}
    mock_create_request.execute.return_value = draft_response

    to = "recipient@example.com"
    subject = "Test Draft Subject"
    body = "This is the draft body."
    cc = ["cc1@example.com", "cc2@example.com"]

    # Act
    result = await create_gmail_draft(user_id=TEST_USER_ID, to=to, subject=subject, body=body, cc=cc)

    # Assert
    mock_get_service.assert_called_once_with('gmail', 'v1', TEST_USER_ID)
    # Check raw message construction and encoding
    expected_raw = f"To: {to}\r\nCc: {','.join(cc)}\r\nSubject: {subject}\r\n\r\n{body}"
    mock_b64encode.assert_called_once_with(expected_raw.encode('utf-8'))
    # Check draft creation call
    expected_draft_body = {'message': {'raw': 'ZW5jb2RlZF9tZXNzYWdl'}} # Use the mocked encoded value
    mock_drafts.create.assert_called_once_with(userId='me', body=expected_draft_body)
    mock_create_request.execute.assert_called_once()
    assert isinstance(result, list)
    assert len(result) == 1
    assert isinstance(result[0], TextContent)
    assert result[0].text == json.dumps(draft_response)


# --- Tests for delete_gmail_draft ---

@pytest.mark.asyncio
@patch('src.mcp_google_workspace.tools_gmail.asyncio.to_thread', side_effect=lambda func, *args, **kwargs: func(*args, **kwargs))
@patch('mcp_google_workspace.tools_gmail.gauth.get_google_service')
async def test_delete_gmail_draft_success(mock_get_service, mock_to_thread):
    """Tests successful deletion of a Gmail draft."""
    # Arrange
    mock_service = MagicMock()
    mock_users = MagicMock()
    mock_drafts = MagicMock()
    mock_delete_request = MagicMock()
    mock_get_service.return_value = mock_service
    mock_service.users.return_value = mock_users
    mock_users.drafts.return_value = mock_drafts
    mock_drafts.delete.return_value = mock_delete_request
    mock_delete_request.execute.return_value = {} # Delete returns empty body on success

    # Act
    result = await delete_gmail_draft(user_id=TEST_USER_ID, draft_id=TEST_DRAFT_ID)

    # Assert
    mock_get_service.assert_called_once_with('gmail', 'v1', TEST_USER_ID)
    mock_drafts.delete.assert_called_once_with(userId='me', id=TEST_DRAFT_ID)
    mock_delete_request.execute.assert_called_once()
    assert isinstance(result, list)
    assert len(result) == 1
    assert isinstance(result[0], TextContent)
    expected_status = {"status": "success", "message": f"Successfully deleted draft {TEST_DRAFT_ID}"}
    assert result[0].text == json.dumps(expected_status)

@pytest.mark.asyncio
@patch('src.mcp_google_workspace.tools_gmail.asyncio.to_thread', side_effect=lambda func, *args, **kwargs: func(*args, **kwargs))
@patch('mcp_google_workspace.tools_gmail.gauth.get_google_service')
async def test_delete_gmail_draft_http_error_404(mock_get_service, mock_to_thread):
    """Tests handling of 404 HttpError when deleting a draft."""
    # Arrange
    mock_service = MagicMock()
    mock_users = MagicMock()
    mock_drafts = MagicMock()
    mock_delete_request = MagicMock()
    mock_get_service.return_value = mock_service
    mock_service.users.return_value = mock_users
    mock_users.drafts.return_value = mock_drafts
    mock_drafts.delete.return_value = mock_delete_request
    mock_delete_request.execute.side_effect = create_http_error_response(404, "Not Found")

    # Act & Assert
    with pytest.raises(RuntimeError, match=f"Draft with ID {TEST_DRAFT_ID} not found."):
        await delete_gmail_draft(user_id=TEST_USER_ID, draft_id=TEST_DRAFT_ID)

    mock_get_service.assert_called_once_with('gmail', 'v1', TEST_USER_ID)
    mock_delete_request.execute.assert_called_once()


# --- Tests for reply_gmail_email ---

@pytest.mark.asyncio
@patch('src.mcp_google_workspace.tools_gmail.base64.urlsafe_b64encode', return_value=b'ZW5jb2RlZF9yZXBseQ==') # Mock encode
@patch('src.mcp_google_workspace.tools_gmail.asyncio.to_thread', side_effect=lambda func, *args, **kwargs: func(*args, **kwargs))
@patch('mcp_google_workspace.tools_gmail.gauth.get_google_service')
async def test_reply_gmail_email_success_send(mock_get_service, mock_to_thread, mock_b64encode):
    """Tests successfully creating and sending a reply."""
    # Arrange
    mock_service = MagicMock()
    mock_users = MagicMock()
    mock_messages = MagicMock()
    mock_get_request = MagicMock() # For original message
    mock_send_request = MagicMock() # For sending reply
    mock_get_service.return_value = mock_service
    mock_service.users.return_value = mock_users
    mock_users.messages.return_value = mock_messages
    mock_messages.get.return_value = mock_get_request
    mock_messages.send.return_value = mock_send_request

    original_headers = [
        {'name': 'Subject', 'value': 'Original Subject'},
        {'name': 'From', 'value': 'sender@example.com'},
        {'name': 'To', 'value': 'me@example.com'},
        {'name': 'Cc', 'value': 'cc_orig@example.com'},
        {'name': 'Message-ID', 'value': '<original_msg_id>'},
        {'name': 'References', 'value': '<ref1> <ref2>'},
        {'name': 'In-Reply-To', 'value': '<ref2>'},
    ]
    original_message_data = {'id': TEST_MESSAGE_ID, 'threadId': 'thread123', 'payload': {'headers': original_headers}}
    mock_get_request.execute.return_value = original_message_data
    send_response = {'id': 'sent_reply_id', 'threadId': 'thread123', 'labelIds': ['SENT']}
    mock_send_request.execute.return_value = send_response

    reply_body = "This is the reply."
    reply_cc = ["extra_cc@example.com"]

    # Act
    result = await reply_gmail_email(
        user_id=TEST_USER_ID,
        original_message_id=TEST_MESSAGE_ID,
        reply_body=reply_body,
        send=True, # Send the reply
        cc=reply_cc
    )

    # Assert
    mock_get_service.assert_called_once_with('gmail', 'v1', TEST_USER_ID)
    mock_messages.get.assert_called_once_with(userId='me', id=TEST_MESSAGE_ID, format='metadata', metadataHeaders=['Subject', 'From', 'To', 'Cc', 'Message-ID', 'References', 'In-Reply-To'])
    mock_get_request.execute.assert_called_once()

    # Check reply construction and encoding
    expected_raw_reply = (
        "To: sender@example.com\r\n"
        "Cc: extra_cc@example.com\r\n" # Only explicit CC used in current logic
        "Subject: Re: Original Subject\r\n"
        "In-Reply-To: <ref2>\r\n"
        "References: <ref1> <ref2> <original_msg_id>\r\n"
        "\r\n"
        "This is the reply."
    )
    mock_b64encode.assert_called_once_with(expected_raw_reply.encode('utf-8'))

    # Check send call
    expected_send_body = {'raw': 'ZW5jb2RlZF9yZXBseQ==', 'threadId': 'thread123'}
    mock_messages.send.assert_called_once_with(userId='me', body=expected_send_body)
    mock_send_request.execute.assert_called_once()

    assert isinstance(result, list)
    assert len(result) == 1
    assert isinstance(result[0], TextContent)
    assert result[0].text == json.dumps(send_response)

@pytest.mark.asyncio
@patch('src.mcp_google_workspace.tools_gmail.base64.urlsafe_b64encode', return_value=b'ZW5jb2RlZF9yZXBseQ==') # Mock encode
@patch('src.mcp_google_workspace.tools_gmail.asyncio.to_thread', side_effect=lambda func, *args, **kwargs: func(*args, **kwargs))
@patch('mcp_google_workspace.tools_gmail.gauth.get_google_service')
async def test_reply_gmail_email_success_draft(mock_get_service, mock_to_thread, mock_b64encode):
    """Tests successfully creating a reply as a draft."""
    # Arrange
    mock_service = MagicMock()
    mock_users = MagicMock()
    mock_messages = MagicMock()
    mock_drafts = MagicMock() # Need drafts service for create
    mock_get_request = MagicMock() # For original message
    mock_create_draft_request = MagicMock() # For creating draft
    mock_get_service.return_value = mock_service
    mock_service.users.return_value = mock_users
    mock_users.messages.return_value = mock_messages
    mock_users.drafts.return_value = mock_drafts # Mock drafts service
    mock_messages.get.return_value = mock_get_request
    mock_drafts.create.return_value = mock_create_draft_request # Mock draft create

    original_headers = [{'name': 'Subject', 'value': 'Draft Subject'}, {'name': 'From', 'value': 'sender@example.com'}, {'name': 'Message-ID', 'value': '<original_draft_msg_id>'}]
    original_message_data = {'id': TEST_MESSAGE_ID, 'threadId': 'thread456', 'payload': {'headers': original_headers}}
    mock_get_request.execute.return_value = original_message_data
    draft_response = {'id': 'new_draft_reply_id', 'message': {'id': 'draft_msg_id', 'threadId': 'thread456'}}
    mock_create_draft_request.execute.return_value = draft_response

    reply_body = "This is the reply draft."

    # Act
    result = await reply_gmail_email(
        user_id=TEST_USER_ID,
        original_message_id=TEST_MESSAGE_ID,
        reply_body=reply_body,
        send=False, # Create draft
        cc=None
    )

    # Assert
    mock_get_service.assert_called_once_with('gmail', 'v1', TEST_USER_ID)
    mock_messages.get.assert_called_once() # Original message fetched
    mock_get_request.execute.assert_called_once()
    mock_b64encode.assert_called_once() # Reply encoded

    # Check draft create call
    expected_draft_body = {'message': {'raw': 'ZW5jb2RlZF9yZXBseQ==', 'threadId': 'thread456'}}
    mock_drafts.create.assert_called_once_with(userId='me', body=expected_draft_body)
    mock_create_draft_request.execute.assert_called_once()
    mock_messages.send.assert_not_called() # Ensure send was not called

    assert isinstance(result, list)
    assert len(result) == 1
    assert isinstance(result[0], TextContent)
    assert result[0].text == json.dumps(draft_response)


# --- Tests for bulk_save_gmail_attachments ---
# Similar to bulk_get, we mock the gather result

@pytest.mark.asyncio
@patch('mcp_google_workspace.tools_gmail.asyncio.gather') # Mock gather without AsyncMock
@patch('mcp_google_workspace.tools_gmail.asyncio.to_thread', side_effect=lambda func, *args, **kwargs: func(*args, **kwargs))
@patch('mcp_google_workspace.tools_gmail.gauth.get_google_service')
async def test_bulk_save_gmail_attachments_mix(mock_get_service, mock_to_thread, mock_gather):
    """Tests bulk saving with a mix of success and error."""
     # Arrange
    mock_service = MagicMock() # Service needed for the outer function
    mock_get_service.return_value = mock_service

    attachments_info = [
        {"message_id": "msg1", "attachment_id": "att1", "save_path": "/path/to/file1.txt"},
        {"message_id": "msg2", "attachment_id": "att2_err", "save_path": "/path/to/file2.pdf"},
        {"message_id": "msg3", "attachment_id": "att3", "save_path": "/path/to/file3.jpg"},
    ]
    # Mock the results that asyncio.gather would return as a completed future
    future = asyncio.Future()
    future.set_result([
        {"status": "success", "message": "Attachment saved to: /path/to/file1.txt", "path": "/path/to/file1.txt"},
        {"status": "error", "message": "Attachment or message not found.", "path": "/path/to/file2.pdf", "input": attachments_info[1]},
        {"status": "success", "message": "Attachment saved to: /path/to/file3.jpg", "path": "/path/to/file3.jpg"},
    ])
    mock_gather.return_value = future

    # Act
    result = await bulk_save_gmail_attachments(user_id=TEST_USER_ID, attachments=attachments_info)

    # Assert
    mock_get_service.assert_called_once_with('gmail', 'v1', TEST_USER_ID)
    mock_gather.assert_called_once()
    # Check number of tasks passed to gather (access the tuple of args)
    assert len(mock_gather.call_args[0]) == len(attachments_info)

    assert isinstance(result, list)
    assert len(result) == 1
    assert isinstance(result[0], TextContent)
    # Assert against the *result* of the future, not the future object itself
    assert result[0].text == json.dumps(future.result())