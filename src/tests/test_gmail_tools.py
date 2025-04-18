import pytest
import json
from unittest.mock import patch, MagicMock

# Adjust import path based on how pytest discovers tests relative to the src root
# Assuming tests are run from the root directory containing mcp-servers/
from mcp_gsuite import toolhandler
from mcp_gsuite.tools_gmail import QueryEmailsToolHandler
from mcp.types import TextContent

TEST_USER_ID = "test@example.com"

@pytest.fixture
def query_emails_handler():
    """Fixture to provide an instance of QueryEmailsToolHandler."""
    return QueryEmailsToolHandler()

@patch('mcp_gsuite.tools_gmail.gmail.GmailService')
def test_query_emails_success(mock_gmail_service_class, query_emails_handler):
    """Test successful execution of query_emails tool."""
    # Arrange
    mock_service_instance = MagicMock()
    mock_gmail_service_class.return_value = mock_service_instance

    mock_emails_response = [
        {'id': '123', 'subject': 'Test Email 1', 'snippet': 'Snippet 1'},
        {'id': '456', 'subject': 'Test Email 2', 'snippet': 'Snippet 2'}
    ]
    mock_service_instance.query_emails.return_value = mock_emails_response

    args = {
        toolhandler.USER_ID_ARG: TEST_USER_ID,
        "query": "is:unread",
        "max_results": 5
    }

    # Act
    results = query_emails_handler.run_tool(args)

    # Assert
    mock_gmail_service_class.assert_called_once_with(user_id=TEST_USER_ID)
    mock_service_instance.query_emails.assert_called_once_with(query="is:unread", max_results=5)

    assert len(results) == 1
    assert isinstance(results[0], TextContent)
    assert results[0].type == "text"
    
    expected_json = json.dumps(mock_emails_response, indent=2)
    assert results[0].text == expected_json

@patch('mcp_gsuite.tools_gmail.gmail.GmailService')
def test_query_emails_missing_user_id(mock_gmail_service_class, query_emails_handler):
    """Test query_emails tool raises error if user_id is missing."""
    # Arrange
    args = {
        "query": "test"
    }

    # Act & Assert
    with pytest.raises(RuntimeError) as excinfo:
        query_emails_handler.run_tool(args)
    assert toolhandler.USER_ID_ARG in str(excinfo.value)
    mock_gmail_service_class.assert_not_called()

@patch('mcp_gsuite.tools_gmail.gmail.GmailService')
def test_query_emails_api_error(mock_gmail_service_class, query_emails_handler):
    """Test query_emails tool handles underlying API errors (returns empty list)."""
    # Arrange
    mock_service_instance = MagicMock()
    mock_gmail_service_class.return_value = mock_service_instance
    # Simulate the GmailService returning an empty list on error
    mock_service_instance.query_emails.return_value = [] 

    args = {
        toolhandler.USER_ID_ARG: TEST_USER_ID,
        "query": "error condition" 
    }

    # Act
    results = query_emails_handler.run_tool(args)

    # Assert
    mock_gmail_service_class.assert_called_once_with(user_id=TEST_USER_ID)
    mock_service_instance.query_emails.assert_called_once_with(query="error condition", max_results=100) # Default max_results

    assert len(results) == 1
    assert isinstance(results[0], TextContent)
    assert results[0].type == "text"
    assert results[0].text == json.dumps([], indent=2) # Expect empty list JSON


# --- Tests for GetEmailByIdToolHandler ---

from mcp_gsuite.tools_gmail import GetEmailByIdToolHandler

@pytest.fixture
def get_email_handler():
    """Fixture to provide an instance of GetEmailByIdToolHandler."""
    return GetEmailByIdToolHandler()

@patch('mcp_gsuite.tools_gmail.gmail.GmailService')
def test_get_email_by_id_success(mock_gmail_service_class, get_email_handler):
    """Test successful retrieval of an email by ID."""
    # Arrange
    mock_service_instance = MagicMock()
    mock_gmail_service_class.return_value = mock_service_instance

    mock_email_response = {'id': '789', 'subject': 'Specific Email', 'body': 'Details here'}
    # Simulate the structure returned by the actual service method (tuple of email dict, attachments dict)
    mock_attachments_dict = {'part1': {'filename': 'file.txt', 'attachmentId': 'att1', 'partId': 'part1'}}
    mock_service_instance.get_email_by_id_with_attachments.return_value = (mock_email_response, mock_attachments_dict)

    email_id_to_get = "789"
    args = {
        toolhandler.USER_ID_ARG: TEST_USER_ID,
        "email_id": email_id_to_get
    }

    # Act
    results = get_email_handler.run_tool(args)

    # Assert
    mock_gmail_service_class.assert_called_once_with(user_id=TEST_USER_ID)
    mock_service_instance.get_email_by_id_with_attachments.assert_called_once_with(email_id_to_get)

    assert len(results) == 1
    assert isinstance(results[0], TextContent)
    
    # The handler adds the attachments dict to the email dict under the 'attachments' key
    expected_response = mock_email_response.copy()
    expected_response["attachments"] = mock_attachments_dict
    expected_json = json.dumps(expected_response, indent=2)
    assert results[0].text == expected_json

@patch('mcp_gsuite.tools_gmail.gmail.GmailService')
def test_get_email_by_id_missing_args(mock_gmail_service_class, get_email_handler):
    """Test get_email_by_id raises error if args are missing."""
    # Test missing email_id
    with pytest.raises(RuntimeError) as excinfo:
        get_email_handler.run_tool({toolhandler.USER_ID_ARG: TEST_USER_ID})
    assert "Missing required argument: email_id" in str(excinfo.value)

    # Test missing user_id
    with pytest.raises(RuntimeError) as excinfo:
        get_email_handler.run_tool({"email_id": "123"})
    assert toolhandler.USER_ID_ARG in str(excinfo.value)
    
    mock_gmail_service_class.assert_not_called()

@patch('mcp_gsuite.tools_gmail.gmail.GmailService')
def test_get_email_by_id_not_found(mock_gmail_service_class, get_email_handler):
    """Test get_email_by_id handles email not found."""
    # Arrange
    mock_service_instance = MagicMock()
    mock_gmail_service_class.return_value = mock_service_instance
    mock_service_instance.get_email_by_id_with_attachments.return_value = (None, {}) # Simulate not found

    email_id_to_get = "nonexistent"
    args = {
        toolhandler.USER_ID_ARG: TEST_USER_ID,
        "email_id": email_id_to_get
    }

    # Act
    results = get_email_handler.run_tool(args)

    # Assert
    mock_gmail_service_class.assert_called_once_with(user_id=TEST_USER_ID)
    mock_service_instance.get_email_by_id_with_attachments.assert_called_once_with(email_id_to_get)

    assert len(results) == 1
    assert isinstance(results[0], TextContent)
    assert f"Failed to retrieve email with ID: {email_id_to_get}" in results[0].text


# --- Tests for CreateDraftToolHandler ---

from mcp_gsuite.tools_gmail import CreateDraftToolHandler

@pytest.fixture
def create_draft_handler():
    """Fixture to provide an instance of CreateDraftToolHandler."""
    return CreateDraftToolHandler()

@patch('mcp_gsuite.tools_gmail.gmail.GmailService')
def test_create_draft_success(mock_gmail_service_class, create_draft_handler):
    """Test successful creation of a draft email."""
    # Arrange
    mock_service_instance = MagicMock()
    mock_gmail_service_class.return_value = mock_service_instance

    mock_draft_response = {'id': 'draft-123', 'message': {'id': 'msg-abc'}}
    mock_service_instance.create_draft.return_value = mock_draft_response

    args = {
        toolhandler.USER_ID_ARG: TEST_USER_ID,
        "to": "recipient@example.com",
        "subject": "Draft Subject",
        "body": "Draft body content.",
        "cc": ["cc1@example.com", "cc2@example.com"]
    }

    # Act
    results = create_draft_handler.run_tool(args)

    # Assert
    mock_gmail_service_class.assert_called_once_with(user_id=TEST_USER_ID)
    mock_service_instance.create_draft.assert_called_once_with(
        to="recipient@example.com",
        subject="Draft Subject",
        body="Draft body content.",
        cc=["cc1@example.com", "cc2@example.com"]
    )

    assert len(results) == 1
    assert isinstance(results[0], TextContent)
    expected_json = json.dumps(mock_draft_response, indent=2)
    assert results[0].text == expected_json

@patch('mcp_gsuite.tools_gmail.gmail.GmailService')
def test_create_draft_success_no_cc(mock_gmail_service_class, create_draft_handler):
    """Test successful creation of a draft email without CC."""
    # Arrange
    mock_service_instance = MagicMock()
    mock_gmail_service_class.return_value = mock_service_instance

    mock_draft_response = {'id': 'draft-456', 'message': {'id': 'msg-def'}}
    mock_service_instance.create_draft.return_value = mock_draft_response

    args = {
        toolhandler.USER_ID_ARG: TEST_USER_ID,
        "to": "recipient@example.com",
        "subject": "Draft Subject No CC",
        "body": "Draft body content no CC."
        # No "cc" key
    }

    # Act
    results = create_draft_handler.run_tool(args)

    # Assert
    mock_gmail_service_class.assert_called_once_with(user_id=TEST_USER_ID)
    mock_service_instance.create_draft.assert_called_once_with(
        to="recipient@example.com",
        subject="Draft Subject No CC",
        body="Draft body content no CC.",
        cc=None # Expect None when not provided
    )

    assert len(results) == 1
    assert isinstance(results[0], TextContent)
    expected_json = json.dumps(mock_draft_response, indent=2)
    assert results[0].text == expected_json


@patch('mcp_gsuite.tools_gmail.gmail.GmailService')
def test_create_draft_missing_args(mock_gmail_service_class, create_draft_handler):
    """Test create_draft raises error if required args are missing."""
    required_args = ["to", "subject", "body"]
    base_args = {
        toolhandler.USER_ID_ARG: TEST_USER_ID,
        "to": "r@e.com", "subject": "s", "body": "b"
    }

    for arg_to_remove in required_args:
        args = base_args.copy()
        del args[arg_to_remove]
        with pytest.raises(RuntimeError) as excinfo:
            create_draft_handler.run_tool(args)
        assert f"Missing required arguments" in str(excinfo.value) # Tool checks all at once

    # Test missing user_id
    args = base_args.copy()
    del args[toolhandler.USER_ID_ARG]
    with pytest.raises(RuntimeError) as excinfo:
        create_draft_handler.run_tool(args)
    assert toolhandler.USER_ID_ARG in str(excinfo.value)

    mock_gmail_service_class.assert_not_called()


@patch('mcp_gsuite.tools_gmail.gmail.GmailService')
def test_create_draft_api_failure(mock_gmail_service_class, create_draft_handler):
    """Test create_draft handles API failure (returns None)."""
    # Arrange
    mock_service_instance = MagicMock()
    mock_gmail_service_class.return_value = mock_service_instance
    mock_service_instance.create_draft.return_value = None # Simulate API failure

    args = {
        toolhandler.USER_ID_ARG: TEST_USER_ID,
        "to": "recipient@example.com",
        "subject": "Failed Draft",
        "body": "This draft should fail."
    }

    # Act
    results = create_draft_handler.run_tool(args)

    # Assert
    mock_gmail_service_class.assert_called_once_with(user_id=TEST_USER_ID)
    mock_service_instance.create_draft.assert_called_once()

    assert len(results) == 1
    assert isinstance(results[0], TextContent)
    assert "Failed to create draft email" in results[0].text


# --- Tests for ReplyEmailToolHandler ---

from mcp_gsuite.tools_gmail import ReplyEmailToolHandler

@pytest.fixture
def reply_email_handler():
    """Fixture to provide an instance of ReplyEmailToolHandler."""
    return ReplyEmailToolHandler()

@patch('mcp_gsuite.tools_gmail.gmail.GmailService')
def test_reply_email_draft_success(mock_gmail_service_class, reply_email_handler):
    """Test successful creation of a reply draft."""
    # Arrange
    mock_service_instance = MagicMock()
    mock_gmail_service_class.return_value = mock_service_instance

    original_msg_id = "orig-msg-1"
    mock_original_email = {
        'id': original_msg_id,
        'from': 'sender@example.com',
        'subject': 'Original Subject',
        'body': 'Original body.',
        'threadId': 'thread-abc'
    }
    # Note: Reply handler uses get_email_by_id, not get_email_by_id_with_attachments
    mock_service_instance.get_email_by_id.return_value = mock_original_email

    mock_reply_draft_response = {'id': 'draft-reply-1', 'message': {'id': 'reply-msg-1'}}
    mock_service_instance.create_reply.return_value = mock_reply_draft_response

    args = {
        toolhandler.USER_ID_ARG: TEST_USER_ID,
        "original_message_id": original_msg_id,
        "reply_body": "This is the reply.",
        "send": False, # Save as draft
        "cc": ["cc-reply@example.com"]
    }

    # Act
    results = reply_email_handler.run_tool(args)

    # Assert
    mock_gmail_service_class.assert_called_once_with(user_id=TEST_USER_ID)
    mock_service_instance.get_email_by_id.assert_called_once_with(original_msg_id)
    mock_service_instance.create_reply.assert_called_once_with(
        original_message=mock_original_email,
        reply_body="This is the reply.",
        send=False,
        cc=["cc-reply@example.com"]
    )

    assert len(results) == 1
    assert isinstance(results[0], TextContent)
    expected_json = json.dumps(mock_reply_draft_response, indent=2)
    assert results[0].text == expected_json

@patch('mcp_gsuite.tools_gmail.gmail.GmailService')
def test_reply_email_send_success(mock_gmail_service_class, reply_email_handler):
    """Test successful sending of a reply."""
    # Arrange
    mock_service_instance = MagicMock()
    mock_gmail_service_class.return_value = mock_service_instance

    original_msg_id = "orig-msg-2"
    mock_original_email = {
        'id': original_msg_id,
        'from': 'sender2@example.com',
        'subject': 'Another Subject',
        'body': 'Another body.',
        'threadId': 'thread-def'
    }
    mock_service_instance.get_email_by_id.return_value = mock_original_email

    mock_sent_message_response = {'id': 'sent-reply-2', 'labelIds': ['SENT']}
    mock_service_instance.create_reply.return_value = mock_sent_message_response

    args = {
        toolhandler.USER_ID_ARG: TEST_USER_ID,
        "original_message_id": original_msg_id,
        "reply_body": "Sending this reply.",
        "send": True # Send immediately
        # No CC
    }

    # Act
    results = reply_email_handler.run_tool(args)

    # Assert
    mock_gmail_service_class.assert_called_once_with(user_id=TEST_USER_ID)
    mock_service_instance.get_email_by_id.assert_called_once_with(original_msg_id)
    mock_service_instance.create_reply.assert_called_once_with(
        original_message=mock_original_email,
        reply_body="Sending this reply.",
        send=True,
        cc=None # Expect None when not provided
    )

    assert len(results) == 1
    assert isinstance(results[0], TextContent)
    expected_json = json.dumps(mock_sent_message_response, indent=2)
    assert results[0].text == expected_json

@patch('mcp_gsuite.tools_gmail.gmail.GmailService')
def test_reply_email_missing_args(mock_gmail_service_class, reply_email_handler):
    """Test reply_email raises error if required args are missing."""
    required_args = ["original_message_id", "reply_body"]
    base_args = {
        toolhandler.USER_ID_ARG: TEST_USER_ID,
        "original_message_id": "orig-1", "reply_body": "reply"
    }

    for arg_to_remove in required_args:
        args = base_args.copy()
        del args[arg_to_remove]
        with pytest.raises(RuntimeError) as excinfo:
            reply_email_handler.run_tool(args)
        assert "Missing required arguments" in str(excinfo.value)

    # Test missing user_id
    args = base_args.copy()
    del args[toolhandler.USER_ID_ARG]
    with pytest.raises(RuntimeError) as excinfo:
        reply_email_handler.run_tool(args)
    assert toolhandler.USER_ID_ARG in str(excinfo.value)

    mock_gmail_service_class.assert_not_called()

@patch('mcp_gsuite.tools_gmail.gmail.GmailService')
def test_reply_email_original_not_found(mock_gmail_service_class, reply_email_handler):
    """Test reply_email handles failure to find the original message."""
    # Arrange
    mock_service_instance = MagicMock()
    mock_gmail_service_class.return_value = mock_service_instance
    mock_service_instance.get_email_by_id.return_value = None # Simulate original not found

    original_msg_id = "nonexistent-original"
    args = {
        toolhandler.USER_ID_ARG: TEST_USER_ID,
        "original_message_id": original_msg_id,
        "reply_body": "This reply won't work.",
        "send": False
    }

    # Act
    results = reply_email_handler.run_tool(args)

    # Assert
    mock_gmail_service_class.assert_called_once_with(user_id=TEST_USER_ID)
    mock_service_instance.get_email_by_id.assert_called_once_with(original_msg_id)
    mock_service_instance.create_reply.assert_not_called() # Should not attempt reply

    assert len(results) == 1
    assert isinstance(results[0], TextContent)
    assert f"Failed to retrieve original message with ID: {original_msg_id}" in results[0].text

@patch('mcp_gsuite.tools_gmail.gmail.GmailService')
def test_reply_email_api_failure(mock_gmail_service_class, reply_email_handler):
    """Test reply_email handles failure during the create_reply API call."""
    # Arrange
    mock_service_instance = MagicMock()
    mock_gmail_service_class.return_value = mock_service_instance

    original_msg_id = "orig-msg-fail"
    mock_original_email = {'id': original_msg_id, 'from': 'sender@fail.com', 'subject': 'Fail Subject'}
    mock_service_instance.get_email_by_id.return_value = mock_original_email
    mock_service_instance.create_reply.return_value = None # Simulate create_reply failure

    args = {
        toolhandler.USER_ID_ARG: TEST_USER_ID,
        "original_message_id": original_msg_id,
        "reply_body": "This reply API call will fail.",
        "send": True # Test failure on send
    }

    # Act
    results = reply_email_handler.run_tool(args)

    # Assert
    mock_gmail_service_class.assert_called_once_with(user_id=TEST_USER_ID)
    mock_service_instance.get_email_by_id.assert_called_once_with(original_msg_id)
    mock_service_instance.create_reply.assert_called_once() # Called but returned None

    assert len(results) == 1
    assert isinstance(results[0], TextContent)
    assert "Failed to send reply email" in results[0].text # Check correct failure message (send=True)


# --- Tests for DeleteDraftToolHandler ---

from mcp_gsuite.tools_gmail import DeleteDraftToolHandler

@pytest.fixture
def delete_draft_handler():
    """Fixture to provide an instance of DeleteDraftToolHandler."""
    return DeleteDraftToolHandler()

@patch('mcp_gsuite.tools_gmail.gmail.GmailService')
def test_delete_draft_success(mock_gmail_service_class, delete_draft_handler):
    """Test successful deletion of a draft."""
    # Arrange
    mock_service_instance = MagicMock()
    mock_gmail_service_class.return_value = mock_service_instance
    mock_service_instance.delete_draft.return_value = True # Simulate success

    draft_id_to_delete = "draft-to-delete"
    args = {
        toolhandler.USER_ID_ARG: TEST_USER_ID,
        "draft_id": draft_id_to_delete
    }

    # Act
    results = delete_draft_handler.run_tool(args)

    # Assert
    mock_gmail_service_class.assert_called_once_with(user_id=TEST_USER_ID)
    mock_service_instance.delete_draft.assert_called_once_with(draft_id_to_delete)

    assert len(results) == 1
    assert isinstance(results[0], TextContent)
    assert "Successfully deleted draft" in results[0].text

@patch('mcp_gsuite.tools_gmail.gmail.GmailService')
def test_delete_draft_failure(mock_gmail_service_class, delete_draft_handler):
    """Test handling of draft deletion failure."""
    # Arrange
    mock_service_instance = MagicMock()
    mock_gmail_service_class.return_value = mock_service_instance
    mock_service_instance.delete_draft.return_value = False # Simulate failure

    draft_id_to_delete = "draft-fail-delete"
    args = {
        toolhandler.USER_ID_ARG: TEST_USER_ID,
        "draft_id": draft_id_to_delete
    }

    # Act
    results = delete_draft_handler.run_tool(args)

    # Assert
    mock_gmail_service_class.assert_called_once_with(user_id=TEST_USER_ID)
    mock_service_instance.delete_draft.assert_called_once_with(draft_id_to_delete)

    assert len(results) == 1
    assert isinstance(results[0], TextContent)
    assert f"Failed to delete draft with ID: {draft_id_to_delete}" in results[0].text

@patch('mcp_gsuite.tools_gmail.gmail.GmailService')
def test_delete_draft_missing_args(mock_gmail_service_class, delete_draft_handler):
    """Test delete_draft raises error if args are missing."""
    # Test missing draft_id
    with pytest.raises(RuntimeError) as excinfo:
        delete_draft_handler.run_tool({toolhandler.USER_ID_ARG: TEST_USER_ID})
    assert "Missing required argument: draft_id" in str(excinfo.value)

    # Test missing user_id
    with pytest.raises(RuntimeError) as excinfo:
        delete_draft_handler.run_tool({"draft_id": "d1"})
    assert toolhandler.USER_ID_ARG in str(excinfo.value)

    mock_gmail_service_class.assert_not_called()


# --- Tests for GetAttachmentToolHandler ---
import base64
from mcp.types import EmbeddedResource
from unittest.mock import mock_open

from mcp_gsuite.tools_gmail import GetAttachmentToolHandler, decode_base64_data

@pytest.fixture
def get_attachment_handler():
    """Fixture to provide an instance of GetAttachmentToolHandler."""
    return GetAttachmentToolHandler()

@patch('mcp_gsuite.tools_gmail.gmail.GmailService')
def test_get_attachment_resource_success(mock_gmail_service_class, get_attachment_handler):
    """Test successful retrieval of an attachment as a resource."""
    # Arrange
    mock_service_instance = MagicMock()
    mock_gmail_service_class.return_value = mock_service_instance

    message_id = "msg-att-1"
    attachment_id = "att-1"
    filename = "test.txt"
    mime_type = "text/plain"
    mock_attachment_data = {"data": base64.urlsafe_b64encode(b"file content").decode(), "size": 12}
    mock_service_instance.get_attachment.return_value = mock_attachment_data

    args = {
        toolhandler.USER_ID_ARG: TEST_USER_ID,
        "message_id": message_id,
        "attachment_id": attachment_id,
        "mime_type": mime_type,
        "filename": filename
        # No save_to_disk arg
    }

    # Act
    results = get_attachment_handler.run_tool(args)

    # Assert
    mock_gmail_service_class.assert_called_once_with(user_id=TEST_USER_ID)
    mock_service_instance.get_attachment.assert_called_once_with(message_id, attachment_id)

    assert len(results) == 1
    assert isinstance(results[0], EmbeddedResource)
    assert results[0].type == "resource"
    assert results[0].resource.blob == mock_attachment_data["data"]
    assert results[0].resource.mimeType == mime_type
    assert str(results[0].resource.uri) == f"attachment://gmail/{message_id}/{attachment_id}/{filename}"

@patch('mcp_gsuite.tools_gmail.decode_base64_data')
@patch('builtins.open', new_callable=mock_open)
@patch('mcp_gsuite.tools_gmail.gmail.GmailService')
def test_get_attachment_save_to_disk_success(mock_gmail_service_class, mock_file_open, mock_decode, get_attachment_handler):
    """Test successful retrieval and saving of an attachment to disk."""
    # Arrange
    mock_service_instance = MagicMock()
    mock_gmail_service_class.return_value = mock_service_instance

    message_id = "msg-att-2"
    attachment_id = "att-2"
    filename = "report.pdf"
    mime_type = "application/pdf"
    save_path = "/path/to/save/report.pdf"
    raw_b64_data = base64.urlsafe_b64encode(b"pdf bytes").decode()
    decoded_bytes = b"pdf bytes"
    
    mock_attachment_data = {"data": raw_b64_data, "size": 9}
    mock_service_instance.get_attachment.return_value = mock_attachment_data
    mock_decode.return_value = decoded_bytes # Mock the decode function

    args = {
        toolhandler.USER_ID_ARG: TEST_USER_ID,
        "message_id": message_id,
        "attachment_id": attachment_id,
        "mime_type": mime_type,
        "filename": filename,
        "save_to_disk": save_path
    }

    # Act
    results = get_attachment_handler.run_tool(args)

    # Assert
    mock_gmail_service_class.assert_called_once_with(user_id=TEST_USER_ID)
    mock_service_instance.get_attachment.assert_called_once_with(message_id, attachment_id)
    mock_decode.assert_called_once_with(raw_b64_data)
    mock_file_open.assert_called_once_with(save_path, "wb")
    mock_file_open().write.assert_called_once_with(decoded_bytes)

    assert len(results) == 1
    assert isinstance(results[0], TextContent)
    assert f"Attachment saved to disk: {save_path}" in results[0].text

@patch('mcp_gsuite.tools_gmail.gmail.GmailService')
def test_get_attachment_api_failure(mock_gmail_service_class, get_attachment_handler):
    """Test get_attachment handles API failure."""
    # Arrange
    mock_service_instance = MagicMock()
    mock_gmail_service_class.return_value = mock_service_instance
    mock_service_instance.get_attachment.return_value = None # Simulate failure

    message_id = "msg-att-fail"
    attachment_id = "att-fail"
    args = {
        toolhandler.USER_ID_ARG: TEST_USER_ID,
        "message_id": message_id,
        "attachment_id": attachment_id,
        "mime_type": "text/plain",
        "filename": "fail.txt"
    }

    # Act
    results = get_attachment_handler.run_tool(args)

    # Assert
    mock_gmail_service_class.assert_called_once_with(user_id=TEST_USER_ID)
    mock_service_instance.get_attachment.assert_called_once_with(message_id, attachment_id)

    assert len(results) == 1
    assert isinstance(results[0], TextContent)
    assert f"Failed to retrieve attachment with ID: {attachment_id} from message: {message_id}" in results[0].text

@patch('mcp_gsuite.tools_gmail.gmail.GmailService')
def test_get_attachment_missing_args(mock_gmail_service_class, get_attachment_handler):
    """Test get_attachment raises error if required args are missing."""
    required = ["message_id", "attachment_id", "mime_type", "filename"]
    base_args = {
        toolhandler.USER_ID_ARG: TEST_USER_ID,
        "message_id": "m1", "attachment_id": "a1", "mime_type": "t/p", "filename": "f.txt"
    }
    for arg_to_remove in required:
        args = base_args.copy()
        del args[arg_to_remove]
        with pytest.raises(RuntimeError) as excinfo:
            get_attachment_handler.run_tool(args)
        assert f"Missing required argument: {arg_to_remove}" in str(excinfo.value)

    # Test missing user_id
    args = base_args.copy()
    del args[toolhandler.USER_ID_ARG]
    with pytest.raises(RuntimeError) as excinfo:
        get_attachment_handler.run_tool(args)
    assert toolhandler.USER_ID_ARG in str(excinfo.value)

    mock_gmail_service_class.assert_not_called()


# --- Tests for BulkGetEmailsByIdsToolHandler ---

from mcp_gsuite.tools_gmail import BulkGetEmailsByIdsToolHandler

@pytest.fixture
def bulk_get_emails_handler():
    """Fixture to provide an instance of BulkGetEmailsByIdsToolHandler."""
    return BulkGetEmailsByIdsToolHandler()

@patch('mcp_gsuite.tools_gmail.gmail.GmailService')
def test_bulk_get_emails_success(mock_gmail_service_class, bulk_get_emails_handler):
    """Test successful bulk retrieval of emails."""
    # Arrange
    mock_service_instance = MagicMock()
    mock_gmail_service_class.return_value = mock_service_instance

    email_id1 = "bulk-1"
    email_id2 = "bulk-2"
    mock_email1 = {'id': email_id1, 'subject': 'Bulk Email 1'}
    mock_atts1 = {'p1': {'filename': 'f1.txt', 'attachmentId': 'a1', 'partId': 'p1'}}
    mock_email2 = {'id': email_id2, 'subject': 'Bulk Email 2'}
    mock_atts2 = {}

    # Configure side_effect to return different values for consecutive calls
    mock_service_instance.get_email_by_id_with_attachments.side_effect = [
        (mock_email1, mock_atts1),
        (mock_email2, mock_atts2)
    ]

    args = {
        toolhandler.USER_ID_ARG: TEST_USER_ID,
        "email_ids": [email_id1, email_id2]
    }

    # Act
    results = bulk_get_emails_handler.run_tool(args)

    # Assert
    mock_gmail_service_class.assert_called_once_with(user_id=TEST_USER_ID)
    assert mock_service_instance.get_email_by_id_with_attachments.call_count == 2
    mock_service_instance.get_email_by_id_with_attachments.assert_any_call(email_id1)
    mock_service_instance.get_email_by_id_with_attachments.assert_any_call(email_id2)

    assert len(results) == 1
    assert isinstance(results[0], TextContent)

    expected_email1 = mock_email1.copy()
    expected_email1["attachments"] = mock_atts1
    expected_email2 = mock_email2.copy()
    expected_email2["attachments"] = mock_atts2
    expected_json = json.dumps([expected_email1, expected_email2], indent=2)
    assert results[0].text == expected_json

@patch('mcp_gsuite.tools_gmail.gmail.GmailService')
def test_bulk_get_emails_partial_failure(mock_gmail_service_class, bulk_get_emails_handler):
    """Test bulk retrieval where some emails fail."""
    # Arrange
    mock_service_instance = MagicMock()
    mock_gmail_service_class.return_value = mock_service_instance

    email_id1 = "bulk-ok"
    email_id_fail = "bulk-fail"
    mock_email1 = {'id': email_id1, 'subject': 'Bulk OK'}
    mock_atts1 = {}

    mock_service_instance.get_email_by_id_with_attachments.side_effect = [
        (mock_email1, mock_atts1),
        (None, {}) # Simulate failure for the second email
    ]

    args = {
        toolhandler.USER_ID_ARG: TEST_USER_ID,
        "email_ids": [email_id1, email_id_fail]
    }

    # Act
    results = bulk_get_emails_handler.run_tool(args)

    # Assert
    assert mock_service_instance.get_email_by_id_with_attachments.call_count == 2
    
    assert len(results) == 1
    assert isinstance(results[0], TextContent)

    expected_email1 = mock_email1.copy()
    expected_email1["attachments"] = mock_atts1
    expected_json = json.dumps([expected_email1], indent=2) # Only the successful one
    assert results[0].text == expected_json

@patch('mcp_gsuite.tools_gmail.gmail.GmailService')
def test_bulk_get_emails_total_failure(mock_gmail_service_class, bulk_get_emails_handler):
    """Test bulk retrieval where all emails fail."""
    # Arrange
    mock_service_instance = MagicMock()
    mock_gmail_service_class.return_value = mock_service_instance
    mock_service_instance.get_email_by_id_with_attachments.return_value = (None, {}) # All fail

    args = {
        toolhandler.USER_ID_ARG: TEST_USER_ID,
        "email_ids": ["fail1", "fail2"]
    }

    # Act
    results = bulk_get_emails_handler.run_tool(args)

    # Assert
    assert mock_service_instance.get_email_by_id_with_attachments.call_count == 2
    
    assert len(results) == 1
    assert isinstance(results[0], TextContent)
    assert "Failed to retrieve any emails" in results[0].text


# --- Tests for BulkSaveAttachmentsToolHandler ---

from mcp_gsuite.tools_gmail import BulkSaveAttachmentsToolHandler

@pytest.fixture
def bulk_save_attachments_handler():
    """Fixture to provide an instance of BulkSaveAttachmentsToolHandler."""
    return BulkSaveAttachmentsToolHandler()

@patch('mcp_gsuite.tools_gmail.decode_base64_data')
@patch('builtins.open', new_callable=mock_open)
@patch('mcp_gsuite.tools_gmail.gmail.GmailService')
def test_bulk_save_attachments_success(mock_gmail_service_class, mock_file_open, mock_decode, bulk_save_attachments_handler):
    """Test successful bulk saving of attachments."""
    # Arrange
    mock_service_instance = MagicMock()
    mock_gmail_service_class.return_value = mock_service_instance

    msg_id1 = "bulk-save-msg1"
    part_id1 = "p1"
    att_id1 = "att1"
    save_path1 = "/save/path1.txt"
    mock_email1 = {'id': msg_id1}
    mock_atts1 = {part_id1: {'filename': 'f1.txt', 'attachmentId': att_id1, 'partId': part_id1}}
    raw_b64_data1 = base64.urlsafe_b64encode(b"data1").decode()
    mock_att_data1 = {"data": raw_b64_data1}
    decoded_bytes1 = b"data1"

    msg_id2 = "bulk-save-msg2"
    part_id2 = "p2"
    att_id2 = "att2"
    save_path2 = "/save/path2.pdf"
    mock_email2 = {'id': msg_id2}
    mock_atts2 = {part_id2: {'filename': 'f2.pdf', 'attachmentId': att_id2, 'partId': part_id2}}
    raw_b64_data2 = base64.urlsafe_b64encode(b"data2").decode()
    mock_att_data2 = {"data": raw_b64_data2}
    decoded_bytes2 = b"data2"

    # Mock the sequence of calls
    mock_service_instance.get_email_by_id_with_attachments.side_effect = [
        (mock_email1, mock_atts1),
        (mock_email2, mock_atts2)
    ]
    mock_service_instance.get_attachment.side_effect = [
        mock_att_data1,
        mock_att_data2
    ]
    mock_decode.side_effect = [decoded_bytes1, decoded_bytes2]

    args = {
        toolhandler.USER_ID_ARG: TEST_USER_ID,
        "attachments": [
            {"message_id": msg_id1, "part_id": part_id1, "save_path": save_path1},
            {"message_id": msg_id2, "part_id": part_id2, "save_path": save_path2}
        ]
    }

    # Act
    results = bulk_save_attachments_handler.run_tool(args)

    # Assert
    assert mock_service_instance.get_email_by_id_with_attachments.call_count == 2
    assert mock_service_instance.get_attachment.call_count == 2
    mock_service_instance.get_attachment.assert_any_call(msg_id1, att_id1)
    mock_service_instance.get_attachment.assert_any_call(msg_id2, att_id2)
    assert mock_decode.call_count == 2
    assert mock_file_open.call_count == 2
    mock_file_open.assert_any_call(save_path1, "wb")
    mock_file_open.assert_any_call(save_path2, "wb")
    assert mock_file_open().write.call_count == 2
    mock_file_open().write.assert_any_call(decoded_bytes1)
    mock_file_open().write.assert_any_call(decoded_bytes2)

    assert len(results) == 2
    assert isinstance(results[0], TextContent)
    assert f"Attachment saved to: {save_path1}" in results[0].text
    assert isinstance(results[1], TextContent)
    assert f"Attachment saved to: {save_path2}" in results[1].text

# Add tests for partial failure, total failure, missing args for bulk save... (omitted for brevity but should be added)