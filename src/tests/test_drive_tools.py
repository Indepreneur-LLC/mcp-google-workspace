import pytest
import json
from unittest.mock import patch, MagicMock
import base64
import os
from oauth2client.client import Credentials # For loading real credentials

# Assuming mcp_gsuite is importable in the test environment
from mcp_gsuite import server, gauth, drive, tools_drive
from mcp_gsuite.toolhandler import USER_ID_ARG
from mcp.types import TextContent, EmbeddedResource

# --- Test Data ---
TEST_USER_ID = "circa@indepreneur.io" # Use the actual test user
TEST_CREDENTIAL_PATH = "/app/credentials/.test.oauth2.circa@indepreneur.io.json" # Path inside container

MOCK_FILE_ID = "mock_file_id_123" # Keep mocks for API responses
MOCK_FOLDER_ID = "mock_folder_id_456"
MOCK_FILE_NAME = "test_upload.txt"
MOCK_MIME_TYPE = "text/plain"
MOCK_FILE_CONTENT = b"This is test content."
MOCK_FILE_CONTENT_B64 = base64.b64encode(MOCK_FILE_CONTENT).decode('utf-8')

# --- Real Test Credentials Fixture ---
@pytest.fixture(scope="module") # Load once per module
def real_test_credentials():
    """Loads the real test credentials from the file."""
    if not os.path.exists(TEST_CREDENTIAL_PATH):
        pytest.fail(f"Test credentials file not found at {TEST_CREDENTIAL_PATH}. "
                    f"Generate it using create_test_credentials.py first.")
    try:
        with open(TEST_CREDENTIAL_PATH, 'r') as f:
            creds_data = f.read()
        credentials = Credentials.new_from_json(creds_data)
        # Optional: Check if token needs refresh? For testing, assume it's valid enough.
        # if credentials.access_token_expired:
        #     # Handle refresh if necessary for tests, though likely not needed if mocking API calls
        #     pass
        return credentials
    except Exception as e:
        pytest.fail(f"Failed to load test credentials from {TEST_CREDENTIAL_PATH}: {e}")

# --- Mock Credentials (Keep for comparison or specific tests if needed) ---
# @pytest.fixture
# def mock_credentials():
#     creds = MagicMock(spec=gauth.OAuth2Credentials)
#     creds.access_token_expired = False
#     creds.authorize = MagicMock()
#     return creds

# --- Mock Drive Service ---
@pytest.fixture
def mock_drive_service():
    service = MagicMock()
    # Mock files().list()
    service.files().list().execute.return_value = {
        'files': [{'id': MOCK_FILE_ID, 'name': 'mock_file.txt', 'mimeType': 'text/plain'}]
    }
    # Mock files().get()
    service.files().get().execute.return_value = {
        'id': MOCK_FILE_ID, 'name': 'mock_file.txt', 'mimeType': 'text/plain', 'size': '1024'
    }
    # Mock files().get_media() - Requires mocking MediaIoBaseDownload interaction
    # This part is more complex to mock accurately without deeper library knowledge
    mock_downloader = MagicMock()
    mock_downloader.next_chunk.side_effect = [(MagicMock(progress=lambda: 1.0), True)] # Simulate one chunk download
    # We need get_media to return an object that MediaIoBaseDownload can use
    # For simplicity, let's assume download_file directly returns bytes for now in the mock
    # A better mock would involve mocking the http request/response within get_media

    # Mock files().create() - Requires mocking MediaIoBaseUpload interaction
    # Similar complexity to download
    service.files().create().execute.return_value = {
        'id': 'new_mock_file_id', 'name': MOCK_FILE_NAME, 'webViewLink': 'http://example.com/new_file'
    }
    # A better mock would involve mocking the resumable upload process

    return service

# --- Tests ---

@patch('mcp_gsuite.tools_drive.gauth.get_stored_credentials')
@patch('mcp_gsuite.tools_drive.drive.get_drive_service')
@patch('mcp_gsuite.tools_drive.gauth.store_credentials') # Mock storing credentials
def test_list_drive_files(mock_store_creds, mock_get_service, mock_get_creds, real_test_credentials, mock_drive_service):
    """Test the list_drive_files tool handler using real test credentials."""
    # Mock get_stored_credentials to return the real test credentials
    mock_get_creds.return_value = real_test_credentials
    # Mock get_drive_service to return the mocked service
    mock_get_service.return_value = mock_drive_service

    handler = tools_drive.ListDriveFilesToolHandler()
    args = {USER_ID_ARG: TEST_USER_ID} # Use the correct test user ID

    result = handler.run_tool(args)

    assert isinstance(result, list)
    assert len(result) == 1
    assert isinstance(result[0], TextContent)
    data = json.loads(result[0].text)
    assert isinstance(data, list)
    assert len(data) == 1
    assert data[0]['id'] == MOCK_FILE_ID
    mock_get_creds.assert_called_once_with(user_id=TEST_USER_ID)
    mock_get_service.assert_called_once_with(real_test_credentials) # Ensure service is built with real creds
    mock_drive_service.files().list().execute.assert_called_once() # Check the execute() call
    mock_store_creds.assert_called_once() # Check if creds were stored back

@patch('mcp_gsuite.tools_drive.gauth.get_stored_credentials')
@patch('mcp_gsuite.tools_drive.drive.get_drive_service')
@patch('mcp_gsuite.tools_drive.gauth.store_credentials')
def test_get_drive_file_metadata(mock_store_creds, mock_get_service, mock_get_creds, real_test_credentials, mock_drive_service):
    """Test the get_drive_file_metadata tool handler using real test credentials."""
    mock_get_creds.return_value = real_test_credentials
    mock_get_service.return_value = mock_drive_service

    handler = tools_drive.GetDriveFileMetadataToolHandler()
    args = {USER_ID_ARG: TEST_USER_ID, "file_id": MOCK_FILE_ID}

    result = handler.run_tool(args)

    assert isinstance(result, list)
    assert len(result) == 1
    assert isinstance(result[0], TextContent)
    data = json.loads(result[0].text)
    assert data['id'] == MOCK_FILE_ID
    mock_get_creds.assert_called_once_with(user_id=TEST_USER_ID)
    mock_get_service.assert_called_once_with(real_test_credentials)
    # Note: args['fields'] won't work directly as args is now a dict. Need default from handler or define here.
    # For simplicity, let's assume the default field value or mock the call precisely.
    # We'll check the call was made with the correct fileId for now.
    get_call_args, get_call_kwargs = mock_drive_service.files().get.call_args
    assert get_call_kwargs.get('fileId') == MOCK_FILE_ID
    # assert get_call_kwargs.get('fields') == "id, name, mimeType, size, modifiedTime, createdTime, owners, parents, webViewLink, iconLink" # Example if checking default
    mock_store_creds.assert_called_once()

# NOTE: Download and Upload tests require more sophisticated mocking of MediaIoBaseDownload/Upload
# or mocking the underlying drive.download_file/upload_file functions directly.

@patch('mcp_gsuite.tools_drive.gauth.get_stored_credentials')
@patch('mcp_gsuite.tools_drive.drive.get_drive_service')
@patch('mcp_gsuite.tools_drive.drive.download_file') # Mock the core download function
@patch('mcp_gsuite.tools_drive.drive.get_file_metadata') # Mock metadata lookup for filename
@patch('mcp_gsuite.tools_drive.gauth.store_credentials')
def test_download_drive_file(mock_store_creds, mock_get_meta, mock_download, mock_get_service, mock_get_creds, real_test_credentials, mock_drive_service):
    """Test the download_drive_file tool handler using real test credentials (simplified mock)."""
    mock_get_creds.return_value = real_test_credentials
    mock_get_service.return_value = mock_drive_service
    mock_download.return_value = MOCK_FILE_CONTENT
    mock_get_meta.return_value = {'name': 'mock_file.txt', 'mimeType': 'text/plain'}

    handler = tools_drive.DownloadDriveFileToolHandler()
    args = {USER_ID_ARG: TEST_USER_ID, "file_id": MOCK_FILE_ID}

    result = handler.run_tool(args)

    assert isinstance(result, list)
    assert len(result) == 1
    assert isinstance(result[0], EmbeddedResource)
    # Assert the decoded blob content matches the original mock content
    assert base64.b64decode(result[0].resource.blob) == MOCK_FILE_CONTENT # Use attribute access
    assert result[0].title == 'mock_file.txt'
    assert result[0].resource.mimeType == 'text/plain' # Check mimeType within resource object
    mock_get_creds.assert_called_once_with(user_id=TEST_USER_ID)
    # Check that get_drive_service was called (potentially twice if metadata is fetched after download)
    mock_get_service.assert_called_with(real_test_credentials)
    mock_download.assert_called_once_with(mock_drive_service, file_id=MOCK_FILE_ID)
    mock_get_meta.assert_called_once() # Check metadata was fetched
    mock_store_creds.assert_called_once()

@patch('mcp_gsuite.tools_drive.gauth.get_stored_credentials')
@patch('mcp_gsuite.tools_drive.drive.get_drive_service')
@patch('mcp_gsuite.tools_drive.drive.upload_file') # Mock the core upload function
@patch('mcp_gsuite.tools_drive.gauth.store_credentials')
def test_upload_drive_file(mock_store_creds, mock_upload, mock_get_service, mock_get_creds, real_test_credentials, mock_drive_service):
    """Test the upload_drive_file tool handler using real test credentials (simplified mock)."""
    mock_get_creds.return_value = real_test_credentials
    mock_get_service.return_value = mock_drive_service
    mock_upload.return_value = {'id': 'new_mock_file_id', 'name': MOCK_FILE_NAME}

    handler = tools_drive.UploadDriveFileToolHandler()
    args = {
        USER_ID_ARG: TEST_USER_ID,
        "file_name": MOCK_FILE_NAME,
        "mime_type": MOCK_MIME_TYPE,
        "file_content_b64": MOCK_FILE_CONTENT_B64,
        "folder_id": MOCK_FOLDER_ID
    }

    result = handler.run_tool(args)

    assert isinstance(result, list)
    assert len(result) == 1
    assert isinstance(result[0], TextContent)
    data = json.loads(result[0].text)
    assert data['id'] == 'new_mock_file_id'
    mock_get_creds.assert_called_once_with(user_id=TEST_USER_ID)
    mock_get_service.assert_called_once_with(real_test_credentials)
    mock_upload.assert_called_once_with(
        mock_drive_service,
        file_name=MOCK_FILE_NAME,
        mime_type=MOCK_MIME_TYPE,
        file_content=MOCK_FILE_CONTENT, # Check decoded content
        folder_id=MOCK_FOLDER_ID
    )
    mock_store_creds.assert_called_once()

# TODO: Add tests for error handling (e.g., invalid credentials, API errors, file not found)
# TODO: Add tests for edge cases (e.g., empty file list, large files if applicable)