# Tests for src/mcp_google_workspace/tools_drive.py
import pytest
from unittest.mock import MagicMock, patch

# TODO: Add tests
import pytest
import json
import base64
from unittest.mock import MagicMock, patch, AsyncMock
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
from mcp_google_workspace.tools_drive import (
    list_drive_files,
    get_drive_file_metadata,
    download_drive_file,
    upload_drive_file
)

# Define common test variables
TEST_USER_ID = "circa@indepreneur.io"
TEST_FILE_ID = "test_file_id_123"
TEST_FOLDER_ID = "test_folder_id_456"
TEST_OAUTH_STATE = "test_drive_state_456" # Although not used by drive tools, keep for consistency if needed elsewhere

# Mock HttpError response helper (copied from calendar tests)
def create_http_error_response(status_code, reason="Error", content=b'{"error": "details"}'):
    resp = MagicMock()
    resp.status = status_code
    resp.reason = reason
    return HttpError(resp, content)

# --- Tests for list_drive_files ---

@pytest.mark.asyncio
@patch('src.mcp_google_workspace.tools_drive.asyncio.to_thread', side_effect=lambda func, *args, **kwargs: func(*args, **kwargs))
@patch('mcp_google_workspace.tools_drive.gauth.get_google_service')
async def test_list_drive_files_success(mock_get_service, mock_to_thread):
    """Tests successful listing of drive files."""
    # Arrange
    mock_service = MagicMock()
    mock_files = MagicMock()
    mock_list_request = MagicMock()
    mock_list_request.execute = MagicMock(return_value={'files': [{'id': 'file1', 'name': 'Test File.txt'}]}) # Mock execute() directly
    mock_get_service.return_value = mock_service
    mock_service.files.return_value = mock_files
    mock_files.list.return_value = mock_list_request

    # Act
    result = await list_drive_files(user_id=TEST_USER_ID, query="name contains 'Test'")

    # Assert
    mock_get_service.assert_called_once_with('drive', 'v3', TEST_USER_ID)
    mock_service.files.assert_called_once()
    mock_files.list.assert_called_once_with(
        q="name contains 'Test'",
        pageSize=100,
        fields="nextPageToken, files(id, name, mimeType, size, modifiedTime, parents)"
    )
    # Assert that the execute method was called
    mock_list_request.execute.assert_called_once()
    assert isinstance(result, list)
    assert len(result) == 1
    assert isinstance(result[0], TextContent)
    expected_json = json.dumps({'files': [{'id': 'file1', 'name': 'Test File.txt'}]})
    assert result[0].text == expected_json

@pytest.mark.asyncio
@patch('src.mcp_google_workspace.tools_drive.asyncio.to_thread', side_effect=lambda func, *args, **kwargs: func(*args, **kwargs))
@patch('mcp_google_workspace.tools_drive.gauth.get_google_service')
async def test_list_drive_files_auth_error(mock_get_service, mock_to_thread):
    """Tests handling of AuthenticationError during file listing."""
    # Arrange
    mock_get_service.side_effect = AuthenticationError("Drive Auth Failed")

    # Act & Assert
    with pytest.raises(AuthenticationError, match="Drive Auth Failed"):
        await list_drive_files(user_id=TEST_USER_ID)

    mock_get_service.assert_called_once_with('drive', 'v3', TEST_USER_ID)

@pytest.mark.asyncio
@patch('src.mcp_google_workspace.tools_drive.asyncio.to_thread', side_effect=lambda func, *args, **kwargs: func(*args, **kwargs))
@patch('mcp_google_workspace.tools_drive.gauth.get_google_service')
async def test_list_drive_files_http_error(mock_get_service, mock_to_thread):
    """Tests handling of HttpError during file listing."""
    # Arrange
    mock_service = MagicMock()
    mock_files = MagicMock()
    mock_list_request = MagicMock()
    mock_list_request.execute = MagicMock(side_effect=create_http_error_response(403, "Forbidden", b'{"error": {"message": "API limit exceeded"}}'))
    mock_get_service.return_value = mock_service
    mock_service.files.return_value = mock_files
    mock_files.list.return_value = mock_list_request

    # Act & Assert
    # Escape special characters in the JSON for regex matching
    expected_pattern = r"Google API Error: 403 API limit exceeded\. Details: \{\"error\": \{\"message\": \"API limit exceeded\"\}\}" # Match actual error output
    with pytest.raises(RuntimeError, match=expected_pattern):
        await list_drive_files(user_id=TEST_USER_ID)

    mock_get_service.assert_called_once_with('drive', 'v3', TEST_USER_ID)
    mock_list_request.execute.assert_called_once()


# --- Tests for get_drive_file_metadata ---

@pytest.mark.asyncio
@patch('src.mcp_google_workspace.tools_drive.asyncio.to_thread', side_effect=lambda func, *args, **kwargs: func(*args, **kwargs))
@patch('mcp_google_workspace.tools_drive.gauth.get_google_service')
async def test_get_drive_file_metadata_success(mock_get_service, mock_to_thread):
    """Tests successful retrieval of file metadata."""
    # Arrange
    mock_service = MagicMock()
    mock_files = MagicMock()
    mock_get_request = MagicMock()
    metadata = {'id': TEST_FILE_ID, 'name': 'My Doc.gdoc', 'mimeType': 'application/vnd.google-apps.document'}
    mock_get_request.execute = MagicMock(return_value=metadata)
    mock_get_service.return_value = mock_service
    mock_service.files.return_value = mock_files
    mock_files.get.return_value = mock_get_request

    # Act
    result = await get_drive_file_metadata(file_id=TEST_FILE_ID, user_id=TEST_USER_ID)

    # Assert
    mock_get_service.assert_called_once_with('drive', 'v3', TEST_USER_ID)
    mock_service.files.assert_called_once()
    expected_fields = ("id, name, mimeType, size, modifiedTime, createdTime, "
                       "owners, parents, webViewLink, iconLink")
    mock_files.get.assert_called_once_with(fileId=TEST_FILE_ID, fields=expected_fields)
    mock_get_request.execute.assert_called_once()
    assert isinstance(result, list)
    assert len(result) == 1
    assert isinstance(result[0], TextContent)
    assert result[0].text == json.dumps(metadata)

@pytest.mark.asyncio
@patch('src.mcp_google_workspace.tools_drive.asyncio.to_thread', side_effect=lambda func, *args, **kwargs: func(*args, **kwargs))
@patch('mcp_google_workspace.tools_drive.gauth.get_google_service')
async def test_get_drive_file_metadata_auth_error(mock_get_service, mock_to_thread):
    """Tests handling of AuthenticationError during metadata retrieval."""
    # Arrange
    mock_get_service.side_effect = AuthenticationError("Drive Auth Failed")

    # Act & Assert
    with pytest.raises(AuthenticationError, match="Drive Auth Failed"):
        await get_drive_file_metadata(file_id=TEST_FILE_ID, user_id=TEST_USER_ID)

    mock_get_service.assert_called_once_with('drive', 'v3', TEST_USER_ID)

@pytest.mark.asyncio
@patch('src.mcp_google_workspace.tools_drive.asyncio.to_thread', side_effect=lambda func, *args, **kwargs: func(*args, **kwargs))
@patch('mcp_google_workspace.tools_drive.gauth.get_google_service')
async def test_get_drive_file_metadata_http_error_404(mock_get_service, mock_to_thread):
    """Tests handling of 404 HttpError (file not found) during metadata retrieval."""
    # Arrange
    mock_service = MagicMock()
    mock_files = MagicMock()
    mock_get_request = MagicMock()
    mock_get_request.execute = MagicMock(side_effect=create_http_error_response(404, "Not Found", b'{"error": "File not found"}'))
    mock_get_service.return_value = mock_service
    mock_service.files.return_value = mock_files
    mock_files.get.return_value = mock_get_request

    # Act & Assert
    with pytest.raises(FileNotFoundError, match=f"File with ID '{TEST_FILE_ID}' not found."):
        await get_drive_file_metadata(file_id=TEST_FILE_ID, user_id=TEST_USER_ID)

    mock_get_service.assert_called_once_with('drive', 'v3', TEST_USER_ID)
    mock_get_request.execute.assert_called_once()


# --- Tests for download_drive_file ---

@pytest.mark.asyncio
@patch('src.mcp_google_workspace.tools_drive.base64.b64encode', return_value=b'dGVzdCBjb250ZW50') # Mock base64 encoding
@patch('src.mcp_google_workspace.tools_drive.asyncio.to_thread', side_effect=lambda func, *args, **kwargs: func(*args, **kwargs))
@patch('mcp_google_workspace.tools_drive.gauth.get_google_service')
async def test_download_drive_file_success(mock_get_service, mock_to_thread, mock_b64encode):
    """Tests successful download of a drive file."""
    # Arrange
    mock_service = MagicMock()
    mock_files = MagicMock()
    mock_get_request_meta = MagicMock()
    mock_get_media_request = MagicMock()
    mock_get_service.return_value = mock_service
    mock_service.files.return_value = mock_files
    mock_files.get.return_value = mock_get_request_meta
    mock_files.get_media.return_value = mock_get_media_request

    # Mock return values for the two run_google_api_call invocations
    metadata = {'name': 'download.txt', 'mimeType': 'text/plain'}
    file_content = b'test content'
    # Mock the execute methods for both metadata and media requests
    mock_get_request_meta.execute = MagicMock(return_value=metadata)
    mock_get_media_request.execute = MagicMock(return_value=file_content)

    # Act
    result = await download_drive_file(file_id=TEST_FILE_ID, user_id=TEST_USER_ID)

    # Assert
    mock_get_service.assert_called_once_with('drive', 'v3', TEST_USER_ID)
    assert mock_service.files.call_count == 2 # Called for get() and get_media()
    mock_files.get.assert_called_once_with(fileId=TEST_FILE_ID, fields="name, mimeType")
    mock_files.get_media.assert_called_once_with(fileId=TEST_FILE_ID)

    # Assert execute methods were called
    mock_get_request_meta.execute.assert_called_once()
    mock_get_media_request.execute.assert_called_once()

    mock_b64encode.assert_called_once_with(file_content)

    assert isinstance(result, EmbeddedResource)
    assert result.type == "resource"
    assert result.title == 'download.txt'
    assert result.description == f"Downloaded content for Google Drive file ID: {TEST_FILE_ID}"
    assert result.resource.blob == 'dGVzdCBjb250ZW50' # Check encoded content (Attribute access)
    assert str(result.resource.uri) == f"drive://{TEST_FILE_ID}/download.txt" # Compare string representation
    assert result.resource.mimeType == 'text/plain'

@pytest.mark.asyncio
@patch('src.mcp_google_workspace.tools_drive.asyncio.to_thread', side_effect=lambda func, *args, **kwargs: func(*args, **kwargs))
@patch('mcp_google_workspace.tools_drive.gauth.get_google_service')
async def test_download_drive_file_metadata_404(mock_get_service, mock_to_thread):
    """Tests download failure when metadata check returns 404."""
    # Arrange
    mock_service = MagicMock()
    mock_files = MagicMock()
    mock_get_request_meta = MagicMock()
    mock_get_service.return_value = mock_service
    mock_service.files.return_value = mock_files
    mock_files.get.return_value = mock_get_request_meta
    # Metadata call fails
    mock_get_request_meta.execute = MagicMock(side_effect=create_http_error_response(404, "Not Found", b'{"error": "File not found"}'))

    # Act & Assert
    with pytest.raises(FileNotFoundError, match=f"File with ID '{TEST_FILE_ID}' not found or access denied."):
        await download_drive_file(file_id=TEST_FILE_ID, user_id=TEST_USER_ID)

    mock_get_service.assert_called_once_with('drive', 'v3', TEST_USER_ID)
    mock_get_request_meta.execute.assert_called_once() # Only metadata call happens

@pytest.mark.asyncio
@patch('src.mcp_google_workspace.tools_drive.asyncio.to_thread', side_effect=lambda func, *args, **kwargs: func(*args, **kwargs))
@patch('mcp_google_workspace.tools_drive.gauth.get_google_service')
async def test_download_drive_file_download_403(mock_get_service, mock_to_thread):
    """Tests download failure when download step returns 403."""
    # Arrange
    mock_service = MagicMock()
    mock_files = MagicMock()
    mock_get_request_meta = MagicMock()
    mock_get_media_request = MagicMock()
    mock_get_service.return_value = mock_service
    mock_service.files.return_value = mock_files
    mock_files.get.return_value = mock_get_request_meta
    mock_files.get_media.return_value = mock_get_media_request

    metadata = {'name': 'download.txt', 'mimeType': 'text/plain'}
    # Metadata call succeeds, download call fails
    mock_get_request_meta.execute = MagicMock(return_value=metadata)
    mock_get_media_request.execute = MagicMock(side_effect=create_http_error_response(403, "Forbidden", b'{"error": "Permission denied"}'))

    # Act & Assert
    with pytest.raises(PermissionError, match=f"Permission denied to download file '{TEST_FILE_ID}'."):
        await download_drive_file(file_id=TEST_FILE_ID, user_id=TEST_USER_ID)

    mock_get_service.assert_called_once_with('drive', 'v3', TEST_USER_ID)
    mock_get_request_meta.execute.assert_called_once()
    mock_get_media_request.execute.assert_called_once()


# --- Tests for upload_drive_file ---

@pytest.mark.asyncio
@patch('io.BytesIO', return_value=BytesIO(b'decoded content')) # Mock BytesIO from standard library
@patch('mcp_google_workspace.tools_drive.base64.b64decode', return_value=b'decoded content') # Mock base64 decoding
@patch('mcp_google_workspace.tools_drive.asyncio.to_thread', side_effect=lambda func, *args, **kwargs: func(*args, **kwargs))
@patch('mcp_google_workspace.tools_drive.gauth.get_google_service')
async def test_upload_drive_file_success(mock_get_service, mock_to_thread, mock_b64decode, mock_bytesio):
    """Tests successful upload of a drive file."""
    # Arrange
    mock_service = MagicMock()
    mock_files = MagicMock()
    mock_create_request = MagicMock()
    mock_get_service.return_value = mock_service
    mock_service.files.return_value = mock_files
    mock_files.create.return_value = mock_create_request
    upload_response = {'id': 'new_file_id', 'name': 'upload.txt', 'webViewLink': 'http://...'}
    mock_create_request.execute = MagicMock(return_value=upload_response)
    file_content_b64 = "ZGVjb2RlZCBjb250ZW50" # "decoded content"

    # Act
    result = await upload_drive_file(
        file_name='upload.txt',
        mime_type='text/plain',
        file_content_b64=file_content_b64,
        user_id=TEST_USER_ID,
        folder_id=TEST_FOLDER_ID
    )

    # Assert
    mock_get_service.assert_called_once_with('drive', 'v3', TEST_USER_ID)
    mock_b64decode.assert_called_once_with(file_content_b64)
    mock_bytesio.assert_called_once_with(b'decoded content')
    mock_service.files.assert_called_once()
    expected_metadata = {'name': 'upload.txt', 'parents': [TEST_FOLDER_ID]}
    mock_files.create.assert_called_once_with(
        body=expected_metadata,
        media_body=mock_bytesio.return_value, # Check that the BytesIO object was passed
        fields='id, name, webViewLink'
    )
    mock_create_request.execute.assert_called_once()
    assert isinstance(result, list)
    assert len(result) == 1
    assert isinstance(result[0], TextContent)
    assert result[0].text == json.dumps(upload_response)

@pytest.mark.asyncio
@patch('src.mcp_google_workspace.tools_drive.base64.b64decode', side_effect=Exception("Bad decode")) # Mock base64 decoding failure
@patch('src.mcp_google_workspace.tools_drive.asyncio.to_thread', side_effect=lambda func, *args, **kwargs: func(*args, **kwargs))
@patch('mcp_google_workspace.tools_drive.gauth.get_google_service')
async def test_upload_drive_file_decode_error(mock_get_service, mock_to_thread, mock_b64decode):
    """Tests handling of base64 decode error during upload."""
    # Arrange
    mock_service = MagicMock()
    mock_get_service.return_value = mock_service # Service needed before decode
    file_content_b64 = "this is not base64"

    # Act & Assert
    with pytest.raises(ValueError, match="Invalid base64 encoding provided for file 'bad_upload.txt'."):
        await upload_drive_file(
            file_name='bad_upload.txt',
            mime_type='text/plain',
            file_content_b64=file_content_b64,
            user_id=TEST_USER_ID
        )

    mock_get_service.assert_called_once_with('drive', 'v3', TEST_USER_ID)
    mock_b64decode.assert_called_once_with(file_content_b64)

@pytest.mark.asyncio
@patch('io.BytesIO', return_value=BytesIO(b'decoded content')) # Mock BytesIO from standard library
@patch('mcp_google_workspace.tools_drive.base64.b64decode', return_value=b'decoded content')
@patch('mcp_google_workspace.tools_drive.asyncio.to_thread', side_effect=lambda func, *args, **kwargs: func(*args, **kwargs))
@patch('mcp_google_workspace.tools_drive.gauth.get_google_service')
async def test_upload_drive_file_http_error_404_folder(mock_get_service, mock_to_thread, mock_b64decode, mock_bytesio):
    """Tests handling of 404 HttpError (folder not found) during upload."""
    # Arrange
    mock_service = MagicMock()
    mock_files = MagicMock()
    mock_create_request = MagicMock()
    mock_get_service.return_value = mock_service
    mock_service.files.return_value = mock_files
    mock_files.create.return_value = mock_create_request
    mock_create_request.execute = MagicMock(side_effect=create_http_error_response(404, "Not Found", b'{"error": "Folder not found"}'))
    file_content_b64 = "ZGVjb2RlZCBjb250ZW50"

    # Act & Assert
    with pytest.raises(FileNotFoundError, match=f"Target folder with ID '{TEST_FOLDER_ID}' not found."):
        await upload_drive_file(
            file_name='upload.txt',
            mime_type='text/plain',
            file_content_b64=file_content_b64,
            user_id=TEST_USER_ID,
            folder_id=TEST_FOLDER_ID # Specify folder ID
        )

    mock_get_service.assert_called_once_with('drive', 'v3', TEST_USER_ID)
    mock_create_request.execute.assert_called_once()