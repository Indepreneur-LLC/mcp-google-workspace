# ===== IMPORTS ===== #

## ===== STANDARD LIBRARY ===== ##
from typing import Sequence
import logging
import asyncio
import base64
import json
##-##

## ===== THIRD-PARTY ===== ##
from mcp.types import (
    EmbeddedResource,
    TextContent,
)
from googleapiclient.errors import HttpError
import google.auth.exceptions
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
async def list_drive_files(
    user_id: str,
    query: str | None = None,
    page_size: int = 100,
    fields: str = "nextPageToken, files(id, name, mimeType, size, modifiedTime, parents)"
) -> Sequence[TextContent | EmbeddedResource]:
    """Lists Google Drive files."""
    try:
        if not user_id: raise ValueError("user_id must be provided.") # Use standard error

        # Get service using gauth helper
        service = await asyncio.to_thread(gauth.get_google_service, 'drive', 'v3', user_id)
        if service is None:
            # This case should ideally be handled by get_google_service raising AuthenticationError
            logger.error(f"Failed to obtain Google Drive service for user {user_id}. Credentials might be missing or invalid.")
            raise gauth.AuthenticationError(f"Failed to obtain Google Drive service for user {user_id}. Authentication may be required or invalid.")

        # Call the underlying drive function (assuming it's synchronous)
        list_request = service.files().list(
            q=query,
            pageSize=page_size,
            fields=fields
        )
        files = await asyncio.to_thread(list_request.execute)

        # Wrap the file list dict in TextContent after JSON serialization
        return [TextContent(type="text", text=json.dumps(files))]

    except gauth.AuthenticationError as auth_error:
        # Re-raise the specific authentication error for the MCP server to handle
        logger.warning(f"Authentication error in list_drive_files for user {user_id}: {auth_error}")
        raise auth_error # Propagate the error
    except HttpError as e:
        logger.error(f"Google API HTTP error in list_drive_files for user {user_id}: {e}", exc_info=True)
        # Raise a standard runtime error for the MCP server
        raise RuntimeError(f"Google API Error: {e.resp.status} {e.reason}. Details: {e.content.decode()}")
    except Exception as e:
        logger.error(f"Unexpected error in list_drive_files for user {user_id}: {e}", exc_info=True)
        # Raise a standard runtime error
        raise RuntimeError(f"Failed to list Drive files for {user_id}. Reason: {e}")

async def get_drive_file_metadata(
    file_id: str,
    user_id: str,
    fields: str = ("id, name, mimeType, size, modifiedTime, createdTime, "
                   "owners, parents, webViewLink, iconLink")
) -> Sequence[TextContent | EmbeddedResource]:
    """Gets metadata for a Google Drive file."""
    try:
        if not user_id: raise ValueError("user_id must be provided.")
        if not file_id: raise ValueError("file_id must be provided.")

        # Get service using gauth helper
        service = await asyncio.to_thread(gauth.get_google_service, 'drive', 'v3', user_id)
        if service is None:
            logger.error(f"Failed to obtain Google Drive service for user {user_id}.")
            raise gauth.AuthenticationError(f"Failed to obtain Google Drive service for user {user_id}. Authentication may be required or invalid.")

        # Call the underlying API (assuming synchronous)
        get_request = service.files().get(fileId=file_id, fields=fields)
        metadata = await asyncio.to_thread(get_request.execute)

        # Wrap the metadata dict in TextContent after JSON serialization
        return [TextContent(type="text", text=json.dumps(metadata))]

    except gauth.AuthenticationError as auth_error:
        logger.warning(f"Authentication error in get_drive_file_metadata for user {user_id}, file {file_id}: {auth_error}")
        raise auth_error # Propagate
    except HttpError as e:
        if e.resp.status == 404:
            logger.warning(f"File {file_id} not found for metadata request by user {user_id}: {e}")
            # Raise a standard FileNotFoundError
            raise FileNotFoundError(f"File with ID '{file_id}' not found.")
        else:
            logger.error(f"Google API HTTP error in get_drive_file_metadata for user {user_id}, file {file_id}: {e}", exc_info=True)
            # Raise a standard runtime error
            raise RuntimeError(f"Google API Error: {e.resp.status} {e.reason}. Details: {e.content.decode()}")
    except Exception as e:
        logger.error(f"Unexpected error in get_drive_file_metadata for user {user_id}, file {file_id}: {e}", exc_info=True)
        # Raise a standard runtime error
        raise RuntimeError(f"Failed to get metadata for file {file_id} for user {user_id}. Reason: {e}")

async def download_drive_file(file_id: str, user_id: str) -> EmbeddedResource:
    """Downloads a Google Drive file and returns it as an EmbeddedResource."""
    try:
        if not user_id: raise ValueError("user_id must be provided.")
        if not file_id: raise ValueError("file_id must be provided.")

        # Get service using gauth helper
        service = await asyncio.to_thread(gauth.get_google_service, 'drive', 'v3', user_id)
        if service is None:
            logger.error(f"Failed to obtain Google Drive service for user {user_id}.")
            raise gauth.AuthenticationError(f"Failed to obtain Google Drive service for user {user_id}. Authentication may be required or invalid.")

        # --- Get Metadata First ---
        try:
            get_request_meta = service.files().get(fileId=file_id, fields="name, mimeType")
            metadata = await asyncio.to_thread(get_request_meta.execute)
            filename = metadata.get("name", file_id)
            mimetype = metadata.get("mimeType", "application/octet-stream")
        except HttpError as meta_http_error:
            # If metadata fails with 404, the file doesn't exist or isn't accessible
            if meta_http_error.resp.status == 404:
                logger.warning(f"File {file_id} not found for metadata check before download by user {user_id}: {meta_http_error}")
                raise FileNotFoundError(f"File with ID '{file_id}' not found or access denied.")
            # Handle 403 for permission issues
            elif meta_http_error.resp.status == 403:
                 logger.warning(f"Permission denied getting metadata for file {file_id} for user {user_id}: {meta_http_error}")
                 raise PermissionError(f"Permission denied to access metadata for file '{file_id}'.")
            else:
                # Re-raise other HttpErrors from metadata call
                logger.error(f"Google API HTTP error getting metadata before download for user {user_id}, file {file_id}: {meta_http_error}", exc_info=True)
                raise RuntimeError(f"Google API Error getting metadata: {meta_http_error.resp.status} {meta_http_error.reason}. Details: {meta_http_error.content.decode()}")
        except Exception as meta_e:
            logger.error(f"Unexpected error getting metadata before download for user {user_id}, file {file_id}: {meta_e}", exc_info=True)
            raise RuntimeError(f"Failed to get metadata before downloading file {file_id}. Reason: {meta_e}")

        # --- Download File Content ---
        # Use media download request
        request = service.files().get_media(fileId=file_id)
        # Execute the download in a thread
        file_content = await asyncio.to_thread(request.execute)

        if file_content is None:
            # This case might indicate an issue not caught by HttpError (unlikely for download)
            logger.error(f"Drive API download returned None unexpectedly for file {file_id}, user {user_id}")
            raise RuntimeError(f"File download for ID '{file_id}' failed unexpectedly after metadata check.")

        # --- Encode and Package ---
        # Encode content (run in thread for potentially large files)
        try:
            file_content_b64 = await asyncio.to_thread(lambda: base64.b64encode(file_content).decode('utf-8'))
        except Exception as encode_error: # Catch broad exception during encoding
             logger.error(f"Base64 encoding error for downloaded file {file_id}, user {user_id}: {encode_error}", exc_info=True)
             raise RuntimeError(f"Failed to encode downloaded file data. Reason: {encode_error}")


        # Construct the EmbeddedResource
        resource_dict = {
            "blob": file_content_b64,
            "uri": f"drive://{file_id}/{filename}", # Include filename in URI
            "mimeType": mimetype
        }
        # Return the single EmbeddedResource
        return EmbeddedResource(type="resource", resource=resource_dict, title=filename,
                                description=f"Downloaded content for Google Drive file ID: {file_id}")

    except gauth.AuthenticationError as auth_error:
        logger.warning(f"Authentication error in download_drive_file for user {user_id}, file {file_id}: {auth_error}")
        raise auth_error # Propagate
    except FileNotFoundError as fnf_error: # Catch specific file not found from metadata check
        raise fnf_error
    except PermissionError as perm_error: # Catch specific permission error from metadata check
        raise perm_error
    except HttpError as e:
        # Catch errors specifically from the download step (metadata errors handled above)
        if e.resp.status == 404: # Should have been caught by metadata check, but handle defensively
            logger.warning(f"File {file_id} not found during download attempt by user {user_id}: {e}")
            raise FileNotFoundError(f"File with ID '{file_id}' not found during download.")
        elif e.resp.status == 403:
            logger.warning(f"Permission denied downloading file {file_id} for user {user_id}: {e}")
            raise PermissionError(f"Permission denied to download file '{file_id}'.")
        else:
            logger.error(f"Google API HTTP error during download for user {user_id}, file {file_id}: {e}", exc_info=True)
            raise RuntimeError(f"Google API Error downloading file: {e.resp.status} {e.reason}. Details: {e.content.decode()}")
    except Exception as e:
        logger.error(f"Unexpected error in download_drive_file for user {user_id}, file {file_id}: {e}", exc_info=True)
        raise RuntimeError(f"Failed to download file {file_id}. Reason: {e}")
##-##

### ----- WRITE/MODIFY TOOLS ----- ###
async def upload_drive_file(
    file_name: str,
    mime_type: str,
    file_content_b64: str,
    user_id: str,
    folder_id: str | None = None
) -> Sequence[TextContent | EmbeddedResource]:
    """Uploads a file to Google Drive."""
    try:
        if not user_id: raise ValueError("user_id must be provided.")
        if not file_name: raise ValueError("file_name must be provided.")
        if not mime_type: raise ValueError("mime_type must be provided.")
        if not file_content_b64: raise ValueError("file_content_b64 must be provided.")

        # Get service using gauth helper
        service = await asyncio.to_thread(gauth.get_google_service, 'drive', 'v3', user_id)
        if service is None:
            logger.error(f"Failed to obtain Google Drive service for user {user_id}.")
            raise gauth.AuthenticationError(f"Failed to obtain Google Drive service for user {user_id}. Authentication may be required or invalid.")

        # Decode base64 content (run in thread)
        try:
            file_content = await asyncio.to_thread(base64.b64decode, file_content_b64)
        except Exception as decode_error: # Catch broad exception during decode
            logger.error(f"Failed to decode base64 content for upload '{file_name}' (user: {user_id}): {decode_error}", exc_info=True)
            # Raise standard ValueError for bad input
            raise ValueError(f"Invalid base64 encoding provided for file '{file_name}'.") from decode_error

        # Prepare file metadata
        file_metadata = {'name': file_name}
        if folder_id:
            file_metadata['parents'] = [folder_id]

        # Prepare media body
        # Use io.BytesIO for the media body
        import io
        media_body = io.BytesIO(file_content)

        # Execute upload (run in thread)
        create_request = service.files().create(
            body=file_metadata,
            media_body=media_body, # Pass BytesIO directly
            # media_mime_type=mime_type, # This seems redundant if using MediaIoBaseUpload
            fields='id, name, webViewLink' # Request useful fields back
        )
        upload_response = await asyncio.to_thread(create_request.execute)

        # Wrap the upload response dict in TextContent after JSON serialization
        return [TextContent(type="text", text=json.dumps(upload_response))]

    except gauth.AuthenticationError as auth_error:
        logger.warning(f"Authentication error in upload_drive_file for user {user_id}, file '{file_name}': {auth_error}")
        raise auth_error # Propagate
    except ValueError as ve: # Catch the ValueError from decoding
        raise ve # Re-raise it
    except HttpError as e:
        # Check for 404 if folder_id was specified and not found
        if e.resp.status == 404 and folder_id:
            logger.warning(f"Target folder {folder_id} not found for upload by user {user_id}: {e}")
            # Raise FileNotFoundError for the folder
            raise FileNotFoundError(f"Target folder with ID '{folder_id}' not found.")
        # Handle 403 for permission issues
        elif e.resp.status == 403:
            logger.warning(f"Permission denied uploading file '{file_name}' for user {user_id} (folder: {folder_id}): {e}")
            # Raise PermissionError
            raise PermissionError(f"Permission denied to upload file '{file_name}' (check folder permissions).")
        else:
            logger.error(f"Google API HTTP error in upload_drive_file for user {user_id}, file '{file_name}': {e}", exc_info=True)
            # Raise standard RuntimeError
            raise RuntimeError(f"Google API Error uploading file: {e.resp.status} {e.reason}. Details: {e.content.decode()}")
    except Exception as e:
        logger.error(f"Unexpected error in upload_drive_file for user {user_id}, file '{file_name}': {e}", exc_info=True)
        # Raise standard RuntimeError
        raise RuntimeError(f"Failed to upload file '{file_name}'. Reason: {e}")
##-##

##-##

#-#