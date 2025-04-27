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
    JSONRPCError,
    TextContent,
)
from googleapiclient.errors import HttpError # Added import
##-##

## ===== LOCAL ===== ##
from . import gauth
from . import drive
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
    oauth_state: str,
    user_id: str,
    query: str | None = None,
    page_size: int = 100,
    fields: str = "nextPageToken, files(id, name, mimeType, size, modifiedTime, parents)"
) -> Sequence[TextContent | EmbeddedResource]: # Removed user_id param
    """Lists Google Drive files."""
    try:
        if not user_id: raise JSONRPCError(code=-32000, message="Server user ID not configured.")
        credentials = await asyncio.to_thread(gauth.get_authenticated_credentials, user_id, oauth_state)
        # Assuming get_drive_service is lightweight or already handles async internally if needed
        # If get_drive_service itself involves I/O, wrap it too. For now, assume it's fast.
        service = drive.get_drive_service(credentials)
        files = await asyncio.to_thread(drive.list_files, service, page_size=page_size, query=query, fields=fields)
        # Assuming list_files returns the file list object or raises error
        # Wrap the file list dict in TextContent after JSON serialization
        return [TextContent(type="text", text=json.dumps(files))]

    except (FileNotFoundError, gauth.AuthenticationError) as auth_error:
        logger.warning(f"Authentication required for list_drive_files (user: {user_id}): {auth_error}")
        # Generate auth URL and raise standard error with data field
        auth_url = await asyncio.to_thread(gauth.get_auth_url, user_id, oauth_state)
        raise JSONRPCError(
            code=-32001, # Custom server error code for auth required
            message="Google authentication required.",
            data={"authUrl": auth_url, "state": oauth_state, "reason": str(auth_error)}
        )
    except HttpError as e:
        logger.error(f"Google API HTTP error in list_drive_files for user "
                     f"{user_id}: {e}", exc_info=True)
        error_message = f"Google API Error: {e.resp.status} {e.reason}. Details: {e.content.decode()}"
        return {"content": [TextContent(type="text", text=error_message)], "isError": True}
    except Exception as e:
        logger.error(f"Unexpected error in list_drive_files for user "
                     f"{user_id}: {e}", exc_info=True)
        error_message = f"Failed to list Drive files for {user_id}. Reason: {e}"
        return {"content": [TextContent(type="text", text=error_message)], "isError": True}

async def get_drive_file_metadata(
    oauth_state: str,
    file_id: str,
    user_id: str,
    fields: str = ("id, name, mimeType, size, modifiedTime, createdTime, "
                   "owners, parents, webViewLink, iconLink")
) -> Sequence[TextContent | EmbeddedResource]: # Removed user_id param
    """Gets metadata for a Google Drive file."""
    try:
        if not user_id: raise JSONRPCError(code=-32000, message="Server user ID not configured.")
        credentials = await asyncio.to_thread(gauth.get_authenticated_credentials, user_id, oauth_state)
        service = drive.get_drive_service(credentials)
        metadata = await asyncio.to_thread(drive.get_file_metadata, service, file_id=file_id, fields=fields)
        # Assuming get_file_metadata returns the metadata object or raises error
        # Wrap the metadata dict in TextContent after JSON serialization
        return [TextContent(type="text", text=json.dumps(metadata))]

    except (FileNotFoundError, gauth.AuthenticationError) as auth_error:
        logger.warning(f"Authentication required for get_drive_file_metadata "
                       f"(user: {user_id}, file: {file_id}): {auth_error}")
        # Generate auth URL and raise standard error with data field
        auth_url = await asyncio.to_thread(gauth.get_auth_url, user_id, oauth_state)
        raise JSONRPCError(
            code=-32001, # Custom server error code for auth required
            message="Google authentication required.",
            data={"authUrl": auth_url, "state": oauth_state, "reason": str(auth_error)}
        )
    except HttpError as e:
        if e.resp.status == 404:
            logger.warning(f"File {file_id} not found for metadata request by user "
                           f"{user_id}: {e}")
            error_message = f"File with ID '{file_id}' not found."
            return {"content": [TextContent(type="text", text=error_message)], "isError": True}
        else:
            logger.error(f"Google API HTTP error in get_drive_file_metadata for user "
                         f"{user_id}, file {file_id}: {e}", exc_info=True)
            error_message = f"Google API Error: {e.resp.status} {e.reason}. Details: {e.content.decode()}"
            return {"content": [TextContent(type="text", text=error_message)], "isError": True}
    except Exception as e:
        logger.error(f"Unexpected error in get_drive_file_metadata for user "
                     f"{user_id}, file {file_id}: {e}", exc_info=True)
        error_message = f"Failed to get metadata for file {file_id} for user {user_id}. Reason: {e}"
        return {"content": [TextContent(type="text", text=error_message)], "isError": True}

async def download_drive_file(oauth_state: str, file_id: str, user_id: str) -> Sequence[TextContent | EmbeddedResource]:
    """Downloads a Google Drive file."""
    try:
        if not user_id: raise JSONRPCError(code=-32000, message="Server user ID not configured.")
        credentials = await asyncio.to_thread(gauth.get_authenticated_credentials, user_id, oauth_state)
        service = drive.get_drive_service(credentials) # Assume get_drive_service is fast

        # Download file content (blocking)
        file_content = await asyncio.to_thread(drive.download_file, service, file_id=file_id)

        if file_content is None:
            # Assuming download_file raises specific error if not found (e.g., HttpError 404)
            logger.error(f"download_file returned None for file {file_id}, user {user_id}")
            error_message = f"File with ID '{file_id}' not found or could not be downloaded."
            return {"content": [TextContent(type="text", text=error_message)], "isError": True}

        # Get metadata (potentially blocking)
        try:
            # Re-getting service might not be necessary if credentials object is updated in place by google-auth
            metadata = await asyncio.to_thread(drive.get_file_metadata, service, file_id=file_id, fields="name, mimeType")
            filename = metadata.get("name", file_id)
            mimetype = metadata.get("mimeType", "application/octet-stream")
        except HttpError as meta_http_error:
            # Handle 404 specifically for metadata call if it happens after successful download (unlikely)
            if meta_http_error.resp.status == 404:
                logger.warning(f"Metadata not found for downloaded file {file_id} "
                               f"(user: {user_id}): {meta_http_error}. Using defaults.")
                filename = file_id
                mimetype = "application/octet-stream"
            else:
                 # Re-raise other HttpErrors from metadata call
                 raise meta_http_error
        except Exception as meta_e:
            logger.warning(f"Could not get metadata for downloaded file {file_id} "
                           f"(user: {user_id}): {meta_e}. Using default filename/mimetype.")
            filename = file_id
            mimetype = "application/octet-stream"

        # Encode content (potentially blocking for large files)
        file_content_b64 = await asyncio.to_thread(lambda: base64.b64encode(file_content).decode('utf-8'))

        # Construct the EmbeddedResource (this part is correct)
        resource_dict = {
            "blob": file_content_b64,
            "uri": f"drive://{file_id}/{filename}", # Include filename in URI
            "mimeType": mimetype
        }
        # Return the EmbeddedResource directly, not in a list
        return EmbeddedResource(type="resource", resource=resource_dict, title=filename,
                                description=f"Downloaded content for Google Drive file ID: {file_id}")

    except (FileNotFoundError, gauth.AuthenticationError) as auth_error:
        logger.warning(f"Authentication required for download_drive_file "
                       f"(user: {user_id}, file: {file_id}): {auth_error}")
        # Generate auth URL and raise standard error with data field
        auth_url = await asyncio.to_thread(gauth.get_auth_url, user_id, oauth_state)
        raise JSONRPCError(
            code=-32001, # Custom server error code for auth required
            message="Google authentication required.",
            data={"authUrl": auth_url, "state": oauth_state, "reason": str(auth_error)}
        )
    except HttpError as e:
        if e.resp.status == 404:
            logger.warning(f"File {file_id} not found for download by user "
                           f"{user_id}: {e}")
            error_message = f"File with ID '{file_id}' not found."
            return {"content": [TextContent(type="text", text=error_message)], "isError": True}
        # Handle 403 for permission issues if needed
        elif e.resp.status == 403:
            logger.warning(f"Permission denied downloading file {file_id} for user "
                           f"{user_id}: {e}")
            error_message = f"Permission denied to download file '{file_id}'."
            return {"content": [TextContent(type="text", text=error_message)], "isError": True}
        else:
            logger.error(f"Google API HTTP error in download_drive_file for user "
                         f"{user_id}, file {file_id}: {e}", exc_info=True)
            error_message = f"Google API Error downloading file: {e.resp.status} {e.reason}. Details: {e.content.decode()}"
            return {"content": [TextContent(type="text", text=error_message)], "isError": True}
    except base64.binascii.Error as b64_error: # Catch potential encoding errors
        logger.error(f"Base64 encoding error for downloaded file {file_id}, "
                     f"user {user_id}: {b64_error}", exc_info=True)
        raise JSONRPCError(code=-32013, message=f"Failed to encode downloaded file data. "
                                                f"Reason: {b64_error}")
    except Exception as e:
        logger.error(f"Unexpected error in download_drive_file for user "
                     f"{user_id}, file {file_id}: {e}", exc_info=True)
        error_message = f"Failed to download file {file_id} for user {user_id}. Reason: {e}"
        return {"content": [TextContent(type="text", text=error_message)], "isError": True}
##-##

### ----- WRITE/MODIFY TOOLS ----- ###
async def upload_drive_file(
    oauth_state: str,
    file_name: str,
    mime_type: str,
    file_content_b64: str,
    user_id: str,
    folder_id: str | None = None
) -> Sequence[TextContent | EmbeddedResource]:
    """Uploads a file to Google Drive."""
    try:
        if not user_id: raise JSONRPCError(code=-32000, message="Server user ID not configured.")
        credentials = await asyncio.to_thread(gauth.get_authenticated_credentials, user_id, oauth_state)
        service = drive.get_drive_service(credentials)

        # Decode base64 content (potentially blocking for large content)
        try:
            file_content = await asyncio.to_thread(base64.b64decode, file_content_b64)
        except base64.binascii.Error as decode_error:
            logger.error(f"Failed to decode base64 content for upload '{file_name}' "
                         f"(user: {user_id}): {decode_error}")
            raise JSONRPCError(code=-32602, message=f"Invalid base64 encoding provided for "
                                                    f"file '{file_name}'.") from decode_error

        # Execute upload (blocking)
        upload_response = await asyncio.to_thread(
            drive.upload_file,
            service,
            file_name=file_name,
            mime_type=mime_type,
            file_content=file_content,
            folder_id=folder_id
        )

        if upload_response:
            # Wrap the upload response dict in TextContent after JSON serialization
            return [TextContent(type="text", text=json.dumps(upload_response))]
        else:
            # This case is less likely if upload_file raises exceptions on failure
            logger.error(f"drive.upload_file returned None for file '{file_name}', "
                         f"user {user_id}")
            error_message = f"Failed to upload file '{file_name}'. The operation did not return details."
            return {"content": [TextContent(type="text", text=error_message)], "isError": True}

    except (FileNotFoundError, gauth.AuthenticationError) as auth_error:
        logger.warning(f"Authentication required for upload_drive_file "
                       f"(user: {user_id}, file: {file_name}): {auth_error}")
        # Generate auth URL and raise standard error with data field
        auth_url = await asyncio.to_thread(gauth.get_auth_url, user_id, oauth_state)
        raise JSONRPCError(
            code=-32001, # Custom server error code for auth required
            message="Google authentication required.",
            data={"authUrl": auth_url, "state": oauth_state, "reason": str(auth_error)}
        )
    except HttpError as e:
        # Check for 404 if folder_id was specified and not found
        if e.resp.status == 404 and folder_id:
            logger.warning(f"Target folder {folder_id} not found for upload by user "
                           f"{user_id}: {e}")
            error_message = f"Target folder with ID '{folder_id}' not found."
            return {"content": [TextContent(type="text", text=error_message)], "isError": True}
        # Handle 403 for permission issues if needed
        elif e.resp.status == 403:
            logger.warning(f"Permission denied uploading file '{file_name}' for user "
                           f"{user_id} (folder: {folder_id}): {e}")
            error_message = f"Permission denied to upload file '{file_name}' (check folder permissions)."
            return {"content": [TextContent(type="text", text=error_message)], "isError": True}
        else:
            logger.error(f"Google API HTTP error in upload_drive_file for user "
                         f"{user_id}, file {file_name}: {e}", exc_info=True)
            error_message = f"Google API Error uploading file: {e.resp.status} {e.reason}. Details: {e.content.decode()}"
            return {"content": [TextContent(type="text", text=error_message)], "isError": True}
    # ValueError/JSONRPCError from decoding is already handled above
    except Exception as e:
        logger.error(f"Unexpected error in upload_drive_file for user "
                     f"{user_id}, file {file_name}: {e}", exc_info=True)
        error_message = f"Failed to upload file '{file_name}' for user {user_id}. Reason: {e}"
        return {"content": [TextContent(type="text", text=error_message)], "isError": True}
##-##

##-##

#-#