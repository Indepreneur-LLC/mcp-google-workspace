# ===== IMPORTS ===== #

## ===== STANDARD LIBRARY ===== ##
import logging
import io
##-##

## ===== THIRD PARTY ===== ##
from googleapiclient.discovery import build
from googleapiclient.errors import HttpError
from googleapiclient.http import MediaIoBaseDownload, MediaIoBaseUpload
from google.oauth2.credentials import Credentials
##-##

## ===== LOCAL ===== ##
# (No local imports currently)
##-##

#-#

# ===== GLOBALS ===== #

## ===== LOGGING ===== ##
logger = logging.getLogger(__name__)
##-##

#-#

# ===== CLASSES ===== #

## ===== EXCEPTIONS ===== ##
# Define custom exceptions
class DriveFileNotFoundError(Exception):
    pass

class DriveFolderNotFoundError(Exception):
    pass
##-##

#-#

# ===== FUNCTIONS ===== #

## ===== SERVICE INITIALIZATION ===== ##
def get_drive_service(credentials: Credentials): # Updated type hint
    """Builds and returns an authorized Drive API service object."""
    try:
        service = build('drive', 'v3', credentials=credentials)
        return service
    except HttpError as error:
        logger.error(f"An error occurred building the Drive service: {error}")
        raise
    except Exception as e:
        logger.error(f"An unexpected error occurred building the Drive service: {e}")
        raise
##-##

## ===== CORE API FUNCTIONS ===== ##
def list_files(
    service,
    page_size: int = 100,
    query: str | None = None,
    fields: str = "nextPageToken, files(id, name, mimeType, size, modifiedTime, parents)"
) -> list: # Raises HttpError
    """Lists files in Google Drive."""
    # Removed outer try/except - let HttpError propagate
    # This call can raise HttpError
    results = service.files().list(
        pageSize=page_size,
        q=query,
        fields=fields
    ).execute()
    # Return the list of files directly
    return results.get('files', [])

def get_file_metadata(
    service,
    file_id: str,
    fields: str = "*"
) -> dict: # Raises HttpError, DriveFileNotFoundError
    """Gets metadata for a specific file."""
    try:
        file_metadata = service.files().get(fileId=file_id, fields=fields).execute()
        return file_metadata
    except HttpError as e:
        logger.error(f"HttpError getting metadata for file {file_id}: {e}")
        if e.resp.status == 404:
            raise DriveFileNotFoundError(f"File with ID '{file_id}' not found.") from e
        else:
            # Re-raise other HttpErrors
            raise
    except Exception as e:
        logger.error(f"An unexpected error occurred getting metadata for file {file_id}: {e}",
                     exc_info=True) # Add exc_info for better debugging
        raise

def download_file(
    service,
    file_id: str
) -> bytes: # Raises HttpError, DriveFileNotFoundError
    """Downloads a file's content."""
    try:
        request = service.files().get_media(fileId=file_id)
        fh = io.BytesIO()
        downloader = MediaIoBaseDownload(fh, request)
        done = False
        while done is False:
            status, done = downloader.next_chunk()
            logger.info(f"Download {int(status.progress() * 100)}%.")
        fh.seek(0)
        return fh.read()
    except HttpError as e:
        # Handle cases like file not found, permission denied, etc.
        logger.error(f"HttpError downloading file {file_id}: {e}")
        if e.resp.status == 404:
            raise DriveFileNotFoundError(f"File with ID '{file_id}' not found.") from e
        elif e.resp.status == 403:
            # Consider a specific PermissionError if needed
            raise PermissionError(f"Permission denied downloading file '{file_id}'.") from e
        else:
            # Re-raise other HttpErrors
            raise
    except Exception as e:
        logger.error(f"An unexpected error occurred downloading file {file_id}: {e}",
                     exc_info=True) # Add exc_info
        raise

def upload_file(
    service,
    file_name: str,
    mime_type: str,
    file_content: bytes,
    folder_id: str | None = None
) -> dict: # Raises HttpError, DriveFolderNotFoundError
    """Uploads a file."""
    try:
        file_metadata = {'name': file_name}
        if folder_id:
            file_metadata['parents'] = [folder_id]

        media = MediaIoBaseUpload(io.BytesIO(file_content), mimetype=mime_type, resumable=True)
        request = service.files().create(
            body=file_metadata,
            media_body=media,
            fields='id, name, webViewLink' # Fields to return upon success
        )
        response = None
        while response is None:
            status, response = request.next_chunk()
            if status:
                logger.info(f"Upload {int(status.progress() * 100)}%.")
        logger.info(f"File '{response.get('name')}' uploaded successfully with ID: {response.get('id')}")
        return response
    except HttpError as e:
        logger.error(f"HttpError uploading file '{file_name}': {e}")
        # Check for 404 if folder_id was specified
        if e.resp.status == 404 and folder_id:
            raise DriveFolderNotFoundError(f"Target folder with ID '{folder_id}' not found.") from e
        elif e.resp.status == 403:
            # Consider a specific PermissionError if needed
            raise PermissionError(f"Permission denied uploading file '{file_name}' to folder '{folder_id}'.") from e
        else:
            # Re-raise other HttpErrors
            raise
    except Exception as e:
        logger.error(f"An unexpected error occurred uploading file '{file_name}': {e}",
                     exc_info=True) # Add exc_info
        raise

##-##

#-#