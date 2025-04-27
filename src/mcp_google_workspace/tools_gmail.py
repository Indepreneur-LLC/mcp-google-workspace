# ===== IMPORTS ===== #

## ===== STANDARD LIBRARY ===== ##
from collections.abc import Sequence
import logging
import asyncio
import base64
import json
import os
##-##

## ===== THIRD PARTY ===== ##
from googleapiclient.errors import HttpError
from mcp.types import (
    EmbeddedResource,
    JSONRPCError,
    ImageContent,
    TextContent
)
##-##

## ===== LOCAL ===== ##
from . import gmail
from . import gauth
##-##

#-#

# ===== GLOBALS ===== #

## ===== LOGGING ===== ##
logger = logging.getLogger(__name__)
##-##

#-#

# ===== FUNCTIONS ===== #

## ===== HELPERS ===== ##
def decode_base64_data(file_data):
    standard_base64_data = file_data.replace("-", "+").replace("_", "/")
    missing_padding = len(standard_base64_data) % 4
    if missing_padding:
        standard_base64_data += '=' * (4 - missing_padding)
    return base64.b64decode(standard_base64_data, validate=True)
##-##

## ===== TOOL FUNCTIONS ===== ##

### ----- READ/QUERY TOOLS ----- ###
async def query_gmail_emails(
    oauth_state: str,
    user_id: str,
    query: str | None = None,
    max_results: int = 100
) -> Sequence[TextContent | ImageContent | EmbeddedResource]:
    """Queries Gmail emails."""
    try:
        if not user_id: raise JSONRPCError(code=-32000, message="Server user ID not configured.")
        credentials = await asyncio.to_thread(gauth.get_authenticated_credentials, user_id, oauth_state)
        gmail_service = gmail.GmailService(credentials=credentials)
        emails = await asyncio.to_thread(gmail_service.query_emails, query=query, max_results=max_results)
        # Wrap the list of email dicts in TextContent after JSON serialization
        return [TextContent(type="text", text=json.dumps(emails))]

    except (FileNotFoundError, gauth.AuthenticationError) as auth_error:
        logger.warning(f"Authentication required for query_gmail_emails (user: {user_id}): {auth_error}")
        # Generate auth URL and raise standard error with data field
        auth_url = await asyncio.to_thread(gauth.get_auth_url, user_id, oauth_state)
        raise JSONRPCError(
            code=-32001, # Custom server error code for auth required
            message="Google authentication required.",
            data={"authUrl": auth_url, "state": oauth_state, "reason": str(auth_error)}
        )
    except HttpError as e:
        logger.error(f"Google API HTTP error in query_gmail_emails for user "
                     f"{user_id}: {e}", exc_info=True)
        error_message = f"Google API Error: {e.resp.status} {e.reason}. Details: {e.content.decode()}"
        return {"content": [TextContent(type="text", text=error_message)], "isError": True}
    except Exception as e:
        logger.error(f"Unexpected error in query_gmail_emails for user "
                     f"{user_id}: {e}", exc_info=True)
        error_message = f"Failed to query emails for {user_id}. Reason: {e}"
        return {"content": [TextContent(type="text", text=error_message)], "isError": True}

async def get_gmail_email(
    user_id: str, # Added missing user_id parameter
    oauth_state: str,
    email_id: str
) -> Sequence[TextContent | ImageContent | EmbeddedResource]:
    """Retrieves a specific Gmail email by ID."""
    try:
        if not user_id: raise JSONRPCError(code=-32000, message="User ID not provided to tool.") # Updated error message
        credentials = await asyncio.to_thread(gauth.get_authenticated_credentials, user_id, oauth_state)
        gmail_service = gmail.GmailService(credentials=credentials)
        email, attachments = await asyncio.to_thread(gmail_service.get_email_by_id_with_attachments, email_id)

        if email is None:
            # Assuming service layer raises specific error if not found
            logger.error(f"get_email_by_id_with_attachments returned None for email "
                         f"{email_id}, user {user_id}")
            error_message = f"Email with ID {email_id} not found or could not be retrieved."
            return {"content": [TextContent(type="text", text=error_message)], "isError": True}

        email["attachments"] = attachments
        # Wrap the email dict in TextContent after JSON serialization
        return [TextContent(type="text", text=json.dumps(email))]

    except (FileNotFoundError, gauth.AuthenticationError) as auth_error:
        logger.warning(f"Authentication required for get_gmail_email "
                       f"(user: {user_id}, email: {email_id}): {auth_error}")
        # Generate auth URL and raise standard error with data field
        auth_url = await asyncio.to_thread(gauth.get_auth_url, user_id, oauth_state)
        raise JSONRPCError(
            code=-32001, # Custom server error code for auth required
            message="Google authentication required.",
            data={"authUrl": auth_url, "state": oauth_state, "reason": str(auth_error)}
        )
    except HttpError as e:
        logger.error(f"Google API HTTP error in get_gmail_email for user "
                     f"{user_id}, email {email_id}: {e}", exc_info=True)
        error_message = f"Google API Error: {e.resp.status} {e.reason}. Details: {e.content.decode()}"
        return {"content": [TextContent(type="text", text=error_message)], "isError": True}
    except Exception as e: # Catch potential specific errors from service layer if added
        logger.error(f"Unexpected error in get_gmail_email for user "
                     f"{user_id}, email {email_id}: {e}", exc_info=True)
        error_message = f"Failed to get email {email_id} for {user_id}. Reason: {e}"
        return {"content": [TextContent(type="text", text=error_message)], "isError": True}

async def bulk_get_gmail_emails(
    oauth_state: str,
    email_ids: list[str],
    user_id: str
) -> Sequence[TextContent | ImageContent | EmbeddedResource]: # Removed user_id param
    """Retrieves multiple Gmail emails by ID."""
    try:
        if not user_id: raise JSONRPCError(code=-32000, message="Server user ID not configured.")
        credentials = await asyncio.to_thread(gauth.get_authenticated_credentials, user_id, oauth_state)
        gmail_service = gmail.GmailService(credentials=credentials)

        tasks = []
        for email_id in email_ids:
            # Wrap individual calls in to_thread for potential parallelism (though GIL limits true parallelism)
            # Or consider a batch API if available and more efficient
            tasks.append(asyncio.to_thread(gmail_service.get_email_by_id_with_attachments, email_id))

        email_results = await asyncio.gather(*tasks, return_exceptions=True)

        processed_results = []
        for i, result in enumerate(email_results):
            email_id = email_ids[i]
            if isinstance(result, Exception):
                logger.error(f"Error retrieving email {email_id} in bulk operation for user "
                             f"{user_id}: {result}", exc_info=result)
                # Include error marker in results
                processed_results.append({"email_id": email_id, "error": str(result)})
            elif result and result[0] is not None: # result is (email, attachments) tuple
                email, attachments = result
                email["attachments"] = attachments
                processed_results.append(email)
            else:
                logger.warning(f"Failed to retrieve email {email_id} (returned None) in bulk "
                               f"operation for user {user_id}.")
                processed_results.append({"email_id": email_id, "error": "Email not found or retrieval failed."})


        if not processed_results:
            # This case might be less likely now errors are included
            error_message = "Failed to retrieve or process any emails from the provided IDs."
            return {"content": [TextContent(type="text", text=error_message)], "isError": True}

        # Wrap the list of results/errors in TextContent after JSON serialization
        return [TextContent(type="text", text=json.dumps(processed_results))]

    except (FileNotFoundError, gauth.AuthenticationError) as auth_error:
        logger.warning(f"Authentication required for bulk_get_gmail_emails (user: {user_id}): {auth_error}")
        # Generate auth URL and raise standard error with data field
        auth_url = await asyncio.to_thread(gauth.get_auth_url, user_id, oauth_state)
        raise JSONRPCError(
            code=-32001, # Custom server error code for auth required
            message="Google authentication required.",
            data={"authUrl": auth_url, "state": oauth_state, "reason": str(auth_error)}
        )
    except HttpError as e: # Catch HttpError if it occurs during batch processing (less likely here)
        logger.error(f"Google API HTTP error during bulk_get_gmail_emails for user "
                     f"{user_id}: {e}", exc_info=True)
        error_message = f"Google API Error: {e.resp.status} {e.reason}. Details: {e.content.decode()}"
        return {"content": [TextContent(type="text", text=error_message)], "isError": True}
    except Exception as e:
        logger.error(f"Unexpected error in bulk_get_gmail_emails for user "
                     f"{user_id}: {e}", exc_info=True)
        # Return partial results if available, otherwise raise generic error
        if 'processed_results' in locals() and processed_results:
            logger.warning(f"Returning partial results for bulk_get_gmail_emails "
                           f"due to error: {e}")
            # Optionally add a top-level error marker to the list
            processed_results.append({"error": f"Bulk operation failed partially. Reason: {e}"})
            # Wrap the list of results/errors in TextContent after JSON serialization
            return [TextContent(type="text", text=json.dumps(processed_results))]
        else:
            error_message = f"Failed bulk email retrieval for {user_id}. Reason: {e}"
            return {"content": [TextContent(type="text", text=error_message)], "isError": True}

async def get_gmail_attachment(
    oauth_state: str,
    message_id: str,
    attachment_id: str,
    mime_type: str,
    filename: str,
    user_id: str,
    save_to_disk: str | None = None
) -> Sequence[TextContent | ImageContent | EmbeddedResource]:
    """Retrieves a Gmail attachment."""
    try:
        if not user_id: raise JSONRPCError(code=-32000, message="Server user ID not configured.")
        credentials = await asyncio.to_thread(gauth.get_authenticated_credentials, user_id, oauth_state)
        gmail_service = gmail.GmailService(credentials=credentials)
        attachment_data = await asyncio.to_thread(gmail_service.get_attachment, message_id, attachment_id)

        if attachment_data is None:
            # Assuming service layer raises specific error
            logger.error(f"get_attachment returned None for msg {message_id}, "
                         f"att {attachment_id}, user {user_id}")
            error_message = f"Failed to retrieve attachment {attachment_id} from message {message_id}. It might not exist or an error occurred."
            return {"content": [TextContent(type="text", text=error_message)], "isError": True}

        file_data = attachment_data.get("data")
        if not file_data:
            logger.error(f"Attachment {attachment_id} from message {message_id} contained no data "
                         f"for user {user_id}")
            error_message = f"Attachment {attachment_id} from message {message_id} contained no data."
            return {"content": [TextContent(type="text", text=error_message)], "isError": True}

        attachment_url = f"attachment://gmail/{message_id}/{attachment_id}/{filename}"

        if save_to_disk:
            try:
                # Decoding and writing are potentially blocking
                decoded_data = await asyncio.to_thread(decode_base64_data, file_data)
                # Ensure directory exists (sync is ok here, usually fast)
                os.makedirs(os.path.dirname(save_to_disk), exist_ok=True)
                # Use async file I/O if available/necessary, otherwise thread
                async with asyncio.Lock(): # Basic lock if writing to shared locations, though unique paths assumed
                    await asyncio.to_thread(lambda: open(save_to_disk, "wb").write(decoded_data))

                # Wrap the status dict in TextContent after JSON serialization
                status_dict = {"status": "success", "message": f"Attachment saved to disk: {save_to_disk}", "path": save_to_disk}
                return [TextContent(type="text", text=json.dumps(status_dict))]
            except Exception as save_e:
                logger.error(f"Error saving attachment {filename} to {save_to_disk} "
                             f"for user {user_id}: {save_e}", exc_info=True)
                error_message = f"Failed to save attachment {filename} to {save_to_disk}. Reason: {save_e}"
                return {"content": [TextContent(type="text", text=error_message)], "isError": True}
        else:
            # Return as embedded resource (this part is already correct)
            return EmbeddedResource(
                type="resource",
                resource={
                    "blob": file_data, # Send base64 data directly
                    "uri": attachment_url,
                    "mimeType": mime_type,
                },
            )

    except (FileNotFoundError, gauth.AuthenticationError) as auth_error:
        logger.warning(f"Authentication required for get_gmail_attachment "
                       f"(user: {user_id}, msg: {message_id}, att: {attachment_id}): {auth_error}")
        # Generate auth URL and raise standard error with data field
        auth_url = await asyncio.to_thread(gauth.get_auth_url, user_id, oauth_state)
        raise JSONRPCError(
            code=-32001, # Custom server error code for auth required
            message="Google authentication required.",
            data={"authUrl": auth_url, "state": oauth_state, "reason": str(auth_error)}
        )
    except HttpError as e:
         # Check for 404 specifically
        if e.resp.status == 404:
            logger.warning(f"Attachment {attachment_id} or message {message_id} not found "
                           f"for user {user_id}: {e}")
            error_message = f"Attachment {attachment_id} or message {message_id} not found."
            return {"content": [TextContent(type="text", text=error_message)], "isError": True}
        else:
            logger.error(f"Google API HTTP error in get_gmail_attachment for user "
                         f"{user_id}, msg {message_id}, att {attachment_id}: {e}", exc_info=True)
            error_message = f"Google API Error: {e.resp.status} {e.reason}. Details: {e.content.decode()}"
            return {"content": [TextContent(type="text", text=error_message)], "isError": True}
    except base64.binascii.Error as b64_error: # Catch potential decoding errors
        logger.error(f"Base64 decoding error for attachment {attachment_id}, msg {message_id}, "
                     f"user {user_id}: {b64_error}", exc_info=True)
        error_message = f"Failed to decode attachment data. Reason: {b64_error}"
        return {"content": [TextContent(type="text", text=error_message)], "isError": True}
    except Exception as e:
        logger.error(f"Unexpected error in get_gmail_attachment for user "
                     f"{user_id}, msg {message_id}, att {attachment_id}: {e}", exc_info=True)
        error_message = f"Failed to get attachment {attachment_id} for {user_id}. Reason: {e}"
        return {"content": [TextContent(type="text", text=error_message)], "isError": True}
##-##

### ----- WRITE/MODIFY TOOLS ----- ###
async def create_gmail_draft(
    oauth_state: str,
    to: str,
    subject: str,
    body: str,
    user_id: str,
    cc: list[str] | None = None
) -> Sequence[TextContent | ImageContent | EmbeddedResource]:
    """Creates a new Gmail draft."""
    try:
        if not user_id: raise JSONRPCError(code=-32000, message="Server user ID not configured.")
        credentials = await asyncio.to_thread(gauth.get_authenticated_credentials, user_id, oauth_state)
        gmail_service = gmail.GmailService(credentials=credentials)
        draft = await asyncio.to_thread(
            gmail_service.create_draft,
            to=to,
            subject=subject,
            body=body,
            cc=cc
        )

        if draft is None:
            # Assuming service layer raises specific error
            logger.error(f"create_draft returned None for user {user_id}")
            error_message = "Failed to create draft email."
            return {"content": [TextContent(type="text", text=error_message)], "isError": True}

        # Wrap the draft dict in TextContent after JSON serialization
        return [TextContent(type="text", text=json.dumps(draft))]

    except (FileNotFoundError, gauth.AuthenticationError) as auth_error:
        logger.warning(f"Authentication required for create_gmail_draft (user: {user_id}): {auth_error}")
        # Generate auth URL and raise standard error with data field
        auth_url = await asyncio.to_thread(gauth.get_auth_url, user_id, oauth_state)
        raise JSONRPCError(
            code=-32001, # Custom server error code for auth required
            message="Google authentication required.",
            data={"authUrl": auth_url, "state": oauth_state, "reason": str(auth_error)}
        )
    except HttpError as e:
        logger.error(f"Google API HTTP error in create_gmail_draft for user "
                     f"{user_id}: {e}", exc_info=True)
        error_message = f"Google API Error: {e.resp.status} {e.reason}. Details: {e.content.decode()}"
        return {"content": [TextContent(type="text", text=error_message)], "isError": True}
    except Exception as e:
        logger.error(f"Unexpected error in create_gmail_draft for user "
                     f"{user_id}: {e}", exc_info=True)
        error_message = f"Failed to create draft for {user_id}. Reason: {e}"
        return {"content": [TextContent(type="text", text=error_message)], "isError": True}

async def delete_gmail_draft(
    oauth_state: str,
    draft_id: str,
    user_id: str
) -> Sequence[TextContent | ImageContent | EmbeddedResource]: # Removed user_id param
    """Deletes a Gmail draft by ID."""
    try:
        if not user_id: raise JSONRPCError(code=-32000, message="Server user ID not configured.")
        credentials = await asyncio.to_thread(gauth.get_authenticated_credentials, user_id, oauth_state)
        gmail_service = gmail.GmailService(credentials=credentials)
        success = await asyncio.to_thread(gmail_service.delete_draft, draft_id)

        if success:
             # Return a simple success message or confirmation object
             status_dict = {"status": "success", "message": f"Successfully deleted draft {draft_id}"}
             return [TextContent(type="text", text=json.dumps(status_dict))]
        else:
             # Assuming service layer raises specific error if deletion fails
            logger.error(f"delete_draft returned False for draft {draft_id}, user {user_id}")
            error_message = f"Failed to delete draft with ID: {draft_id}. It might not exist or an error occurred."
            return {"content": [TextContent(type="text", text=error_message)], "isError": True}

    except (FileNotFoundError, gauth.AuthenticationError) as auth_error:
        logger.warning(f"Authentication required for delete_gmail_draft "
                       f"(user: {user_id}, draft: {draft_id}): {auth_error}")
        # Generate auth URL and raise standard error with data field
        auth_url = await asyncio.to_thread(gauth.get_auth_url, user_id, oauth_state)
        raise JSONRPCError(
            code=-32001, # Custom server error code for auth required
            message="Google authentication required.",
            data={"authUrl": auth_url, "state": oauth_state, "reason": str(auth_error)}
        )
    except HttpError as e:
        # Check for 404 specifically, could indicate draft not found
        if e.resp.status == 404:
            logger.warning(f"Draft {draft_id} not found for deletion by user "
                           f"{user_id}: {e}")
            error_message = f"Draft with ID {draft_id} not found."
            return {"content": [TextContent(type="text", text=error_message)], "isError": True}
        else:
            logger.error(f"Google API HTTP error in delete_gmail_draft for user "
                         f"{user_id}, draft {draft_id}: {e}", exc_info=True)
            error_message = f"Google API Error: {e.resp.status} {e.reason}. Details: {e.content.decode()}"
            return {"content": [TextContent(type="text", text=error_message)], "isError": True}
    except Exception as e:
        logger.error(f"Unexpected error in delete_gmail_draft for user "
                     f"{user_id}, draft {draft_id}: {e}", exc_info=True)
        error_message = f"Failed to delete draft {draft_id} for {user_id}. Reason: {e}"
        return {"content": [TextContent(type="text", text=error_message)], "isError": True}

async def reply_gmail_email(
    oauth_state: str,
    original_message_id: str,
    reply_body: str,
    user_id: str,
    send: bool = False,
    cc: list[str] | None = None
) -> Sequence[TextContent | ImageContent | EmbeddedResource]: # Removed user_id param
    """Creates and optionally sends a reply to a Gmail message."""
    try:
        if not user_id: raise JSONRPCError(code=-32000, message="Server user ID not configured.")
        credentials = await asyncio.to_thread(gauth.get_authenticated_credentials, user_id, oauth_state)
        gmail_service = gmail.GmailService(credentials=credentials)

        # Get original message (potentially blocking)
        original_message = await asyncio.to_thread(gmail_service.get_email_by_id, original_message_id)
        if original_message is None:
            # Assuming service layer raises specific error if not found
            logger.error(f"get_email_by_id returned None for original message "
                         f"{original_message_id}, user {user_id}")
            error_message = f"Original message with ID {original_message_id} not found or could not be retrieved."
            return {"content": [TextContent(type="text", text=error_message)], "isError": True}

        # Create reply (potentially blocking)
        result = await asyncio.to_thread(
            gmail_service.create_reply,
            original_message=original_message,
            reply_body=reply_body,
            send=send,
            cc=cc
        )

        if result is None:
            # Assuming service layer raises specific error
            logger.error(f"create_reply returned None for user {user_id}, "
                         f"original msg {original_message_id}")
            error_message = f"Failed to {'send' if send else 'draft'} reply email."
            return {"content": [TextContent(type="text", text=error_message)], "isError": True}

        # Wrap the result dict in TextContent after JSON serialization
        return [TextContent(type="text", text=json.dumps(result))]

    except (FileNotFoundError, gauth.AuthenticationError) as auth_error:
        logger.warning(f"Authentication required for reply_gmail_email "
                       f"(user: {user_id}, msg: {original_message_id}): {auth_error}")
        # Generate auth URL and raise standard error with data field
        auth_url = await asyncio.to_thread(gauth.get_auth_url, user_id, oauth_state)
        raise JSONRPCError(
            code=-32001, # Custom server error code for auth required
            message="Google authentication required.",
            data={"authUrl": auth_url, "state": oauth_state, "reason": str(auth_error)}
        )
    except HttpError as e:
        # Check for 404 on original message fetch?
        if e.resp.status == 404 and "original_message" not in locals(): # Check if error happened during original message fetch
            logger.warning(f"Original message {original_message_id} not found for reply by user "
                           f"{user_id}: {e}")
            error_message = f"Original message with ID {original_message_id} not found."
            return {"content": [TextContent(type="text", text=error_message)], "isError": True}
        else:
            logger.error(f"Google API HTTP error in reply_gmail_email for user "
                         f"{user_id}, msg {original_message_id}: {e}", exc_info=True)
            error_message = f"Google API Error: {e.resp.status} {e.reason}. Details: {e.content.decode()}"
            return {"content": [TextContent(type="text", text=error_message)], "isError": True}
    except Exception as e:
        logger.error(f"Unexpected error in reply_gmail_email for user "
                     f"{user_id}, msg {original_message_id}: {e}", exc_info=True)
        error_message = f"Failed to reply to email {original_message_id} for {user_id}. Reason: {e}"
        return {"content": [TextContent(type="text", text=error_message)], "isError": True}

async def bulk_save_gmail_attachments(oauth_state: str, attachments: list[dict], user_id: str) -> Sequence[TextContent | ImageContent | EmbeddedResource]:
    """Saves multiple Gmail attachments to disk."""
    results = []
    credentials = None

    async def save_single_attachment(gmail_service, attachment_info):
        message_id = attachment_info.get("message_id")
        attachment_id = attachment_info.get("attachment_id")
        save_path = attachment_info.get("save_path")

        if not all([message_id, attachment_id, save_path]):
            return {"status": "error", "message": f"Skipping attachment due to missing info: {attachment_info}", "input": attachment_info}

        try:
            attachment_data = await asyncio.to_thread(gmail_service.get_attachment, message_id, attachment_id)
            if attachment_data is None:
                raise ValueError(f"Attachment {attachment_id} from message {message_id} not found or retrieval failed.")

            file_data = attachment_data.get("data")
            if not file_data:
                raise ValueError(f"Attachment {attachment_id} from message {message_id} contained no data.")

            decoded_data = await asyncio.to_thread(decode_base64_data, file_data)
            os.makedirs(os.path.dirname(save_path), exist_ok=True)
            async with asyncio.Lock(): # Basic lock
                 await asyncio.to_thread(lambda: open(save_path, "wb").write(decoded_data))
            return {"status": "success", "message": f"Attachment saved to: {save_path}", "path": save_path}

        except HttpError as e:
            logger.error(f"Google API HTTP error saving attachment {attachment_id} "
                         f"(msg: {message_id}) to {save_path}: {e}", exc_info=True)
            return {"status": "error", "message": f"Google API Error saving {attachment_id}: "
                                                  f"{e.resp.status} {e.reason}", "path": save_path, "input": attachment_info}
        except base64.binascii.Error as b64_error:
            logger.error(f"Base64 decoding error saving attachment {attachment_id} "
                         f"(msg: {message_id}) to {save_path}: {b64_error}", exc_info=True)
            return {"status": "error", "message": f"Decoding error for {attachment_id}: "
                                                  f"{b64_error}", "path": save_path, "input": attachment_info}
        except Exception as inner_e:
            logger.error(f"Error processing attachment {attachment_id} (msg: {message_id}) "
                         f"to {save_path} in bulk save: {inner_e}", exc_info=True)
            return {"status": "error", "message": f"Failed to save attachment {attachment_id} "
                                                  f"to {save_path}. Reason: {inner_e}", "path": save_path, "input": attachment_info}


    try:
        if not user_id: raise JSONRPCError(code=-32000, message="Server user ID not configured.")
        credentials = await asyncio.to_thread(gauth.get_authenticated_credentials, user_id, oauth_state)
        gmail_service = gmail.GmailService(credentials=credentials)

        # Create tasks for each attachment save
        tasks = [save_single_attachment(gmail_service, att_info) for att_info in attachments]
        results = await asyncio.gather(*tasks) # Exceptions are returned in results

        # Wrap the list of status dicts in TextContent after JSON serialization
        return [TextContent(type="text", text=json.dumps(results))]


    except (FileNotFoundError, gauth.AuthenticationError) as auth_error:
        logger.warning(f"Authentication required for bulk_save_gmail_attachments "
                       f"(user: {user_id}): {auth_error}")
        # Generate auth URL and raise standard error with data field
        auth_url = await asyncio.to_thread(gauth.get_auth_url, user_id, oauth_state)
        raise JSONRPCError(
            code=-32001, # Custom server error code for auth required
            message="Google authentication required.",
            data={"authUrl": auth_url, "state": oauth_state, "reason": str(auth_error)}
        )
    # HttpError and other exceptions are handled within save_single_attachment now
    except Exception as e:
        # Catch errors during initial auth or task setup
        logger.error(f"Unexpected error setting up bulk_save_gmail_attachments for user "
                     f"{user_id}: {e}", exc_info=True)
        error_message = f"Failed bulk attachment save setup for {user_id}. Reason: {e}"
        # Since this is a bulk operation, returning partial results might be better,
        # but for now, let's return a top-level error consistent with the pattern.
        return {"content": [TextContent(type="text", text=error_message)], "isError": True}
##-##

##-##

#-#