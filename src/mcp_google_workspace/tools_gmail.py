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
    ImageContent,
    TextContent
)
##-##

## ===== LOCAL ===== ##
# from . import gmail # Removed, service obtained via gauth
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
    # oauth_state: str, # Removed
    user_id: str,
    query: str | None = None,
    max_results: int = 100
) -> Sequence[TextContent | ImageContent | EmbeddedResource]:
    """Queries Gmail emails."""
    try:
        if not user_id: raise ValueError("User ID not provided.")
        # credentials = await asyncio.to_thread(gauth.get_authenticated_credentials, user_id, oauth_state) # Removed
        # gmail_service = gmail.GmailService(credentials=credentials) # Removed
        gmail_service = await asyncio.to_thread(gauth.get_google_service, 'gmail', 'v1', user_id)
        if gmail_service is None:
            raise gauth.AuthenticationError(f"Failed to get Gmail service for user {user_id}. User might not be authenticated or authorized.")

        emails = await asyncio.to_thread(gmail_service.users().messages().list(userId='me', q=query, maxResults=max_results).execute) # Direct API call
        # Wrap the list of email dicts in TextContent after JSON serialization
        return [TextContent(type="text", text=json.dumps(emails.get('messages', [])))] # Return only messages list

    except gauth.AuthenticationError as auth_error: # Catch specific auth error
        logger.warning(f"Authentication required for query_gmail_emails (user: {user_id}): {auth_error}")
        # Re-raise the standard authentication error; decorator handles JSONRPC formatting
        raise auth_error
    except HttpError as e:
        logger.error(f"Google API HTTP error in query_gmail_emails for user "
                     f"{user_id}: {e}", exc_info=True)
        error_message = f"Google API Error: {e.resp.status} {e.reason}. Details: {e.content.decode()}"
        # Raise standard runtime error; decorator handles JSONRPC formatting
        raise RuntimeError(error_message)
    except Exception as e:
        logger.error(f"Unexpected error in query_gmail_emails for user "
                     f"{user_id}: {e}", exc_info=True)
        error_message = f"Failed to query emails for {user_id}. Reason: {e}"
        # Raise standard runtime error; decorator handles JSONRPC formatting
        raise RuntimeError(error_message)

async def get_gmail_email(
    user_id: str,
    # oauth_state: str, # Removed
    email_id: str
) -> Sequence[TextContent | ImageContent | EmbeddedResource]:
    """Retrieves a specific Gmail email by ID, including attachments."""
    try:
        if not user_id: raise ValueError("User ID not provided.")
        # credentials = await asyncio.to_thread(gauth.get_authenticated_credentials, user_id, oauth_state) # Removed
        # gmail_service = gmail.GmailService(credentials=credentials) # Removed
        gmail_service = await asyncio.to_thread(gauth.get_google_service, 'gmail', 'v1', user_id)
        if gmail_service is None:
            raise gauth.AuthenticationError(f"Failed to get Gmail service for user {user_id}. User might not be authenticated or authorized.")

        # Fetch email with full format, including headers and payload for attachments
        email_data = await asyncio.to_thread(
            gmail_service.users().messages().get(userId='me', id=email_id, format='full').execute
        )

        # Extract attachments (simplified example, real parsing might be more complex)
        attachments = []
        if 'payload' in email_data and 'parts' in email_data['payload']:
            for part in email_data['payload']['parts']:
                if part.get('filename') and part.get('body') and part['body'].get('attachmentId'):
                    attachments.append({
                        "filename": part['filename'],
                        "mimeType": part['mimeType'],
                        "attachmentId": part['body']['attachmentId'],
                        "size": part['body'].get('size')
                    })

        email_data["attachments"] = attachments # Add extracted attachment info
        # Wrap the email dict in TextContent after JSON serialization
        return [TextContent(type="text", text=json.dumps(email_data))]

    except gauth.AuthenticationError as auth_error:
        logger.warning(f"Authentication required for get_gmail_email "
                       f"(user: {user_id}, email: {email_id}): {auth_error}")
        raise auth_error # Re-raise standard error
    except HttpError as e:
        logger.error(f"Google API HTTP error in get_gmail_email for user "
                     f"{user_id}, email {email_id}: {e}", exc_info=True)
        if e.resp.status == 404:
             raise RuntimeError(f"Email with ID {email_id} not found.")
        else:
            error_message = f"Google API Error: {e.resp.status} {e.reason}. Details: {e.content.decode()}"
            raise RuntimeError(error_message) # Raise standard error
    except Exception as e:
        logger.error(f"Unexpected error in get_gmail_email for user "
                     f"{user_id}, email {email_id}: {e}", exc_info=True)
        error_message = f"Failed to get email {email_id} for {user_id}. Reason: {e}"
        raise RuntimeError(error_message) # Raise standard error

async def bulk_get_gmail_emails(
    # oauth_state: str, # Removed
    email_ids: list[str],
    user_id: str
) -> Sequence[TextContent | ImageContent | EmbeddedResource]:
    """Retrieves multiple Gmail emails by ID."""
    try:
        if not user_id: raise ValueError("User ID not provided.")
        # credentials = await asyncio.to_thread(gauth.get_authenticated_credentials, user_id, oauth_state) # Removed
        # gmail_service = gmail.GmailService(credentials=credentials) # Removed
        gmail_service = await asyncio.to_thread(gauth.get_google_service, 'gmail', 'v1', user_id)
        if gmail_service is None:
            raise gauth.AuthenticationError(f"Failed to get Gmail service for user {user_id}. User might not be authenticated or authorized.")

        async def _get_single_email(email_id: str):
            """Helper to get a single email, handling errors."""
            try:
                # Fetch email with full format
                email_data = await asyncio.to_thread(
                    gmail_service.users().messages().get(userId='me', id=email_id, format='full').execute
                )
                # Extract attachments (simplified)
                attachments = []
                if 'payload' in email_data and 'parts' in email_data['payload']:
                    for part in email_data['payload']['parts']:
                        if part.get('filename') and part.get('body') and part['body'].get('attachmentId'):
                            attachments.append({
                                "filename": part['filename'],
                                "mimeType": part['mimeType'],
                                "attachmentId": part['body']['attachmentId'],
                                "size": part['body'].get('size')
                            })
                email_data["attachments"] = attachments
                return email_data
            except HttpError as e:
                 logger.error(f"Error retrieving email {email_id} in bulk for user {user_id}: {e}", exc_info=True)
                 return {"email_id": email_id, "error": f"Google API Error: {e.resp.status} {e.reason}"}
            except Exception as e:
                logger.error(f"Error retrieving email {email_id} in bulk for user {user_id}: {e}", exc_info=True)
                return {"email_id": email_id, "error": str(e)}

        tasks = [_get_single_email(email_id) for email_id in email_ids]
        email_results = await asyncio.gather(*tasks) # Exceptions handled within _get_single_email

        # Wrap the list of results/errors in TextContent after JSON serialization
        return [TextContent(type="text", text=json.dumps(email_results))]

    except gauth.AuthenticationError as auth_error:
        logger.warning(f"Authentication required for bulk_get_gmail_emails (user: {user_id}): {auth_error}")
        raise auth_error # Re-raise standard error
    # HttpError during initial service get or other setup errors
    except HttpError as e:
        logger.error(f"Google API HTTP error during bulk_get_gmail_emails setup for user "
                     f"{user_id}: {e}", exc_info=True)
        error_message = f"Google API Error during setup: {e.resp.status} {e.reason}. Details: {e.content.decode()}"
        raise RuntimeError(error_message) # Raise standard error
    except Exception as e:
        logger.error(f"Unexpected error in bulk_get_gmail_emails setup for user "
                     f"{user_id}: {e}", exc_info=True)
        error_message = f"Failed bulk email retrieval setup for {user_id}. Reason: {e}"
        raise RuntimeError(error_message) # Raise standard error

async def get_gmail_attachment(
    # oauth_state: str, # Removed
    message_id: str,
    attachment_id: str,
    mime_type: str, # Keep for EmbeddedResource return type hint, though not strictly needed for API call
    filename: str,  # Keep for EmbeddedResource return type hint and save_to_disk logic
    user_id: str,
    save_to_disk: str | None = None
) -> Sequence[TextContent | ImageContent | EmbeddedResource]:
    """Retrieves a Gmail attachment."""
    try:
        if not user_id: raise ValueError("User ID not provided.")
        # credentials = await asyncio.to_thread(gauth.get_authenticated_credentials, user_id, oauth_state) # Removed
        # gmail_service = gmail.GmailService(credentials=credentials) # Removed
        gmail_service = await asyncio.to_thread(gauth.get_google_service, 'gmail', 'v1', user_id)
        if gmail_service is None:
            raise gauth.AuthenticationError(f"Failed to get Gmail service for user {user_id}. User might not be authenticated or authorized.")

        # Fetch attachment data directly using the API
        attachment_data = await asyncio.to_thread(
            gmail_service.users().messages().attachments().get(
                userId='me', messageId=message_id, id=attachment_id
            ).execute
        )

        file_data = attachment_data.get("data")
        if not file_data:
            logger.error(f"Attachment {attachment_id} from message {message_id} contained no data "
                         f"for user {user_id}")
            raise RuntimeError(f"Attachment {attachment_id} from message {message_id} contained no data.")

        attachment_url = f"attachment://gmail/{message_id}/{attachment_id}/{filename}"

        if save_to_disk:
            try:
                # Decoding and writing are potentially blocking
                decoded_data = await asyncio.to_thread(decode_base64_data, file_data)
                # Ensure directory exists (sync is ok here, usually fast)
                save_dir = os.path.dirname(save_to_disk)
                if save_dir: # Avoid error if saving to current dir
                    os.makedirs(save_dir, exist_ok=True)
                # Use async file I/O if available/necessary, otherwise thread
                async with asyncio.Lock(): # Basic lock if writing to shared locations, though unique paths assumed
                    await asyncio.to_thread(lambda: open(save_to_disk, "wb").write(decoded_data))

                # Wrap the status dict in TextContent after JSON serialization
                status_dict = {"status": "success", "message": f"Attachment saved to disk: {save_to_disk}", "path": save_to_disk}
                return [TextContent(type="text", text=json.dumps(status_dict))]
            except Exception as save_e:
                logger.error(f"Error saving attachment {filename} to {save_to_disk} "
                             f"for user {user_id}: {save_e}", exc_info=True)
                raise RuntimeError(f"Failed to save attachment {filename} to {save_to_disk}. Reason: {save_e}")
        else:
            # Return as embedded resource
            return EmbeddedResource(
                type="resource",
                resource={
                    "blob": file_data, # Send base64 data directly
                    "uri": attachment_url,
                    "mimeType": mime_type, # Use provided mime_type
                },
            )

    except gauth.AuthenticationError as auth_error:
        logger.warning(f"Authentication required for get_gmail_attachment "
                       f"(user: {user_id}, msg: {message_id}, att: {attachment_id}): {auth_error}")
        raise auth_error # Re-raise standard error
    except HttpError as e:
         # Check for 404 specifically
        if e.resp.status == 404:
            logger.warning(f"Attachment {attachment_id} or message {message_id} not found "
                           f"for user {user_id}: {e}")
            raise RuntimeError(f"Attachment {attachment_id} or message {message_id} not found.")
        else:
            logger.error(f"Google API HTTP error in get_gmail_attachment for user "
                         f"{user_id}, msg {message_id}, att {attachment_id}: {e}", exc_info=True)
            error_message = f"Google API Error: {e.resp.status} {e.reason}. Details: {e.content.decode()}"
            raise RuntimeError(error_message) # Raise standard error
    except base64.binascii.Error as b64_error: # Catch potential decoding errors
        logger.error(f"Base64 decoding error for attachment {attachment_id}, msg {message_id}, "
                     f"user {user_id}: {b64_error}", exc_info=True)
        error_message = f"Failed to decode attachment data. Reason: {b64_error}"
        raise RuntimeError(error_message) # Raise standard error
    except Exception as e:
        logger.error(f"Unexpected error in get_gmail_attachment for user "
                     f"{user_id}, msg {message_id}, att {attachment_id}: {e}", exc_info=True)
        error_message = f"Failed to get attachment {attachment_id} for {user_id}. Reason: {e}"
        raise RuntimeError(error_message) # Raise standard error
##-##

### ----- WRITE/MODIFY TOOLS ----- ###
async def create_gmail_draft(
    # oauth_state: str, # Removed
    to: str,
    subject: str,
    body: str,
    user_id: str,
    cc: list[str] | None = None
) -> Sequence[TextContent | ImageContent | EmbeddedResource]:
    """Creates a new Gmail draft."""
    try:
        if not user_id: raise ValueError("User ID not provided.")
        # credentials = await asyncio.to_thread(gauth.get_authenticated_credentials, user_id, oauth_state) # Removed
        # gmail_service = gmail.GmailService(credentials=credentials) # Removed
        gmail_service = await asyncio.to_thread(gauth.get_google_service, 'gmail', 'v1', user_id)
        if gmail_service is None:
            raise gauth.AuthenticationError(f"Failed to get Gmail service for user {user_id}. User might not be authenticated or authorized.")

        # Construct the email message
        message_lines = [
            f"To: {to}",
        ]
        if cc:
            message_lines.append(f"Cc: {','.join(cc)}")
        message_lines.extend([
            f"Subject: {subject}",
            "",
            body
        ])
        raw_message = "\r\n".join(message_lines)
        encoded_message = base64.urlsafe_b64encode(raw_message.encode('utf-8')).decode('utf-8')

        draft_body = {'message': {'raw': encoded_message}}
        draft = await asyncio.to_thread(
            gmail_service.users().drafts().create(userId='me', body=draft_body).execute
        )

        # Wrap the draft dict in TextContent after JSON serialization
        return [TextContent(type="text", text=json.dumps(draft))]

    except gauth.AuthenticationError as auth_error:
        logger.warning(f"Authentication required for create_gmail_draft (user: {user_id}): {auth_error}")
        raise auth_error # Re-raise standard error
    except HttpError as e:
        logger.error(f"Google API HTTP error in create_gmail_draft for user "
                     f"{user_id}: {e}", exc_info=True)
        error_message = f"Google API Error: {e.resp.status} {e.reason}. Details: {e.content.decode()}"
        raise RuntimeError(error_message) # Raise standard error
    except Exception as e:
        logger.error(f"Unexpected error in create_gmail_draft for user "
                     f"{user_id}: {e}", exc_info=True)
        error_message = f"Failed to create draft for {user_id}. Reason: {e}"
        raise RuntimeError(error_message) # Raise standard error

async def delete_gmail_draft(
    # oauth_state: str, # Removed
    draft_id: str,
    user_id: str
) -> Sequence[TextContent | ImageContent | EmbeddedResource]:
    """Deletes a Gmail draft by ID."""
    try:
        if not user_id: raise ValueError("User ID not provided.")
        # credentials = await asyncio.to_thread(gauth.get_authenticated_credentials, user_id, oauth_state) # Removed
        # gmail_service = gmail.GmailService(credentials=credentials) # Removed
        gmail_service = await asyncio.to_thread(gauth.get_google_service, 'gmail', 'v1', user_id)
        if gmail_service is None:
            raise gauth.AuthenticationError(f"Failed to get Gmail service for user {user_id}. User might not be authenticated or authorized.")

        # API returns an empty body on success, raises HttpError otherwise
        await asyncio.to_thread(
            gmail_service.users().drafts().delete(userId='me', id=draft_id).execute
        )

        # Return a simple success message or confirmation object
        status_dict = {"status": "success", "message": f"Successfully deleted draft {draft_id}"}
        return [TextContent(type="text", text=json.dumps(status_dict))]

    except gauth.AuthenticationError as auth_error:
        logger.warning(f"Authentication required for delete_gmail_draft "
                       f"(user: {user_id}, draft: {draft_id}): {auth_error}")
        raise auth_error # Re-raise standard error
    except HttpError as e:
        # Check for 404 specifically, could indicate draft not found
        if e.resp.status == 404:
            logger.warning(f"Draft {draft_id} not found for deletion by user "
                           f"{user_id}: {e}")
            raise RuntimeError(f"Draft with ID {draft_id} not found.")
        else:
            logger.error(f"Google API HTTP error in delete_gmail_draft for user "
                         f"{user_id}, draft {draft_id}: {e}", exc_info=True)
            error_message = f"Google API Error: {e.resp.status} {e.reason}. Details: {e.content.decode()}"
            raise RuntimeError(error_message) # Raise standard error
    except Exception as e:
        logger.error(f"Unexpected error in delete_gmail_draft for user "
                     f"{user_id}, draft {draft_id}: {e}", exc_info=True)
        error_message = f"Failed to delete draft {draft_id} for {user_id}. Reason: {e}"
        raise RuntimeError(error_message) # Raise standard error

async def reply_gmail_email(
    # oauth_state: str, # Removed
    original_message_id: str,
    reply_body: str,
    user_id: str,
    send: bool = False,
    cc: list[str] | None = None
) -> Sequence[TextContent | ImageContent | EmbeddedResource]:
    """Creates and optionally sends a reply to a Gmail message."""
    try:
        if not user_id: raise ValueError("User ID not provided.")
        # credentials = await asyncio.to_thread(gauth.get_authenticated_credentials, user_id, oauth_state) # Removed
        # gmail_service = gmail.GmailService(credentials=credentials) # Removed
        gmail_service = await asyncio.to_thread(gauth.get_google_service, 'gmail', 'v1', user_id)
        if gmail_service is None:
            raise gauth.AuthenticationError(f"Failed to get Gmail service for user {user_id}. User might not be authenticated or authorized.")

        # Get original message to extract headers for reply
        original_message = await asyncio.to_thread(
            gmail_service.users().messages().get(userId='me', id=original_message_id, format='metadata', metadataHeaders=['Subject', 'From', 'To', 'Cc', 'Message-ID', 'References', 'In-Reply-To']).execute
        )

        # Construct reply headers
        headers = original_message.get('payload', {}).get('headers', [])
        subject = next((h['value'] for h in headers if h['name'].lower() == 'subject'), '')
        msg_id = next((h['value'] for h in headers if h['name'].lower() == 'message-id'), '')
        references = next((h['value'] for h in headers if h['name'].lower() == 'references'), '')
        in_reply_to = next((h['value'] for h in headers if h['name'].lower() == 'in-reply-to'), msg_id) # Use Message-ID if In-Reply-To missing
        original_to = next((h['value'] for h in headers if h['name'].lower() == 'to'), '')
        original_from = next((h['value'] for h in headers if h['name'].lower() == 'from'), '')
        original_cc = next((h['value'] for h in headers if h['name'].lower() == 'cc'), '')

        reply_subject = f"Re: {subject}" if not subject.lower().startswith("re:") else subject
        reply_to = original_from # Reply to the sender
        reply_cc_list = []
        if cc: # Add explicitly provided CCs
            reply_cc_list.extend(cc)
        # Optionally add original To/Cc recipients to the reply CC list (common practice)
        # if original_to: reply_cc_list.extend([addr.strip() for addr in original_to.split(',')])
        # if original_cc: reply_cc_list.extend([addr.strip() for addr in original_cc.split(',')])
        # reply_cc = ','.join(set(reply_cc_list)) # Remove duplicates

        # Construct the reply message
        message_lines = [
            f"To: {reply_to}",
        ]
        if reply_cc_list:
             message_lines.append(f"Cc: {','.join(set(reply_cc_list))}") # Use unique CC list
        message_lines.extend([
            f"Subject: {reply_subject}",
            f"In-Reply-To: {in_reply_to}",
            f"References: {references} {msg_id}".strip(), # Append original msg_id to references
            "",
            reply_body
        ])
        raw_message = "\r\n".join(message_lines)
        encoded_message = base64.urlsafe_b64encode(raw_message.encode('utf-8')).decode('utf-8')

        message_body = {'raw': encoded_message, 'threadId': original_message['threadId']}

        if send:
            # Send the message directly
            result = await asyncio.to_thread(
                gmail_service.users().messages().send(userId='me', body=message_body).execute
            )
            action = "sent"
        else:
            # Create a draft instead
            draft_body = {'message': message_body}
            result = await asyncio.to_thread(
                gmail_service.users().drafts().create(userId='me', body=draft_body).execute
            )
            action = "drafted"

        logger.info(f"Reply {action} successfully for user {user_id}, original msg {original_message_id}")
        # Wrap the result dict in TextContent after JSON serialization
        return [TextContent(type="text", text=json.dumps(result))]

    except gauth.AuthenticationError as auth_error:
        logger.warning(f"Authentication required for reply_gmail_email "
                       f"(user: {user_id}, msg: {original_message_id}): {auth_error}")
        raise auth_error # Re-raise standard error
    except HttpError as e:
        # Check for 404 on original message fetch
        if e.resp.status == 404 and "original_message" not in locals():
            logger.warning(f"Original message {original_message_id} not found for reply by user "
                           f"{user_id}: {e}")
            raise RuntimeError(f"Original message with ID {original_message_id} not found.")
        else:
            # Error during reply creation/sending
            logger.error(f"Google API HTTP error in reply_gmail_email for user "
                         f"{user_id}, msg {original_message_id}: {e}", exc_info=True)
            error_message = f"Google API Error: {e.resp.status} {e.reason}. Details: {e.content.decode()}"
            raise RuntimeError(error_message) # Raise standard error
    except Exception as e:
        logger.error(f"Unexpected error in reply_gmail_email for user "
                     f"{user_id}, msg {original_message_id}: {e}", exc_info=True)
        error_message = f"Failed to reply to email {original_message_id} for {user_id}. Reason: {e}"
        raise RuntimeError(error_message) # Raise standard error

async def bulk_save_gmail_attachments(
    # oauth_state: str, # Removed
    attachments: list[dict], # List of dicts with {"message_id": ..., "attachment_id": ..., "save_path": ...}
    user_id: str
) -> Sequence[TextContent | ImageContent | EmbeddedResource]:
    """Saves multiple Gmail attachments to disk."""
    results = []
    # credentials = None # Removed

    async def save_single_attachment(gmail_service, attachment_info):
        message_id = attachment_info.get("message_id")
        attachment_id = attachment_info.get("attachment_id")
        save_path = attachment_info.get("save_path")
        filename = os.path.basename(save_path) # Extract filename for logging

        if not all([message_id, attachment_id, save_path]):
            logger.warning(f"Skipping attachment due to missing info: {attachment_info}")
            return {"status": "error", "message": "Missing message_id, attachment_id, or save_path", "input": attachment_info}

        try:
            # Fetch attachment data directly using the API
            attachment_data = await asyncio.to_thread(
                gmail_service.users().messages().attachments().get(
                    userId='me', messageId=message_id, id=attachment_id
                ).execute
            )

            file_data = attachment_data.get("data")
            if not file_data:
                 raise RuntimeError(f"Attachment {attachment_id} from message {message_id} contained no data.")

            decoded_data = await asyncio.to_thread(decode_base64_data, file_data)
            save_dir = os.path.dirname(save_path)
            if save_dir: # Avoid error if saving to current dir
                os.makedirs(save_dir, exist_ok=True)
            async with asyncio.Lock(): # Basic lock
                 await asyncio.to_thread(lambda: open(save_path, "wb").write(decoded_data))
            logger.info(f"Successfully saved attachment {filename} to {save_path} for user {user_id}")
            return {"status": "success", "message": f"Attachment saved to: {save_path}", "path": save_path}

        except HttpError as e:
            logger.error(f"Google API HTTP error saving attachment {filename} "
                         f"(msg: {message_id}, att: {attachment_id}) to {save_path}: {e}", exc_info=True)
            error_detail = f"Google API Error: {e.resp.status} {e.reason}"
            if e.resp.status == 404:
                error_detail = "Attachment or message not found."
            return {"status": "error", "message": error_detail, "path": save_path, "input": attachment_info}
        except base64.binascii.Error as b64_error:
            logger.error(f"Base64 decoding error saving attachment {filename} "
                         f"(msg: {message_id}, att: {attachment_id}) to {save_path}: {b64_error}", exc_info=True)
            return {"status": "error", "message": f"Decoding error: {b64_error}", "path": save_path, "input": attachment_info}
        except Exception as inner_e:
            logger.error(f"Error processing attachment {filename} (msg: {message_id}, att: {attachment_id}) "
                         f"to {save_path} in bulk save: {inner_e}", exc_info=True)
            return {"status": "error", "message": f"Failed to save attachment. Reason: {inner_e}", "path": save_path, "input": attachment_info}


    try:
        if not user_id: raise ValueError("User ID not provided.")
        # credentials = await asyncio.to_thread(gauth.get_authenticated_credentials, user_id, oauth_state) # Removed
        # gmail_service = gmail.GmailService(credentials=credentials) # Removed
        gmail_service = await asyncio.to_thread(gauth.get_google_service, 'gmail', 'v1', user_id)
        if gmail_service is None:
            raise gauth.AuthenticationError(f"Failed to get Gmail service for user {user_id}. User might not be authenticated or authorized.")

        # Create tasks for each attachment save
        tasks = [save_single_attachment(gmail_service, att_info) for att_info in attachments]
        results = await asyncio.gather(*tasks) # Exceptions handled within save_single_attachment

        # Wrap the list of status dicts in TextContent after JSON serialization
        return [TextContent(type="text", text=json.dumps(results))]


    except gauth.AuthenticationError as auth_error:
        logger.warning(f"Authentication required for bulk_save_gmail_attachments "
                       f"(user: {user_id}): {auth_error}")
        raise auth_error # Re-raise standard error
    # HttpError during initial service get or other setup errors
    except HttpError as e:
        logger.error(f"Google API HTTP error during bulk_save_gmail_attachments setup for user "
                     f"{user_id}: {e}", exc_info=True)
        error_message = f"Google API Error during setup: {e.resp.status} {e.reason}. Details: {e.content.decode()}"
        raise RuntimeError(error_message) # Raise standard error
    except Exception as e:
        # Catch errors during initial auth or task setup
        logger.error(f"Unexpected error setting up bulk_save_gmail_attachments for user "
                     f"{user_id}: {e}", exc_info=True)
        error_message = f"Failed bulk attachment save setup for {user_id}. Reason: {e}"
        raise RuntimeError(error_message) # Raise standard error
##-##

##-##

#-#