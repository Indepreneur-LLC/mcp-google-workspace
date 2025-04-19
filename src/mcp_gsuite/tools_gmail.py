# ===== IMPORTS ===== #

## ===== STANDARD LIBRARY ===== ##
from collections.abc import Sequence
import logging
import asyncio
import base64
import os
##-##

## ===== THIRD PARTY ===== ##
from googleapiclient.errors import HttpError
from mcp import (
    EmbeddedResource,
    ToolAnnotations,
    JSONRPCError,
    ImageContent,
    TextContent
)
##-##

## ===== LOCAL ===== ##
from .server import app, GLOBAL_USER_ID
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
@app.tool(
    name="query_gmail_emails",
    description="""Query Gmail emails based on an optional search query.
    Returns emails in reverse chronological order (newest first).
    Returns metadata such as subject and also a short summary of the content.
    """,
    inputSchema={
        "type": "object",
        "properties": {
            # user_id removed from schema - will be passed internally
            "oauth_state": {
                 "type": "string",
                 "description": "Internal state parameter for authentication flow tracking."
            },
            "query": {
                "type": "string",
                "description": (
                    "Gmail search query (optional). Examples:\n"
                    "    - a $string: Search email body, subject, and sender information for $string\n"
                    "    - 'is:unread' for unread emails\n"
                    "    - 'from:example@gmail.com' for emails from a specific sender\n"
                    "    - 'newer_than:2d' for emails from last 2 days\n"
                    "    - 'has:attachment' for emails with attachments\n"
                    "If not provided, returns recent emails without filtering."
                ),
            },
            "max_results": {
                "type": "integer",
                "description": "Maximum number of emails to retrieve (1-500)",
                "minimum": 1,
                "maximum": 500,
                "default": 100
            }
        },
        "required": ["oauth_state"] # Removed user_id
    },
    annotations=ToolAnnotations(
        version="1.0",
        author="Roo",
        tags=["gmail", "email", "search", "query"]
    )
)
async def query_gmail_emails(
    oauth_state: str,
    query: str | None = None,
    max_results: int = 100
) -> Sequence[TextContent | ImageContent | EmbeddedResource]:
    """Queries Gmail emails."""
    try:
        # Authenticate and Execute in thread using GLOBAL_USER_ID
        if not GLOBAL_USER_ID: raise JSONRPCError(code=-32000, message="Server user ID not configured.")
        credentials = await asyncio.to_thread(gauth.get_authenticated_credentials, GLOBAL_USER_ID, oauth_state)
        gmail_service = gmail.GmailService(credentials=credentials)
        emails = await asyncio.to_thread(gmail_service.query_emails, query=query, max_results=max_results)
        return emails # Return raw data

    except (FileNotFoundError, gauth.AuthenticationError) as auth_error:
        logger.warning(f"Authentication required for query_gmail_emails (user: {GLOBAL_USER_ID}): {auth_error}")
        # Generate auth URL and raise standard error with data field
        auth_url = await asyncio.to_thread(gauth.get_auth_url, GLOBAL_USER_ID, oauth_state)
        raise JSONRPCError(
            code=-32001, # Custom server error code for auth required
            message="Google authentication required.",
            data={"authUrl": auth_url, "state": oauth_state, "reason": str(auth_error)}
        )
    except HttpError as e:
        logger.error(f"Google API HTTP error in query_gmail_emails for user "
                     f"{GLOBAL_USER_ID}: {e}", exc_info=True)
        raise JSONRPCError(code=-32002, message=f"Google API Error: {e.resp.status} "
                                                f"{e.reason}. Details: {e.content.decode()}")
    except Exception as e:
        logger.error(f"Unexpected error in query_gmail_emails for user "
                     f"{GLOBAL_USER_ID}: {e}", exc_info=True)
        raise JSONRPCError(code=-32000, message=f"Failed to query emails for "
                                                f"{GLOBAL_USER_ID}. Reason: {e}")

@app.tool(
    name="get_gmail_email",
    description="Retrieves a complete Gmail email message by its ID, including the full message body and attachment IDs.",
    inputSchema={
        "type": "object",
        "properties": {
            # user_id removed from schema
            "oauth_state": {
                 "type": "string",
                 "description": "Internal state parameter for authentication flow tracking."
            },
            "email_id": {
                "type": "string",
                "description": "The ID of the Gmail message to retrieve"
            }
        },
        "required": ["oauth_state", "email_id"] # Removed user_id
    },
    annotations=ToolAnnotations(
        version="1.0",
        author="Roo",
        tags=["gmail", "email", "get", "read"]
    )
)
async def get_gmail_email(oauth_state: str, email_id: str) -> Sequence[TextContent | ImageContent | EmbeddedResource]:
    """Retrieves a specific Gmail email by ID."""
    try:
        # Authenticate and Execute in thread using GLOBAL_USER_ID
        if not GLOBAL_USER_ID: raise JSONRPCError(code=-32000, message="Server user ID not configured.")
        credentials = await asyncio.to_thread(gauth.get_authenticated_credentials, GLOBAL_USER_ID, oauth_state)
        gmail_service = gmail.GmailService(credentials=credentials)
        email, attachments = await asyncio.to_thread(gmail_service.get_email_by_id_with_attachments, email_id)

        if email is None:
            # Assuming service layer raises specific error if not found
            logger.error(f"get_email_by_id_with_attachments returned None for email "
                         f"{email_id}, user {GLOBAL_USER_ID}")
            raise JSONRPCError(code=-32003, message=f"Email with ID {email_id} not found or "
                                                    f"could not be retrieved.")

        email["attachments"] = attachments
        return email # Return raw data

    except (FileNotFoundError, gauth.AuthenticationError) as auth_error:
        logger.warning(f"Authentication required for get_gmail_email "
                       f"(user: {GLOBAL_USER_ID}, email: {email_id}): {auth_error}")
        # Generate auth URL and raise standard error with data field
        auth_url = await asyncio.to_thread(gauth.get_auth_url, GLOBAL_USER_ID, oauth_state)
        raise JSONRPCError(
            code=-32001, # Custom server error code for auth required
            message="Google authentication required.",
            data={"authUrl": auth_url, "state": oauth_state, "reason": str(auth_error)}
        )
    except HttpError as e:
        logger.error(f"Google API HTTP error in get_gmail_email for user "
                     f"{GLOBAL_USER_ID}, email {email_id}: {e}", exc_info=True)
        raise JSONRPCError(code=-32002, message=f"Google API Error: {e.resp.status} "
                                                f"{e.reason}. Details: {e.content.decode()}")
    except Exception as e: # Catch potential specific errors from service layer if added
        logger.error(f"Unexpected error in get_gmail_email for user "
                     f"{GLOBAL_USER_ID}, email {email_id}: {e}", exc_info=True)
        raise JSONRPCError(code=-32000, message=f"Failed to get email {email_id} for "
                                                f"{GLOBAL_USER_ID}. Reason: {e}")

@app.tool(
    name="bulk_get_gmail_emails",
    description="Retrieves multiple Gmail email messages by their IDs in a single request, including the full message bodies and attachment IDs.",
    inputSchema={
        "type": "object",
        "properties": {
            # user_id removed from schema
            "oauth_state": {
                 "type": "string",
                 "description": "Internal state parameter for authentication flow tracking."
            },
            "email_ids": {
                "type": "array",
                "items": {
                    "type": "string"
                },
                "description": "List of Gmail message IDs to retrieve"
            }
        },
        "required": ["oauth_state", "email_ids"] # Removed user_id
    },
    annotations=ToolAnnotations(
        version="1.0",
        author="Roo",
        tags=["gmail", "email", "get", "read", "bulk"]
    )
)
async def bulk_get_gmail_emails(
    oauth_state: str,
    email_ids: list[str]
) -> Sequence[TextContent | ImageContent | EmbeddedResource]: # Removed user_id param
    """Retrieves multiple Gmail emails by ID."""
    try:
        # Authenticate and Execute in thread using GLOBAL_USER_ID
        if not GLOBAL_USER_ID: raise JSONRPCError(code=-32000, message="Server user ID not configured.")
        credentials = await asyncio.to_thread(gauth.get_authenticated_credentials, GLOBAL_USER_ID, oauth_state)
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
                             f"{GLOBAL_USER_ID}: {result}", exc_info=result)
                # Include error marker in results
                processed_results.append({"email_id": email_id, "error": str(result)})
            elif result and result[0] is not None: # result is (email, attachments) tuple
                email, attachments = result
                email["attachments"] = attachments
                processed_results.append(email)
            else:
                logger.warning(f"Failed to retrieve email {email_id} (returned None) in bulk "
                               f"operation for user {GLOBAL_USER_ID}.")
                processed_results.append({"email_id": email_id, "error": "Email not found or retrieval failed."})


        if not processed_results:
            # This case might be less likely now errors are included
            raise JSONRPCError(code=-32004, message="Failed to retrieve or process any emails "
                                                    "from the provided IDs.")

        return processed_results # Return raw list of results/errors

    except (FileNotFoundError, gauth.AuthenticationError) as auth_error:
        logger.warning(f"Authentication required for bulk_get_gmail_emails (user: {GLOBAL_USER_ID}): {auth_error}")
        # Generate auth URL and raise standard error with data field
        auth_url = await asyncio.to_thread(gauth.get_auth_url, GLOBAL_USER_ID, oauth_state)
        raise JSONRPCError(
            code=-32001, # Custom server error code for auth required
            message="Google authentication required.",
            data={"authUrl": auth_url, "state": oauth_state, "reason": str(auth_error)}
        )
    except HttpError as e: # Catch HttpError if it occurs during batch processing (less likely here)
        logger.error(f"Google API HTTP error during bulk_get_gmail_emails for user "
                     f"{GLOBAL_USER_ID}: {e}", exc_info=True)
        raise JSONRPCError(code=-32002, message=f"Google API Error: {e.resp.status} "
                                                f"{e.reason}. Details: {e.content.decode()}")
    except Exception as e:
        logger.error(f"Unexpected error in bulk_get_gmail_emails for user "
                     f"{GLOBAL_USER_ID}: {e}", exc_info=True)
        # Return partial results if available, otherwise raise generic error
        if 'processed_results' in locals() and processed_results:
            logger.warning(f"Returning partial results for bulk_get_gmail_emails "
                           f"due to error: {e}")
            # Optionally add a top-level error marker to the list
            processed_results.append({"error": f"Bulk operation failed partially. Reason: {e}"})
            return processed_results
        else:
            raise JSONRPCError(code=-32000, message=f"Failed bulk email retrieval for "
                                                    f"{GLOBAL_USER_ID}. Reason: {e}")

@app.tool(
    name="get_gmail_attachment",
    description="Retrieves a Gmail attachment by its ID and message ID.",
    inputSchema={
        "type": "object",
        "properties": {
            # user_id removed from schema
            "oauth_state": {
                 "type": "string",
                 "description": "Internal state parameter for authentication flow tracking."
            },
            "message_id": {
                "type": "string",
                "description": "The ID of the Gmail message containing the attachment"
            },
            "attachment_id": {
                "type": "string",
                "description": "The ID of the attachment to retrieve"
            },
            "mime_type": { # Keep for EmbeddedResource, even if not strictly needed for API call
                "type": "string",
                "description": "The MIME type of the attachment (e.g., 'application/pdf')"
            },
            "filename": { # Keep for EmbeddedResource
                "type": "string",
                "description": "The filename of the attachment (e.g., 'document.pdf')"
            },
            "save_to_disk": {
                "type": "string",
                "description": "Optional full path to save the attachment to disk. If not provided, "
                               "the attachment is returned as an embedded resource."
            }
        },
        "required": ["oauth_state", "message_id", "attachment_id", "mime_type", "filename"] # Removed user_id
    },
    annotations=ToolAnnotations(
        version="1.0",
        author="Roo",
        tags=["gmail", "email", "attachment", "get", "download"]
    )
)
async def get_gmail_attachment(
    oauth_state: str,
    message_id: str,
    attachment_id: str,
    mime_type: str,
    filename: str,
    save_to_disk: str | None = None
) -> Sequence[TextContent | ImageContent | EmbeddedResource]:
    """Retrieves a Gmail attachment."""
    try:
        # Authenticate and Execute in thread using GLOBAL_USER_ID
        if not GLOBAL_USER_ID: raise JSONRPCError(code=-32000, message="Server user ID not configured.")
        credentials = await asyncio.to_thread(gauth.get_authenticated_credentials, GLOBAL_USER_ID, oauth_state)
        gmail_service = gmail.GmailService(credentials=credentials)
        attachment_data = await asyncio.to_thread(gmail_service.get_attachment, message_id, attachment_id)

        if attachment_data is None:
            # Assuming service layer raises specific error
            logger.error(f"get_attachment returned None for msg {message_id}, "
                         f"att {attachment_id}, user {GLOBAL_USER_ID}")
            raise JSONRPCError(code=-32010, message=f"Failed to retrieve attachment {attachment_id} "
                                                    f"from message {message_id}. It might not exist "
                                                    f"or an error occurred.")

        file_data = attachment_data.get("data")
        if not file_data:
            logger.error(f"Attachment {attachment_id} from message {message_id} contained no data "
                         f"for user {GLOBAL_USER_ID}")
            raise JSONRPCError(code=-32011, message=f"Attachment {attachment_id} from message "
                                                    f"{message_id} contained no data.")

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

                return {"status": "success", "message": f"Attachment saved to disk: {save_to_disk}", "path": save_to_disk}
            except Exception as save_e:
                logger.error(f"Error saving attachment {filename} to {save_to_disk} "
                             f"for user {GLOBAL_USER_ID}: {save_e}", exc_info=True)
                raise JSONRPCError(code=-32012, message=f"Failed to save attachment {filename} "
                                                        f"to {save_to_disk}. Reason: {save_e}")
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
                       f"(user: {GLOBAL_USER_ID}, msg: {message_id}, att: {attachment_id}): {auth_error}")
        # Generate auth URL and raise standard error with data field
        auth_url = await asyncio.to_thread(gauth.get_auth_url, GLOBAL_USER_ID, oauth_state)
        raise JSONRPCError(
            code=-32001, # Custom server error code for auth required
            message="Google authentication required.",
            data={"authUrl": auth_url, "state": oauth_state, "reason": str(auth_error)}
        )
    except HttpError as e:
         # Check for 404 specifically
        if e.resp.status == 404:
            logger.warning(f"Attachment {attachment_id} or message {message_id} not found "
                           f"for user {GLOBAL_USER_ID}: {e}")
            raise JSONRPCError(code=-32010, message=f"Attachment {attachment_id} or message "
                                                    f"{message_id} not found.")
        else:
            logger.error(f"Google API HTTP error in get_gmail_attachment for user "
                         f"{GLOBAL_USER_ID}, msg {message_id}, att {attachment_id}: {e}", exc_info=True)
            raise JSONRPCError(code=-32002, message=f"Google API Error: {e.resp.status} "
                                                    f"{e.reason}. Details: {e.content.decode()}")
    except base64.binascii.Error as b64_error: # Catch potential decoding errors
        logger.error(f"Base64 decoding error for attachment {attachment_id}, msg {message_id}, "
                     f"user {GLOBAL_USER_ID}: {b64_error}", exc_info=True)
        raise JSONRPCError(code=-32013, message=f"Failed to decode attachment data. "
                                                f"Reason: {b64_error}")
    except Exception as e:
        logger.error(f"Unexpected error in get_gmail_attachment for user "
                     f"{GLOBAL_USER_ID}, msg {message_id}, att {attachment_id}: {e}", exc_info=True)
        raise JSONRPCError(code=-32000, message=f"Failed to get attachment {attachment_id} for "
                                                f"{GLOBAL_USER_ID}. Reason: {e}")
##-##

### ----- WRITE/MODIFY TOOLS ----- ###
@app.tool(
    name="create_gmail_draft",
    description="""Creates a draft email message from scratch in Gmail with specified recipient, subject, body, and optional CC recipients.
    Do NOT use this tool when you want to draft or send a REPLY to an existing message. This tool does NOT include any previous message content. Use the reply_gmail_email tool
    with send=False instead.
    """,
    inputSchema={
        "type": "object",
        "properties": {
            # user_id removed from schema
            "oauth_state": {
                 "type": "string",
                 "description": "Internal state parameter for authentication flow tracking."
            },
            "to": {
                "type": "string",
                "description": "Email address of the recipient"
            },
            "subject": {
                "type": "string",
                "description": "Subject line of the email"
            },
            "body": {
                "type": "string",
                "description": "Body content of the email"
            },
            "cc": {
                "type": "array",
                "items": {
                    "type": "string"
                },
                "description": "Optional list of email addresses to CC"
            }
        },
        "required": ["oauth_state", "to", "subject", "body"] # Removed user_id
    },
    annotations=ToolAnnotations(
        version="1.0",
        author="Roo",
        tags=["gmail", "email", "draft", "create", "compose"]
    )
)
async def create_gmail_draft(
    oauth_state: str,
    to: str,
    subject: str,
    body: str,
    cc: list[str] | None = None
) -> Sequence[TextContent | ImageContent | EmbeddedResource]:
    """Creates a new Gmail draft."""
    try:
        # Authenticate and Execute in thread using GLOBAL_USER_ID
        if not GLOBAL_USER_ID: raise JSONRPCError(code=-32000, message="Server user ID not configured.")
        credentials = await asyncio.to_thread(gauth.get_authenticated_credentials, GLOBAL_USER_ID, oauth_state)
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
            logger.error(f"create_draft returned None for user {GLOBAL_USER_ID}")
            raise JSONRPCError(code=-32005, message="Failed to create draft email.")

        return draft # Return raw data

    except (FileNotFoundError, gauth.AuthenticationError) as auth_error:
        logger.warning(f"Authentication required for create_gmail_draft (user: {GLOBAL_USER_ID}): {auth_error}")
        # Generate auth URL and raise standard error with data field
        auth_url = await asyncio.to_thread(gauth.get_auth_url, GLOBAL_USER_ID, oauth_state)
        raise JSONRPCError(
            code=-32001, # Custom server error code for auth required
            message="Google authentication required.",
            data={"authUrl": auth_url, "state": oauth_state, "reason": str(auth_error)}
        )
    except HttpError as e:
        logger.error(f"Google API HTTP error in create_gmail_draft for user "
                     f"{GLOBAL_USER_ID}: {e}", exc_info=True)
        raise JSONRPCError(code=-32002, message=f"Google API Error: {e.resp.status} "
                                                f"{e.reason}. Details: {e.content.decode()}")
    except Exception as e:
        logger.error(f"Unexpected error in create_gmail_draft for user "
                     f"{GLOBAL_USER_ID}: {e}", exc_info=True)
        raise JSONRPCError(code=-32000, message=f"Failed to create draft for "
                                                f"{GLOBAL_USER_ID}. Reason: {e}")

@app.tool(
    name="delete_gmail_draft",
    description="Deletes a Gmail draft message by its ID. This action cannot be undone.",
    inputSchema={
        "type": "object",
        "properties": {
            # user_id removed from schema
            "oauth_state": {
                 "type": "string",
                 "description": "Internal state parameter for authentication flow tracking."
            },
            "draft_id": {
                "type": "string",
                "description": "The ID of the draft to delete"
            }
        },
        "required": ["oauth_state", "draft_id"] # Removed user_id
    },
    annotations=ToolAnnotations(
        version="1.0",
        author="Roo",
        tags=["gmail", "email", "draft", "delete"]
    )
)
async def delete_gmail_draft(
    oauth_state: str,
    draft_id: str
) -> Sequence[TextContent | ImageContent | EmbeddedResource]: # Removed user_id param
    """Deletes a Gmail draft by ID."""
    try:
        # Authenticate and Execute in thread using GLOBAL_USER_ID
        if not GLOBAL_USER_ID: raise JSONRPCError(code=-32000, message="Server user ID not configured.")
        credentials = await asyncio.to_thread(gauth.get_authenticated_credentials, GLOBAL_USER_ID, oauth_state)
        gmail_service = gmail.GmailService(credentials=credentials)
        success = await asyncio.to_thread(gmail_service.delete_draft, draft_id)

        if success:
             # Return a simple success message or confirmation object
             return {"status": "success", "message": f"Successfully deleted draft {draft_id}"}
        else:
             # Assuming service layer raises specific error if deletion fails
            logger.error(f"delete_draft returned False for draft {draft_id}, user {GLOBAL_USER_ID}")
            raise JSONRPCError(code=-32006, message=f"Failed to delete draft with ID: {draft_id}. "
                                                    f"It might not exist or an error occurred.")

    except (FileNotFoundError, gauth.AuthenticationError) as auth_error:
        logger.warning(f"Authentication required for delete_gmail_draft "
                       f"(user: {GLOBAL_USER_ID}, draft: {draft_id}): {auth_error}")
        # Generate auth URL and raise standard error with data field
        auth_url = await asyncio.to_thread(gauth.get_auth_url, GLOBAL_USER_ID, oauth_state)
        raise JSONRPCError(
            code=-32001, # Custom server error code for auth required
            message="Google authentication required.",
            data={"authUrl": auth_url, "state": oauth_state, "reason": str(auth_error)}
        )
    except HttpError as e:
        # Check for 404 specifically, could indicate draft not found
        if e.resp.status == 404:
            logger.warning(f"Draft {draft_id} not found for deletion by user "
                           f"{GLOBAL_USER_ID}: {e}")
            raise JSONRPCError(code=-32007, message=f"Draft with ID {draft_id} not found.")
        else:
            logger.error(f"Google API HTTP error in delete_gmail_draft for user "
                         f"{GLOBAL_USER_ID}, draft {draft_id}: {e}", exc_info=True)
            raise JSONRPCError(code=-32002, message=f"Google API Error: {e.resp.status} "
                                                    f"{e.reason}. Details: {e.content.decode()}")
    except Exception as e:
        logger.error(f"Unexpected error in delete_gmail_draft for user "
                     f"{GLOBAL_USER_ID}, draft {draft_id}: {e}", exc_info=True)
        raise JSONRPCError(code=-32000, message=f"Failed to delete draft {draft_id} for "
                                                f"{GLOBAL_USER_ID}. Reason: {e}")

@app.tool(
    name="reply_gmail_email",
    description="""Creates a reply to an existing Gmail email message and either sends it or saves as draft.
    Use this tool if you want to draft a reply. Use the 'cc' argument if you want to perform a "reply all".
    """,
    inputSchema={
        "type": "object",
        "properties": {
            # user_id removed from schema
            "oauth_state": {
                 "type": "string",
                 "description": "Internal state parameter for authentication flow tracking."
            },
            "original_message_id": {
                "type": "string",
                "description": "The ID of the Gmail message to reply to"
            },
            "reply_body": {
                "type": "string",
                "description": "The body content of your reply message"
            },
            "send": {
                "type": "boolean",
                "description": "If true, sends the reply immediately. If false, saves as draft.",
                "default": False
            },
            "cc": {
                "type": "array",
                "items": {
                    "type": "string"
                },
                "description": "Optional list of email addresses to CC on the reply"
            }
        },
        "required": ["oauth_state", "original_message_id", "reply_body"] # Removed user_id
    },
    annotations=ToolAnnotations(
        version="1.0",
        author="Roo",
        tags=["gmail", "email", "reply", "send", "draft"]
    )
)
async def reply_gmail_email(
    oauth_state: str,
    original_message_id: str,
    reply_body: str,
    send: bool = False,
    cc: list[str] | None = None
) -> Sequence[TextContent | ImageContent | EmbeddedResource]: # Removed user_id param
    """Creates and optionally sends a reply to a Gmail message."""
    try:
        # Authenticate and Execute in thread using GLOBAL_USER_ID
        if not GLOBAL_USER_ID: raise JSONRPCError(code=-32000, message="Server user ID not configured.")
        credentials = await asyncio.to_thread(gauth.get_authenticated_credentials, GLOBAL_USER_ID, oauth_state)
        gmail_service = gmail.GmailService(credentials=credentials)

        # Get original message (potentially blocking)
        original_message = await asyncio.to_thread(gmail_service.get_email_by_id, original_message_id)
        if original_message is None:
            # Assuming service layer raises specific error if not found
            logger.error(f"get_email_by_id returned None for original message "
                         f"{original_message_id}, user {GLOBAL_USER_ID}")
            raise JSONRPCError(code=-32008, message=f"Original message with ID {original_message_id} "
                                                    f"not found or could not be retrieved.")

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
            logger.error(f"create_reply returned None for user {GLOBAL_USER_ID}, "
                         f"original msg {original_message_id}")
            raise JSONRPCError(code=-32009, message=f"Failed to {'send' if send else 'draft'} "
                                                    f"reply email.")

        return result # Return raw data (draft or sent message object)

    except (FileNotFoundError, gauth.AuthenticationError) as auth_error:
        logger.warning(f"Authentication required for reply_gmail_email "
                       f"(user: {GLOBAL_USER_ID}, msg: {original_message_id}): {auth_error}")
        # Generate auth URL and raise standard error with data field
        auth_url = await asyncio.to_thread(gauth.get_auth_url, GLOBAL_USER_ID, oauth_state)
        raise JSONRPCError(
            code=-32001, # Custom server error code for auth required
            message="Google authentication required.",
            data={"authUrl": auth_url, "state": oauth_state, "reason": str(auth_error)}
        )
    except HttpError as e:
        # Check for 404 on original message fetch?
        if e.resp.status == 404 and "original_message" not in locals(): # Check if error happened during original message fetch
            logger.warning(f"Original message {original_message_id} not found for reply by user "
                           f"{GLOBAL_USER_ID}: {e}")
            raise JSONRPCError(code=-32008, message=f"Original message with ID {original_message_id} "
                                                    f"not found.")
        else:
            logger.error(f"Google API HTTP error in reply_gmail_email for user "
                         f"{GLOBAL_USER_ID}, msg {original_message_id}: {e}", exc_info=True)
            raise JSONRPCError(code=-32002, message=f"Google API Error: {e.resp.status} "
                                                    f"{e.reason}. Details: {e.content.decode()}")
    except Exception as e:
        logger.error(f"Unexpected error in reply_gmail_email for user "
                     f"{GLOBAL_USER_ID}, msg {original_message_id}: {e}", exc_info=True)
        raise JSONRPCError(code=-32000, message=f"Failed to reply to email {original_message_id} "
                                                f"for {GLOBAL_USER_ID}. Reason: {e}")

@app.tool(
    name="bulk_save_gmail_attachments",
    description="Saves multiple Gmail attachments to disk by their message IDs and attachment IDs.",
    inputSchema={
        "type": "object",
        "properties": {
            # user_id removed from schema
            "oauth_state": {
                 "type": "string",
                 "description": "Internal state parameter for authentication flow tracking."
            },
            "attachments": {
                "type": "array",
                "items": {
                    "type": "object",
                    "properties": {
                        "message_id": {
                            "type": "string",
                            "description": "ID of the Gmail message containing the attachment"
                        },
                        "attachment_id": { # Changed from part_id for consistency
                            "type": "string",
                            "description": "ID of the attachment"
                        },
                        "save_path": {
                            "type": "string",
                            "description": "Full path where the attachment should be saved"
                        }
                    },
                    "required": ["message_id", "attachment_id", "save_path"]
                },
                "description": "List of attachments to save."
            }
        },
        "required": ["oauth_state", "attachments"] # Removed user_id
    },
    annotations=ToolAnnotations(
        version="1.0",
        author="Roo",
        tags=["gmail", "email", "attachment", "save", "download", "bulk"]
    )
)
async def bulk_save_gmail_attachments(oauth_state: str, attachments: list[dict]) -> Sequence[TextContent | ImageContent | EmbeddedResource]:
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
        # Authenticate once using GLOBAL_USER_ID
        if not GLOBAL_USER_ID: raise JSONRPCError(code=-32000, message="Server user ID not configured.")
        credentials = await asyncio.to_thread(gauth.get_authenticated_credentials, GLOBAL_USER_ID, oauth_state)
        gmail_service = gmail.GmailService(credentials=credentials)

        # Create tasks for each attachment save
        tasks = [save_single_attachment(gmail_service, att_info) for att_info in attachments]
        results = await asyncio.gather(*tasks) # Exceptions are returned in results

        return results # Return list of status dicts


    except (FileNotFoundError, gauth.AuthenticationError) as auth_error:
        logger.warning(f"Authentication required for bulk_save_gmail_attachments "
                       f"(user: {GLOBAL_USER_ID}): {auth_error}")
        # Generate auth URL and raise standard error with data field
        auth_url = await asyncio.to_thread(gauth.get_auth_url, GLOBAL_USER_ID, oauth_state)
        raise JSONRPCError(
            code=-32001, # Custom server error code for auth required
            message="Google authentication required.",
            data={"authUrl": auth_url, "state": oauth_state, "reason": str(auth_error)}
        )
    # HttpError and other exceptions are handled within save_single_attachment now
    except Exception as e:
        # Catch errors during initial auth or task setup
        logger.error(f"Unexpected error setting up bulk_save_gmail_attachments for user "
                     f"{GLOBAL_USER_ID}: {e}", exc_info=True)
        raise JSONRPCError(code=-32000, message=f"Failed bulk attachment save setup for "
                                                f"{GLOBAL_USER_ID}. Reason: {e}")
##-##

##-##

#-#