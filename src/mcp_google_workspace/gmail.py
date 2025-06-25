# ===== IMPORTS ===== #

## ===== STANDARD LIBRARY ===== ##
from __future__ import annotations
'''----------------------------'''
from email.mime.text import MIMEText
# from typing import Tuple # Removed unused import
import logging
import base64
##-##

## ===== THIRD PARTY ===== ##
from google.oauth2.credentials import Credentials
from googleapiclient.errors import HttpError
from googleapiclient.discovery import build
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
class EmailNotFoundError(Exception):
    pass

class AttachmentNotFoundError(Exception):
    pass

class DraftNotFoundError(Exception):
    pass

class EmailParsingError(Exception):
    pass
##-##

## ===== SERVICES ===== ##
class GmailService():
    def __init__(self, credentials: Credentials):
        # Removed user_id lookup, credentials passed directly
        if not credentials:
            # Should not happen if tool layer validates, but good check
             raise ValueError("Credentials must be provided to GmailService.")
        try:
            self.service = build('gmail', 'v1', credentials=credentials)
        except Exception as e:
            # Catch potential build errors (e.g., invalid credentials structure)
            logger.error(f"Failed to build Gmail service: {e}",
                         exc_info=True)
            raise RuntimeError(f"Failed to initialize Gmail service: {e}") from e

    def _parse_message(self, message_data, parse_body=False) -> dict | None:
        """
        Parse a Gmail message into a structured format.
        
        Args:
            message_data (dict): Raw message data from Gmail API
            parse_body (bool): Whether to parse and include the message body (default: False)
        
        Returns:
            dict: Parsed message containing comprehensive metadata
            None: If parsing fails
        """
        try:
            message_id = message_data.get('id')
            thread_id = message_data.get('threadId')
            payload = message_data.get('payload', {})
            headers = payload.get('headers', [])

            metadata = {
                'id': message_id,
                'threadId': thread_id,
                'historyId': message_data.get('historyId'),
                'internalDate': message_data.get('internalDate'),
                'sizeEstimate': message_data.get('sizeEstimate'),
                'labelIds': message_data.get('labelIds', []),
                'snippet': message_data.get('snippet'),
            }

            for header in headers:
                name = header.get('name', '').lower()
                value = header.get('value', '')
                
                if name == 'subject':
                    metadata['subject'] = value
                elif name == 'from':
                    metadata['from'] = value
                elif name == 'to':
                    metadata['to'] = value
                elif name == 'date':
                    metadata['date'] = value
                elif name == 'cc':
                    metadata['cc'] = value
                elif name == 'bcc':
                    metadata['bcc'] = value
                elif name == 'message-id':
                    metadata['message_id'] = value
                elif name == 'in-reply-to':
                    metadata['in_reply_to'] = value
                elif name == 'references':
                    metadata['references'] = value
                elif name == 'delivered-to':
                    metadata['delivered_to'] = value

            if parse_body:
                body = self._extract_body(payload)
                if body:
                    metadata['body'] = body

                metadata['mimeType'] = payload.get('mimeType')

            return metadata

        except Exception as e:
            # Keep logging for internal helper, but maybe raise specific error?
            logging.error(f"Error parsing message structure: {e}",
                          exc_info=True)
            # For now, return None as the caller (get_email_by_id_with_attachments) will handle it
            return None

    def _extract_body(self, payload) -> str | None:
        """
        Extract the email body from the payload.
        Handles both multipart and single part messages, including nested multiparts.
        """
        try:
            # For single part text/plain messages
            if payload.get('mimeType') == 'text/plain':
                data = payload.get('body', {}).get('data')
                if data:
                    return base64.urlsafe_b64decode(data).decode('utf-8')
            
            # For multipart messages (both alternative and related)
            if payload.get('mimeType', '').startswith('multipart/'):
                parts = payload.get('parts', [])
                
                # First try to find a direct text/plain part
                for part in parts:
                    if part.get('mimeType') == 'text/plain':
                        data = part.get('body', {}).get('data')
                        if data:
                            return base64.urlsafe_b64decode(data).decode('utf-8')
                
                # If no direct text/plain, recursively check nested multipart structures
                for part in parts:
                    if part.get('mimeType', '').startswith('multipart/'):
                        nested_body = self._extract_body(part)
                        if nested_body:
                            return nested_body
                            
                # If still no body found, try the first part as fallback
                if parts and 'body' in parts[0] and 'data' in parts[0]['body']:
                    data = parts[0]['body']['data']
                    return base64.urlsafe_b64decode(data).decode('utf-8')

            return None

        except Exception as e:
            # Keep logging for internal helper
            logging.error(f"Error extracting body content: {e}",
                          exc_info=True)
            return None # Caller handles None

    def query_emails(self, query=None, max_results=100):
        """
        Query emails from Gmail based on a search query.
        
        Args:
            query (str, optional): Gmail search query (e.g., 'is:unread', 'from:example@gmail.com')
                                If None, returns all emails
            max_results (int): Maximum number of emails to retrieve (1-500, default: 100)
        
        Returns:
            list: List of parsed email messages, newest first
        """
        # Removed outer try/except - let HttpError propagate
        # Ensure max_results is within API limits
        max_results = min(max(1, max_results), 500)

        # Get the list of messages - can raise HttpError
        result = self.service.users().messages().list(
            userId='me',
            maxResults=max_results,
            q=query if query else ''
        ).execute()

        messages = result.get('messages', [])
        parsed = []
        # errors = [] # Removed unused variable

        # Fetch full message details for each message
        for msg in messages:
            try:
                # This call can raise HttpError (e.g., if a message was deleted between list and get)
                message_data = self.service.users().messages().get(
                    userId='me',
                    id=msg['id']
                ).execute()
                parsed_message = self._parse_message(message_data=message_data, parse_body=False)
                if parsed_message:
                    parsed.append(parsed_message)
                else:
                    # Log if parsing failed for a specific message
                    logger.warning(f"Failed to parse message ID {msg.get('id')} during query.")
                    # errors.append({"id": msg.get('id'), "error": "Parsing failed"}) # Removed unused variable append
            except HttpError as e:
                 logger.error(f"HttpError getting message ID {msg.get('id')} "
                              f"during query: {e}", exc_info=True)
                 # errors.append({"id": msg.get('id'), "error": f"HTTP {e.resp.status}: {e.reason}"}) # Removed unused variable append
            except Exception as e:
                 logger.error(f"Unexpected error getting message ID {msg.get('id')} "
                              f"during query: {e}", exc_info=True)
                 # errors.append({"id": msg.get('id'), "error": f"Unexpected error: {e}"}) # Removed unused variable append


        # Return parsed messages, potentially include errors if needed by caller
        # For now, just return successfully parsed messages. Caller can infer failures if count mismatch.
        # Or return a dict: {"emails": parsed, "errors": errors} ? Let's return just parsed for now.
        return parsed
        
    def get_email_by_id_with_attachments(self, email_id: str) -> Tuple[dict, dict]:
        """
        Fetch and parse a complete email message by its ID including attachment IDs.
        
        Args:
            email_id (str): The Gmail message ID to retrieve
        
        Returns:
            Tuple[dict, dict]: Complete parsed email message including body and dictionary of attachment metadata (key: partId)
            Tuple[None, dict]: If retrieval or parsing fails, raises EmailNotFoundError or EmailParsingError. Returns empty dict for attachments if parsing fails after retrieval.
        """
        # Removed outer try/except - let HttpError propagate
        # Fetch the complete message by ID - can raise HttpError
        try:
            message = self.service.users().messages().get(
                userId='me',
                id=email_id
            ).execute()
        except HttpError as e:
            if e.resp.status == 404:
                raise EmailNotFoundError(f"Email with ID '{email_id}' not found.") from e
            else:
                # Re-raise other HttpErrors
                raise

        # Parse the message with body included
        parsed_email = self._parse_message(message_data=message, parse_body=True)

        if parsed_email is None:
            # Raise error if parsing failed
            raise EmailParsingError(f"Failed to parse email structure for ID '{email_id}'.")

        attachments = {}
        # Use .get() for safer access to potentially missing keys
        payload = message.get('payload', {})
        parts = payload.get('parts', [])
        for part in parts:
            body = part.get('body', {})
            if body and 'attachmentId' in body:
                attachment_id = body['attachmentId']
                part_id = part.get('partId') # partId might not always be present?
                filename = part.get('filename', '') # Handle missing filename
                mime_type = part.get('mimeType', 'application/octet-stream') # Default mimeType

                if attachment_id and part_id: # Ensure key identifiers are present
                    attachments[part_id] = {
                        "filename": filename,
                        "mimeType": mime_type,
                        "attachmentId": attachment_id,
                        "partId": part_id,
                        "size": body.get('size') # Include size if available
                    }
                else:
                     logger.warning(f"Skipping attachment part in email {email_id} due to missing ID "
                                    f"(partId: {part_id}, attachmentId: {attachment_id})")


        return parsed_email, attachments
        
    def create_draft(self, to: str, subject: str, body: str, cc: list[str] | None = None) -> dict:
        """
        Create a draft email message.
        
        Args:
            to (str): Email address of the recipient
            subject (str): Subject line of the email
            body (str): Body content of the email
            cc (list[str], optional): List of email addresses to CC
            
        Returns:
            dict: Draft message data including the draft ID if successful
            Raises: HttpError on API issues, ValueError on encoding errors.
        """
        # Removed outer try/except - let HttpError propagate
        # Create the message in MIME format
        mime_message = MIMEText(body)
        mime_message['to'] = to
        mime_message['subject'] = subject
        if cc:
            mime_message['cc'] = ','.join(cc)

        # Encode the message
        try:
            raw_message = base64.urlsafe_b64encode(mime_message.as_bytes()).decode('utf-8')
        except Exception as encode_error:
            # Handle potential encoding errors
            logger.error(f"Error encoding draft message: {encode_error}",
                         exc_info=True)
            raise ValueError("Failed to encode draft message content.") from encode_error

        # Create the draft - can raise HttpError
        draft = self.service.users().drafts().create(
            userId='me',
            body={
                'message': {
                    'raw': raw_message
                }
            }
        ).execute()

        return draft
        
    def delete_draft(self, draft_id: str) -> bool:
        """
        Delete a draft email message.
        
        Args:
            draft_id (str): The ID of the draft to delete
            
        Returns:
            bool: True if deletion was successful. Raises DraftNotFoundError if draft doesn't exist or HttpError for other API issues.
        """
        try:
            # This call can raise HttpError
            self.service.users().drafts().delete(
                userId='me',
                id=draft_id
            ).execute()
            # Gmail API returns empty body on success for delete
            return True

        except HttpError as e:
            if e.resp.status == 404:
                raise DraftNotFoundError(f"Draft with ID '{draft_id}' not found.") from e
            else:
                raise
        
    def create_reply(self, original_message: dict, reply_body: str, send: bool = False, cc: list[str] | None = None) -> dict:
        """
        Create a reply to an email message and either send it or save as draft.
        
        Args:
            original_message (dict): The original message data (as returned by get_email_by_id)
            reply_body (str): Body content of the reply
            send (bool): If True, sends the reply immediately. If False, saves as draft.
            cc (list[str], optional): List of email addresses to CC
            
        Returns:
            dict: Sent message or draft data if successful
            Raises: ValueError if original message data is invalid, HttpError on API issues, ValueError on encoding errors.
        """
        # Removed outer try/except - let HttpError/ValueError propagate
        to_address = original_message.get('from')
        # Extract original message ID safely
        original_message_id = original_message.get('id')
        original_thread_id = original_message.get('threadId')

        if not to_address:
            raise ValueError("Could not determine original sender's address from the provided message object.")
        if not original_message_id:
             raise ValueError("Could not determine original message ID from the provided message object.")
        if not original_thread_id:
             raise ValueError("Could not determine original thread ID from the provided message object.")


        subject = original_message.get('subject', '')
        if not subject.lower().startswith('re:'):
            subject = f"Re: {subject}"

        # Construct reply body (keep existing logic)
        original_date = original_message.get('date', '')
        original_from = original_message.get('from', '') # Already checked above
        original_body = original_message.get('body', '') # Body might be missing if not parsed fully before

        full_reply_body = (
            f"{reply_body}\n\n"
            f"On {original_date}, {original_from} wrote:\n"
            f"> {original_body.replace('\n', '\n> ') if original_body else '[Original message body not available]'}"
        )

        # Create MIME message
        mime_message = MIMEText(full_reply_body)
        mime_message['to'] = to_address
        mime_message['subject'] = subject
        if cc:
            mime_message['cc'] = ','.join(cc)

        # Set headers for threading
        mime_message['In-Reply-To'] = original_message_id
        # Use References header if available, otherwise fallback to Message-ID
        references = original_message.get('references') or original_message.get('message_id')
        if references:
             mime_message['References'] = f"{references} {original_message_id}" # Append original ID
        else:
             mime_message['References'] = original_message_id


        # Encode message
        try:
            raw_message = base64.urlsafe_b64encode(mime_message.as_bytes()).decode('utf-8')
        except Exception as encode_error:
            logger.error(f"Error encoding reply message: {encode_error}",
                         exc_info=True)
            raise ValueError("Failed to encode reply message content.") from encode_error

        message_body = {
            'raw': raw_message,
            'threadId': original_thread_id
        }

        # Send or Draft - can raise HttpError
        if send:
            result = self.service.users().messages().send(
                userId='me',
                body=message_body
            ).execute()
        else:
            result = self.service.users().drafts().create(
                userId='me',
                body={
                    'message': message_body
                }
            ).execute()

        return result
        
    def get_attachment(self, message_id: str, attachment_id: str) -> dict:
        """
        Retrieves a Gmail attachment by its ID.
        
        Args:
            message_id (str): The ID of the Gmail message containing the attachment
            attachment_id (str): The ID of the attachment to retrieve
        
        Returns:
            dict: Attachment data including filename and base64-encoded content
            Raises: AttachmentNotFoundError, PermissionError, HttpError on API issues.
        """
        try:
            # This call can raise HttpError
            attachment = self.service.users().messages().attachments().get(
                userId='me',
                messageId=message_id,
                id=attachment_id
            ).execute()

            # Check if data is present
            attachment_data = attachment.get("data")
            if attachment_data is None:
                 # This might indicate an issue even if the API call succeeded
                 raise AttachmentNotFoundError(
                     f"Attachment with ID '{attachment_id}' found but contained no data."
                 )

            return {
                "size": attachment.get("size"),
                "data": attachment_data
            }
        except HttpError as e:
            if e.resp.status == 404:
                 raise AttachmentNotFoundError(
                     f"Attachment with ID '{attachment_id}' not found in message '{message_id}'."
                 ) from e
            # Handle 403 Forbidden?
            elif e.resp.status == 403:
                 raise PermissionError(
                     f"Permission denied accessing attachment '{attachment_id}' in message '{message_id}'."
                 ) from e
            else:
                # Re-raise other HttpErrors
                raise
##-##

#-#