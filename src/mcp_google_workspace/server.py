# ===== IMPORTS ===== #

## ===== STANDARD LIBRARY ===== ##
from __future__ import annotations

import sys
import argparse
import asyncio
import logging
from collections.abc import Sequence
##-##

## ===== THIRD PARTY ===== ##
from dotenv import load_dotenv
from mcp.server import Server
from mcp.types import JSONRPCError # Keep this specific import if needed directly
import mcp.types as types # Use this for all other types
##-##

## ===== LOCAL ===== ##
# gauth is needed globally for startup checks
from . import gauth
##-##

#-##

# ===== GLOBALS ===== #
load_dotenv()
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("mcp-google-workspace")

# No global user ID needed for multi-tenant server
#-##

# ===== FUNCTIONS ===== #

def create_app() -> Server:
    """Factory function to create and configure the MCP Server instance."""
    app = Server("mcp-google-workspace") # Initialize MCP Server inside the factory

    # Import tool modules AFTER app is defined so decorators register correctly
    from . import tools_calendar as calendar_tools
    from . import tools_drive as drive_tools
    from . import tools_gmail as gmail_tools

    ## ===== MCP TOOLS ===== ##

    ### ----- DEFINITIONS ----- ###
    # Manually define the tools based on the definitions in tools_*.py files
    ALL_TOOLS = [
        # --- Auth Tools ---
        types.Tool(
            name="initiate_google_oauth",
            description="Generates the Google OAuth 2.0 authorization URL for the user to initiate the authentication flow.",
            inputSchema={
                "type": "object",
                "properties": {
                    "user_email": {"type": "string", "description": "The email address of the user initiating the flow (used for logging/context)."},
                    "oauth_state": {"type": "string", "description": "A unique string provided by the calling application (aggregator) to maintain state across the redirect."}
                },
                "required": ["user_email", "oauth_state"]
            }
        ),

        # --- Gmail Tools ---
        types.Tool(
            name="query_gmail_emails",
            description="Query Gmail emails based on an optional search query.\nReturns emails in reverse chronological order (newest first).\nReturns metadata such as subject and also a short summary of the content.",
            inputSchema={
                "type": "object",
                "properties": {
                    # Removed oauth_state
                    "query": {"type": "string", "description": "Gmail search query (optional). Examples:\n    - a $string: Search email body, subject, and sender information for $string\n    - 'is:unread' for unread emails\n    - 'from:example@gmail.com' for emails from a specific sender\n    - 'newer_than:2d' for emails from last 2 days\n    - 'has:attachment' for emails with attachments\nIf not provided, returns recent emails without filtering."},
                    "max_results": {"type": "integer", "description": "Maximum number of emails to retrieve (1-500)", "minimum": 1, "maximum": 500, "default": 100}
                },
                "required": [] # Removed oauth_state
            }
        ),
        types.Tool(
            name="get_gmail_email",
            description="Retrieves a complete Gmail email message by its ID, including the full message body and attachment IDs.",
            inputSchema={
                "type": "object",
                "properties": {
                    # Removed oauth_state
                    "email_id": {"type": "string", "description": "The ID of the Gmail message to retrieve"}
                },
                "required": ["email_id"] # Removed oauth_state
            }
        ),
        types.Tool(
            name="bulk_get_gmail_emails",
            description="Retrieves multiple Gmail email messages by their IDs in a single request, including the full message bodies and attachment IDs.",
            inputSchema={
                "type": "object",
                "properties": {
                    # Removed oauth_state
                    "email_ids": {"type": "array", "items": {"type": "string"}, "description": "List of Gmail message IDs to retrieve"}
                },
                "required": ["email_ids"] # Removed oauth_state
            }
        ),
        types.Tool(
            name="get_gmail_attachment",
            description="Retrieves a Gmail attachment by its ID and message ID.",
            inputSchema={
                "type": "object",
                "properties": {
                    # Removed oauth_state
                    "message_id": {"type": "string", "description": "The ID of the Gmail message containing the attachment"},
                    "attachment_id": {"type": "string", "description": "The ID of the attachment to retrieve"},
                    "mime_type": {"type": "string", "description": "The MIME type of the attachment (e.g., 'application/pdf')"},
                    "filename": {"type": "string", "description": "The filename of the attachment (e.g., 'document.pdf')"},
                    "save_to_disk": {"type": "string", "description": "Optional full path to save the attachment to disk. If not provided, the attachment is returned as an embedded resource."}
                },
                "required": ["message_id", "attachment_id", "mime_type", "filename"] # Removed oauth_state
            }
        ),
        types.Tool(
            name="create_gmail_draft",
            description="Creates a draft email message from scratch in Gmail with specified recipient, subject, body, and optional CC recipients.\nDo NOT use this tool when you want to draft or send a REPLY to an existing message. This tool does NOT include any previous message content. Use the reply_gmail_email tool\nwith send=False instead.",
            inputSchema={
                "type": "object",
                "properties": {
                    # Removed oauth_state
                    "to": {"type": "string", "description": "Email address of the recipient"},
                    "subject": {"type": "string", "description": "Subject line of the email"},
                    "body": {"type": "string", "description": "Body content of the email"},
                    "cc": {"type": "array", "items": {"type": "string"}, "description": "Optional list of email addresses to CC"}
                },
                "required": ["to", "subject", "body"] # Removed oauth_state
            }
        ),
        types.Tool(
            name="delete_gmail_draft",
            description="Deletes a Gmail draft message by its ID. This action cannot be undone.",
            inputSchema={
                "type": "object",
                "properties": {
                    # Removed oauth_state
                    "draft_id": {"type": "string", "description": "The ID of the draft to delete"}
                },
                "required": ["draft_id"] # Removed oauth_state
            }
        ),
        types.Tool(
            name="reply_gmail_email",
            description="Creates a reply to an existing Gmail email message and either sends it or saves as draft.\nUse this tool if you want to draft a reply. Use the 'cc' argument if you want to perform a \"reply all\".",
            inputSchema={
                "type": "object",
                "properties": {
                    # Removed oauth_state
                    "original_message_id": {"type": "string", "description": "The ID of the Gmail message to reply to"},
                    "reply_body": {"type": "string", "description": "The body content of your reply message"},
                    "send": {"type": "boolean", "description": "If true, sends the reply immediately. If false, saves as draft.", "default": False},
                    "cc": {"type": "array", "items": {"type": "string"}, "description": "Optional list of email addresses to CC on the reply"}
                },
                "required": ["original_message_id", "reply_body"] # Removed oauth_state
            }
        ),
        types.Tool(
            name="bulk_save_gmail_attachments",
            description="Saves multiple Gmail attachments to disk by their message IDs and attachment IDs.",
            inputSchema={
                "type": "object",
                "properties": {
                    # Removed oauth_state
                    "attachments": {
                        "type": "array",
                        "items": {
                            "type": "object",
                            "properties": {
                                "message_id": {"type": "string", "description": "ID of the Gmail message containing the attachment"},
                                "attachment_id": {"type": "string", "description": "ID of the attachment"},
                                "save_path": {"type": "string", "description": "Full path where the attachment should be saved"}
                            },
                            "required": ["message_id", "attachment_id", "save_path"]
                        },
                        "description": "List of attachments to save."
                    }
                },
                "required": ["attachments"] # Removed oauth_state
            }
        ),
        # --- Drive Tools ---
        types.Tool(
            name="list_drive_files",
            description="Lists files in Google Drive, optionally filtered by a query.",
            inputSchema={
                "type": "object",
                "properties": {
                    # Removed oauth_state
                    "query": {"type": "string", "description": "Optional query string to filter files (e.g., \"name contains 'report' and mimeType='application/vnd.google-apps.spreadsheet'\"). Uses Google Drive query language."},
                    "page_size": {"type": "integer", "description": "Maximum number of files to return (1-1000).", "minimum": 1, "maximum": 1000, "default": 100},
                    "fields": {"type": "string", "description": "Fields to include in the response for each file.", "default": "nextPageToken, files(id, name, mimeType, size, modifiedTime, parents)"}
                },
                "required": [] # Removed oauth_state
            }
        ),
        types.Tool(
            name="get_drive_file_metadata",
            description="Gets the metadata for a specific file in Google Drive.",
            inputSchema={
                "type": "object",
                "properties": {
                    # Removed oauth_state
                    "file_id": {"type": "string", "description": "The ID of the file to get metadata for."},
                    "fields": {"type": "string", "description": "Fields to include in the metadata response.", "default": "id, name, mimeType, size, modifiedTime, createdTime, owners, parents, webViewLink, iconLink"}
                },
                "required": ["file_id"] # Removed oauth_state
            }
        ),
        types.Tool(
            name="download_drive_file",
            description="Downloads a file from Google Drive and returns its content as an embedded resource.",
            inputSchema={
                "type": "object",
                "properties": {
                    # Removed oauth_state
                    "file_id": {"type": "string", "description": "The ID of the file to download."}
                },
                "required": ["file_id"] # Removed oauth_state
            }
        ),
        types.Tool(
            name="upload_drive_file",
            description="Uploads a file (provided as base64 encoded content) to Google Drive.",
            inputSchema={
                "type": "object",
                "properties": {
                    # Removed oauth_state
                    "file_name": {"type": "string", "description": "The desired name for the uploaded file."},
                    "mime_type": {"type": "string", "description": "The MIME type of the file (e.g., 'text/plain', 'image/jpeg')."},
                    "file_content_b64": {"type": "string", "description": "The base64 encoded content of the file to upload."},
                    "folder_id": {"type": "string", "description": "Optional ID of the folder to upload the file into. If None or omitted, uploads to the root folder."}
                },
                "required": ["file_name", "mime_type", "file_content_b64"] # Removed oauth_state
            }
        ),
        # --- Calendar Tools ---
        types.Tool(
            name="list_calendars",
            description="Lists all calendars accessible by the user.\nCall it before any other tool whenever the user specifies a particular agenda (Family, Holidays, etc.).",
            inputSchema={
                "type": "object",
                "properties": {
                    # Removed oauth_state
                },
                "required": [] # Removed oauth_state
            }
        ),
        types.Tool(
            name="get_calendar_events",
            description="Retrieves calendar events from the user's Google Calendar within a specified time range.",
            inputSchema={
                "type": "object",
                "properties": {
                    # Removed oauth_state
                    "calendar_id": {"type": "string", "description": "Optional ID of the calendar. Defaults to 'primary'. Use list_calendars to find IDs.", "default": "primary"},
                    "time_min": {"type": "string", "description": "Start time in RFC3339 format (e.g. 2024-12-01T00:00:00Z). Defaults to current time if not specified."},
                    "time_max": {"type": "string", "description": "End time in RFC3339 format (e.g. 2024-12-31T23:59:59Z). Optional."},
                    "max_results": {"type": "integer", "description": "Maximum number of events to return (1-2500)", "minimum": 1, "maximum": 2500, "default": 250},
                    "show_deleted": {"type": "boolean", "description": "Whether to include deleted events", "default": False}
                },
                "required": [] # Removed oauth_state
            }
        ),
        types.Tool(
            name="create_calendar_event",
            description="Creates a new event in a specified Google Calendar of the specified user.",
            inputSchema={
                "type": "object",
                "properties": {
                    # Removed oauth_state
                    "calendar_id": {"type": "string", "description": "Optional ID of the calendar. Defaults to 'primary'. Use list_calendars to find IDs.", "default": "primary"},
                    "summary": {"type": "string", "description": "Title of the event"},
                    "location": {"type": "string", "description": "Location of the event (optional)"},
                    "description": {"type": "string", "description": "Description or notes for the event (optional)"},
                    "start_time": {"type": "string", "description": "Start time in RFC3339 format (e.g. 2024-12-01T10:00:00Z)"},
                    "end_time": {"type": "string", "description": "End time in RFC3339 format (e.g. 2024-12-01T11:00:00Z)"},
                    "attendees": {"type": "array", "items": {"type": "string"}, "description": "List of attendee email addresses (optional)"},
                    "send_notifications": {"type": "boolean", "description": "Whether to send notifications to attendees", "default": True},
                    "timezone": {"type": "string", "description": "Timezone for the event (e.g. 'America/New_York'). Defaults to UTC if not specified."}
                },
                "required": ["summary", "start_time", "end_time"] # Removed oauth_state
            }
        ),
        types.Tool(
            name="delete_calendar_event",
            description="Deletes an event from the user's Google Calendar by its event ID.",
            inputSchema={
                "type": "object",
                "properties": {
                    # Removed oauth_state
                    "calendar_id": {"type": "string", "description": "Optional ID of the calendar. Defaults to 'primary'. Use list_calendars to find IDs.", "default": "primary"},
                    "event_id": {"type": "string", "description": "The ID of the calendar event to delete"},
                    "send_notifications": {"type": "boolean", "description": "Whether to send cancellation notifications to attendees", "default": True}
                },
                "required": ["event_id"] # Removed oauth_state
            }
        ),
    ]
    ###-###

    ### ----- TOOL FUNCTION MAP ----- ###
    # Map tool names to their actual functions
    TOOL_FUNCTION_MAP = {
        # Auth
        "initiate_google_oauth": initiate_google_oauth, # Add mapping for the new tool
        # Gmail
        "query_gmail_emails": gmail_tools.query_gmail_emails,
        "get_gmail_email": gmail_tools.get_gmail_email,
        "bulk_get_gmail_emails": gmail_tools.bulk_get_gmail_emails,
        "get_gmail_attachment": gmail_tools.get_gmail_attachment,
        "create_gmail_draft": gmail_tools.create_gmail_draft,
        "delete_gmail_draft": gmail_tools.delete_gmail_draft,
        "reply_gmail_email": gmail_tools.reply_gmail_email,
        "bulk_save_gmail_attachments": gmail_tools.bulk_save_gmail_attachments,
        # Drive
        "list_drive_files": drive_tools.list_drive_files,
        "get_drive_file_metadata": drive_tools.get_drive_file_metadata,
        "download_drive_file": drive_tools.download_drive_file,
        "upload_drive_file": drive_tools.upload_drive_file,
        # Calendar
        "list_calendars": calendar_tools.list_calendars,
        "get_calendar_events": calendar_tools.get_calendar_events,
        "create_calendar_event": calendar_tools.create_calendar_event,
        "delete_calendar_event": calendar_tools.delete_calendar_event,
    }
    ###-###

    ##-##

    ## ===== MCP TOOL HANDLERS ===== ##

    # Separate handler for the auth initiation tool
    @app.tool()
    async def initiate_google_oauth(user_email: str, oauth_state: str) -> types.CallToolResult:
        """
        Handles the initiate_google_oauth tool call.
        Generates the Google OAuth URL using gauth.get_auth_url.
        """
        logger.info(f"initiate_google_oauth called for user: {user_email} with state: {oauth_state}")
        try:
            # Call the gauth function to get the URL, passing the state
            # Note: user_email is logged but not directly used by get_auth_url
            auth_url = await asyncio.to_thread(gauth.get_auth_url, state=oauth_state)

            if auth_url:
                logger.info(f"Successfully generated auth URL for state: {oauth_state}")
                return types.CallToolResult(content=[types.TextContent(type="text", text=auth_url)], isError=False)
            else:
                logger.error(f"Failed to generate auth URL for state: {oauth_state}. gauth.get_auth_url returned None.")
                return types.CallToolResult(content=[types.TextContent(type="text", text="Failed to generate Google OAuth URL.")], isError=True)
        except Exception as e:
            logger.error(f"Error during initiate_google_oauth for state {oauth_state}: {e}", exc_info=True)
            return types.CallToolResult(content=[types.TextContent(type="text", text=f"An unexpected error occurred: {e}")], isError=True)


    @app.list_tools()
    async def list_tools() -> list[types.Tool]:
        """Lists all available Google Workspace tools."""
        logger.info("list_tools called")
        return ALL_TOOLS

    @app.call_tool()
    async def call_tool(name: str, arguments: dict | None) -> types.CallToolResult:
        """Calls the appropriate Google Workspace tool function."""
        logger.info(f"call_tool called for tool: {name} with args: {arguments}")

        tool_func = TOOL_FUNCTION_MAP.get(name)
        if not tool_func:
            logger.error(f"Tool function '{name}' not found.")
            raise JSONRPCError(code=-32601, message=f"Method not found: {name}")

        # Ensure arguments is a dictionary, even if empty
        args_to_pass = arguments or {}

        try:
            # Call the actual tool function
            # Extract user_id from arguments if present (required for multi-tenant)
            # TODO: Make user_id mandatory in schemas for operational tools in a separate task.
            user_id_from_args = args_to_pass.pop('user_id', None) # Use pop to remove it before passing rest
            if not user_id_from_args:
                 # This check is temporary until schemas are updated.
                 # For now, tools might fail if they strictly require user_id internally.
                 logger.error(f"Tool '{name}' called without 'user_id' argument. Multi-tenant refactor needed.")
                 raise JSONRPCError(code=-32602, message=f"Missing required 'user_id' argument for tool '{name}'.")

            result_content = await tool_func(**args_to_pass, user_id=user_id_from_args)

            # Handle the case where the tool function returns the error dict structure
            if isinstance(result_content, dict) and result_content.get("isError"):
                 logger.warning(f"Tool '{name}' returned an error structure: {result_content.get('content')}")
                 # Ensure content is in the expected format for types.CallToolResult
                 error_content = result_content.get("content", [types.TextContent(type="text", text="Unknown error from tool")])
                 if not isinstance(error_content, list): # Wrap if not a list
                     error_content = [error_content]
                 return types.CallToolResult(content=error_content, isError=True)

            # Ensure the successful result is a list/sequence as expected by types.CallToolResult
            if not isinstance(result_content, Sequence):
                 # If it's a single item (like types.EmbeddedResource from download_drive_file), wrap it
                 if isinstance(result_content, (types.TextContent, types.ImageContent, types.EmbeddedResource)):
                     result_content = [result_content]
                 else:
                     # If it's some other unexpected type, log and wrap as text
                     logger.warning(f"Tool '{name}' returned unexpected type: {type(result_content)}. Wrapping as types.TextContent.")
                     result_content = [types.TextContent(type="text", text=str(result_content))]


            logger.info(f"Tool '{name}' executed successfully.")
            return types.CallToolResult(content=result_content, isError=False)

        except JSONRPCError as rpc_error:
            # Re-raise JSONRPCError (e.g., auth errors) to be handled by the MCP framework
            logger.warning(f"JSONRPCError during tool '{name}' execution: {rpc_error}")
            raise rpc_error
        except Exception as e:
            # Catch any other unexpected errors during tool execution
            logger.error(f"Unexpected error calling tool '{name}': {e}", exc_info=True)
            # Return a standard error result
            error_message = f"An unexpected error occurred while executing tool '{name}': {e}"
            return types.CallToolResult(
                content=[types.TextContent(type="text", text=error_message)],
                isError=True
            )
    ##-##

    ## ===== MCP PROMPTS ===== ##
    # Define available prompts (can be loaded from YAML later)
    AVAILABLE_PROMPTS = {
        "onboarding": types.Prompt(
            name="onboarding_instructions",
            description="Initial prompt to guide users on connecting their GSuite account.",
            arguments=None
        )
    }

    @app.list_prompts()
    async def list_prompts() -> list[types.Prompt]:
        """Lists available prompts."""
        logger.info("list_prompts called")
        prompts_list = [
            types.Prompt(
                name=p.name,
                description=p.description,
                arguments=p.arguments
                )
                for p in AVAILABLE_PROMPTS.values()
            ]
        return prompts_list

    @app.get_prompt()
    async def get_prompt(id: str) -> types.Prompt | None:
        """Gets a specific prompt by ID."""
        return AVAILABLE_PROMPTS.get(id)
    ##-##

    ## ===== MCP RESOURCES ===== ##
    @app.list_resources()
    async def list_resources(user_id: str | None = None, oauth_state: str | None = None) -> list[types.Resource]: # Changed ResourceInfo to Resource
        """Lists available GSuite resources (placeholder)."""
        logger.info(f"list_resources called for user: {user_id}")
        # TODO: Implement actual resource listing
        resources_list = []
        return resources_list

    @app.read_resource()
    async def read_resource(uri: str, user_id: str | None = None, oauth_state: str | None = None) -> types.Resource | None: # Changed return type hint
        """Reads a specific GSuite resource by URI (placeholder)."""
        logger.info(f"read_resource called for URI: {uri}, user: {user_id}")
        # TODO: Implement actual resource reading
        return None
    ##-##

    return app # Return the configured app instance

## ===== MAIN EXECUTION ===== ##
async def main():
    # --- Argument Parsing ---
    # No user-specific arguments needed for multi-tenant server
    logger.info(f"mcp-google-workspace Server starting "
                 f"on platform: {sys.platform}")

    # --- Optional: Check accounts file exists on startup ---
    try:
        # Wrap synchronous file I/O call in to_thread
        accounts = await asyncio.to_thread(gauth.get_account_info)
        logger.info(f"Found configured accounts: {[acc.email for acc in accounts]}")
        # No user-specific checks needed at startup for multi-tenant server.
        # Credential checks happen per-tool-call based on user_id passed in args.
    except FileNotFoundError:
        logger.warning(f"Accounts configuration file ({gauth.get_accounts_file()}) "
                        f"not found. Authentication will likely fail until configured.")
    except Exception as e:
        logger.error(f"Error reading accounts configuration on startup: {e}",
                     exc_info=True) # Add exc_info

    # --- Create the app instance using the factory ---
    app = create_app()

    # --- Import stdio_server and NotificationOptions here ---
    from mcp.server.stdio import stdio_server
    from mcp.server.lowlevel.server import NotificationOptions # Import NotificationOptions

    async with stdio_server() as (read_stream, write_stream):
        # --- DEBUG: Check registered handlers before creating options ---
        print("--- DEBUG: Checking registered handlers ---", file=sys.stderr)
        print(f"types.ListToolsRequest in app.request_handlers: {types.ListToolsRequest in app.request_handlers}", file=sys.stderr)
        print(f"types.CallToolRequest in app.request_handlers: {types.CallToolRequest in app.request_handlers}", file=sys.stderr)
        print(f"types.ListPromptsRequest in app.request_handlers: {types.ListPromptsRequest in app.request_handlers}", file=sys.stderr)
        print(f"types.GetPromptRequest in app.request_handlers: {types.GetPromptRequest in app.request_handlers}", file=sys.stderr)
        print(f"types.ListResourcesRequest in app.request_handlers: {types.ListResourcesRequest in app.request_handlers}", file=sys.stderr)
        print(f"types.ReadResourceRequest in app.request_handlers: {types.ReadResourceRequest in app.request_handlers}", file=sys.stderr)
        print("--- DEBUG: Creating initialization options ---", file=sys.stderr)
        # ---
        # Explicitly create NotificationOptions
        notify_opts = NotificationOptions(
            prompts_changed=True,  # Set to True since list_prompts handler exists
            resources_changed=True, # Set to True since list_resources handler exists
            tools_changed=True     # Set to True since list_tools handler exists
        )
        init_options = app.create_initialization_options(notification_options=notify_opts) # Pass options
        # --- DEBUG: Print the generated options ---
        print(f"--- DEBUG: Generated init_options: {init_options!r} ---", file=sys.stderr)
        # ---
        await app.run(
            read_stream,
            write_stream,
            init_options
        )

##-##

#-#

# ===== ENTRY POINT ===== #
if __name__ == "__main__":
    asyncio.run(main())
#-#
