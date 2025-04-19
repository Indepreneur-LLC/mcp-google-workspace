# ===== IMPORTS ===== #

## ===== STANDARD LIBRARY ===== ##
from __future__ import annotations
import logging
# import traceback # Removed unused import
from dotenv import load_dotenv
import sys
import argparse
import json
import asyncio
##-##

## ===== THIRD PARTY ===== ##
from mcp.server import Server
from mcp.types import (
    Tool,
    TextContent,
    ImageContent,
    EmbeddedResource,
    Prompt,
    PromptInfo,
    Resource,
    ResourceInfo,
)
##-##

## ===== LOCAL ===== ##
from . import gauth
from . import tools_gmail
from . import tools_calendar
from . import tools_drive
##-##

#-#

# ===== GLOBALS ===== #

## ===== CONFIGURATION ===== ##
load_dotenv() # Load environment variables from .env file
##-##

## ===== LOGGING ===== ##
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("mcp-gsuite")
##-##

## ===== STATE ===== ##
GLOBAL_USER_ID: str | None = None # Global variable to store the user ID for this instance
##-##

#-#

# ===== CLASSES ===== #
# (No classes defined in this file currently)
#-#

# ===== FUNCTIONS ===== #

## ===== MCP HANDLERS ===== ##
app = Server("mcp-gsuite") # Initialize MCP Server

# Note: Tool registration (@app.tool) is handled within tools_*.py files.
# Note: Tool listing (@app.list_tools) is handled automatically by MCP.
# Note: Tool calling (@app.call_tool) is handled automatically by MCP.
## ===== MCP PROMPTS ===== ##
# Define available prompts (can be loaded from YAML later)
AVAILABLE_PROMPTS = {
    "onboarding": Prompt(
        id="onboarding",
        title="GSuite Onboarding",
        description="Initial prompt to guide users on connecting their GSuite account.",
        template=(
            "Welcome to the GSuite MCP! To get started, I need access to your Google Account. "
            "Please tell me your Google email address so I can check if I already have "
            "credentials stored."
        )
    ),
    "check_calendar": Prompt(
        id="check_calendar",
        title="Check Calendar Events",
        description="Prompt for checking upcoming calendar events.",
        template=(
            "Sure, I can check your calendar. For which email address should I check? "
            "And for what time range (e.g., 'today', 'next 3 days', or specific dates)?"
        )
    )
}

@app.list_prompts()
async def list_prompts() -> list[PromptInfo]:
    """Lists available prompts."""
    return [
        PromptInfo(id=p.id, title=p.title, description=p.description)
        for p in AVAILABLE_PROMPTS.values()
    ]

@app.get_prompt()
async def get_prompt(id: str) -> Prompt | None:
    """Gets a specific prompt by ID."""
    return AVAILABLE_PROMPTS.get(id)

##-##

## ===== MCP RESOURCES ===== ##
@app.list_resources()
async def list_resources(user_id: str | None = None, oauth_state: str | None = None) -> list[ResourceInfo]:
    """Lists available GSuite resources (placeholder)."""
    logger.info(f"list_resources called for user: {user_id}")
    # TODO: Implement actual resource listing
    return []

@app.read_resource()
async def read_resource(uri: str, user_id: str | None = None, oauth_state: str | None = None) -> Resource | None:
    """Reads a specific GSuite resource by URI (placeholder)."""
    logger.info(f"read_resource called for URI: {uri}, user: {user_id}")
    # TODO: Implement actual resource reading
    return None



##-##

## ===== MAIN EXECUTION ===== ##
async def main():
    # --- Argument Parsing ---
    parser = argparse.ArgumentParser(description="MCP GSuite Server")
    parser.add_argument(
        "--user-id",
        type=str,
        required=True, # Make user_id mandatory for the server instance
        help="The primary user ID (email) this server instance will handle."
    )
    # Allow unknown args for potential future MCP framework args
    args, _ = parser.parse_known_args()
    user_id = args.user_id

    # Set the global user ID for this server instance
    global GLOBAL_USER_ID
    GLOBAL_USER_ID = user_id

    logger.info(f"MCP-GSuite Server starting for user: {GLOBAL_USER_ID} "
                f"on platform: {sys.platform}")

    # --- Optional: Check configured accounts on startup (using to_thread) ---
    try:
        # Wrap synchronous file I/O call in to_thread
        accounts = await asyncio.to_thread(gauth.get_account_info)
        logger.info(f"Found configured accounts: {[acc.email for acc in accounts]}")
        # Check if the provided GLOBAL_USER_ID matches one of the configured accounts (optional validation)
        if GLOBAL_USER_ID not in [acc.email for acc in accounts]:
            logger.warning(f"Provided user_id '{GLOBAL_USER_ID}' not found in "
                           f"configured accounts file.")
        else:
            logger.info(f"Provided user_id '{GLOBAL_USER_ID}' matches a "
                        f"configured account.")
        # Note: No credential check here anymore. Credential checks happen per-tool-call.
    except FileNotFoundError:
        logger.warning(f"Accounts configuration file ({gauth.get_accounts_file()}) "
                       f"not found. Cannot verify user_id against configuration.")
    except Exception as e:
        logger.error(f"Error reading accounts configuration on startup: {e}",
                     exc_info=True) # Add exc_info
    from mcp.server.stdio import stdio_server

    async with stdio_server() as (read_stream, write_stream):
        await app.run(
            read_stream,
            write_stream,
            app.create_initialization_options()
        )

##-##


#-#
if __name__ == "__main__":
    asyncio.run(main())
