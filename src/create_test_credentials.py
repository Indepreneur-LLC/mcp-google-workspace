# Script to initiate the Google OAuth2 flow and generate credentials.
# This is primarily for testing and development purposes.

import sys
import os
import logging
import traceback

# --- How to Generate/Update Test Credentials ---
#
# 1.  Define Scopes:
#     Ensure all required Google API scopes (e.g., Gmail, Calendar, Drive)
#     are listed in the `SCOPES` variable within `mcp_gsuite/gauth.py`.
#     Example Drive Scope: 'https://www.googleapis.com/auth/drive'
#
# 2.  Configure User:
#     Make sure the email address you want to authenticate (e.g., 'test.user@indepreneur.io')
#     is listed in the `config/.accounts.json` file.
#
# 3.  Clear Old Credentials (If Updating Scopes):
#     If you are adding new scopes or re-authenticating, delete the existing
#     credentials file for the user from the host machine's
#     `./mcp-servers/mcp-gsuite/credentials/` directory.
#     Example: `rm ./mcp-servers/mcp-gsuite/credentials/.oauth2.test.user@indepreneur.io.json`
#     The volume mount ensures this is reflected in the container.
#
# 4.  Run This Script:
#     Execute this script inside the running mcp-gsuite container using docker-compose:
#     `dc exec mcp-gsuite python /app/src/create_test_credentials.py`
#     (Note: Ensure this script is present inside the container at `/app/src/`
#     or adjust the path. If using source volume mounts, it should be there).
#
# 5.  Authenticate in Browser:
#     The script will output an `AUTH_REQUIRED:<URL>` line. Copy the entire URL
#     and paste it into your web browser.
#
# 6.  Log In & Grant Permissions:
#     Log in to Google using the email address specified in step 2.
#     Carefully review and grant the permissions requested by the application.
#     Ensure you approve any *new* scopes you added (like Drive).
#
# 7.  Callback & Verification:
#     Google will redirect you back to the configured callback URL
#     (e.g., https://server.indepreneur.io/mcp/oauth/callback).
#     You should see a success message.
#     A new credentials file (`.oauth2.<user_email>.json`) will be created in
#     `./mcp-servers/mcp-gsuite/credentials/` on the host machine, containing
#     the necessary tokens with the approved scopes.
#
# --- End Instructions ---

# Add src directory to Python path to find modules if running directly
# (May not be strictly necessary if run via `python -m` or if PYTHONPATH is set)
# sys.path.append('/app/src') # Let's try without this first, might not be needed with docker exec

try:
    # Import necessary modules AFTER potentially modifying sys.path
    from mcp_gsuite import server, gauth

    # Configure logging (optional but helpful)
    logging.basicConfig(level=logging.INFO)
    logger = logging.getLogger("create_test_credentials")

    # --- Specify the user email to generate credentials for ---
    user_id_to_test = 'circa@indepreneur.io'
    # ---

    logger.info(f"Attempting OAuth setup for: {user_id_to_test}")

    # Ensure credentials directory exists (should be handled by volume mount, but good practice)
    creds_dir = gauth.get_credentials_dir()
    os.makedirs(creds_dir, exist_ok=True)
    logger.info(f"Ensuring credentials directory exists: {creds_dir}")

    # Call the setup function - this will check existing creds or trigger the flow
    server.setup_oauth2(user_id_to_test)
    # If setup_oauth2 completes without raising AuthorizationRequired,
    # it means valid credentials already exist or were refreshed.
    print(f"Credentials for {user_id_to_test} are likely OK or were refreshed.")
    print("If you intended to force re-authentication (e.g., for new scopes),")
    print(f"ensure you deleted the existing file: {creds_dir}.oauth2.{user_id_to_test}.json")


except server.AuthorizationRequired as e:
    # This is the expected outcome if credentials are not present or need re-auth
    print("\n--- AUTHORIZATION REQUIRED ---")
    print("Visit the following URL in your browser:")
    print(e.auth_url)
    print("------------------------------\n")

except Exception as e:
    # Catch any other unexpected errors
    print(f'\n--- ERROR ---')
    print(f'An unexpected error occurred: {e}')
    print(traceback.format_exc())
    print(f'-------------')