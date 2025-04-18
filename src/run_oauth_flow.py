import logging
import uuid
from mcp_gsuite import gauth

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# --- Configuration ---
TARGET_EMAIL = "circa@indepreneur.io"
# --- End Configuration ---

def run_auth_flow():
    """Runs the OAuth 2.0 flow to get new credentials with updated scopes."""
    try:
        # Generate a unique state value
        state = str(uuid.uuid4())

        # 1. Get the authorization URL
        auth_url = gauth.get_authorization_url(email_address=TARGET_EMAIL, state=state)
        logging.info(f"Generated authorization URL for {TARGET_EMAIL}")

        # 2. Prompt user to visit the URL and provide the code
        print("\n" + "="*60)
        print("Please visit the following URL in your browser to authorize the application:")
        print(f"\n{auth_url}\n")
        print("After authorization, you will be redirected to a page (likely showing an error, which is expected).")
        print("Copy the FULL URL from your browser's address bar.")
        print("Paste the FULL URL below:")
        print("="*60)

        redirect_url = input("Paste the full redirect URL here: ")

        # Extract the authorization code and verify state
        from urllib.parse import urlparse, parse_qs
        parsed_url = urlparse(redirect_url)
        query_params = parse_qs(parsed_url.query)

        if 'code' not in query_params:
            logging.error("Could not find 'code' parameter in the provided URL.")
            print("Authorization failed. Please ensure you copied the full redirect URL.")
            return

        if 'state' not in query_params or query_params['state'][0] != state:
            logging.error("State parameter mismatch. Potential security issue.")
            print("Authorization failed due to state mismatch.")
            return

        authorization_code = query_params['code'][0]
        logging.info("Received authorization code.")

        # 3. Exchange the code for credentials
        logging.info("Attempting to exchange authorization code for credentials...")
        credentials = gauth.get_credentials(authorization_code=authorization_code, state=state) # This also stores them

        if credentials:
            logging.info(f"Successfully obtained and stored new credentials for {TARGET_EMAIL}")
            print("\n" + "="*60)
            print("Re-authentication successful!")
            print(f"Credentials for {TARGET_EMAIL} have been updated with the new scopes.")
            print("You can now proceed with using the MCP server.")
            print("="*60)
        else:
            # This case might not be reached if get_credentials raises exceptions
            logging.error("Failed to obtain credentials after code exchange.")
            print("\nAuthorization failed during credential exchange.")

    except gauth.CodeExchangeException as e:
        logging.error(f"Code exchange failed: {e}")
        print("\nAuthorization failed during code exchange.")
        if e.authorization_url:
            print("You might need to retry the authorization process.")
    except gauth.NoRefreshTokenException as e:
        logging.error(f"No refresh token obtained: {e}")
        print("\nAuthorization failed: No refresh token was obtained. Ensure 'offline' access was granted.")
        if e.authorization_url:
            print("Please retry the authorization process using this URL:")
            print(e.authorization_url)
    except gauth.NoUserIdException:
        logging.error("Could not retrieve user ID after authentication.")
        print("\nAuthorization failed: Could not verify user identity.")
    except Exception as e:
        logging.exception(f"An unexpected error occurred during the authentication flow: {e}")
        print(f"\nAn unexpected error occurred: {e}")

if __name__ == "__main__":
    run_auth_flow()