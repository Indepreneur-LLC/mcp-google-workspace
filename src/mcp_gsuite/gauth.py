# ===== IMPORTS ===== #

## ===== STANDARD LIBRARY ===== ##
import argparse
import logging
import json
import os
##-##

## ===== THIRD-PARTY ===== ##
### ----- GOOGLE TRASH ----- ###
from google.oauth2.credentials import Credentials as GoogleCredentials
from google.auth.transport.requests import Request as GoogleAuthRequest
from google.auth.exceptions import RefreshError
from googleapiclient.errors import HttpError
from googleapiclient.discovery import build
from google_auth_oauthlib.flow import Flow
###-###
import requests
import pydantic
import redis
##-##

## ===== LOCAL ===== ##
##-##

#-#

# ===== GLOBALS ===== #

## ===== CONSTANTS ===== ##

### ----- SECRETS PREP ----- ###
parser = argparse.ArgumentParser()
parser.add_argument(
    "--gauth-file",
    type=str,
    default="/app/config/.gauth.json",
    help="Path to client secrets file",
)
args, _ = parser.parse_known_args()
###-###
CLIENTSECRETS_LOCATION = args.gauth_file

REDIRECT_URI = 'https://server.indepreneur.io/mcp/oauth/callback' # Updated based on Nginx setup
SCOPES = [
    "openid",
    "https://www.googleapis.com/auth/userinfo.email",
    "https://mail.google.com/",
    "https://www.googleapis.com/auth/calendar",
    "https://www.googleapis.com/auth/drive"  # Added full Drive scope
]

REDIS_HOST = os.environ.get("REDIS_MASTER_HOST", "redis-master")
REDIS_PORT = 6379
REDIS_CHANNEL = "gsuite_auth_success"
##-##

## ===== CLIENTS ===== ##
try:
    redis_pubsub_client = redis.Redis(host=REDIS_HOST, port=REDIS_PORT, decode_responses=True)
    redis_pubsub_client.ping()
    logging.info(f"[gauth] Connected to Redis for Pub/Sub at {REDIS_HOST}:{REDIS_PORT}")
except redis.exceptions.ConnectionError as e:
    logging.error(f"[gauth] FATAL: Could not connect to Redis for Pub/Sub at {REDIS_HOST}:{REDIS_PORT}. Notifications will fail. Error: {e}")
    redis_pubsub_client = None
##-##

#-#

# ===== FUNCTIONS ===== #
def notify_aggregator_success(state: str):
    """Publishes the validated state to the Redis channel."""
    if not redis_pubsub_client:
        logging.error(f"[gauth] Cannot notify aggregator: Redis client not connected.")
        return
    if not state:
        logging.warning(f"[gauth] Cannot notify aggregator: state parameter is missing.")
        return
    try:
        message = json.dumps({"status": "success", "state": state})
        redis_pubsub_client.publish(REDIS_CHANNEL, message)
        logging.info(f"[gauth] Published state '{state}' to Redis channel '{REDIS_CHANNEL}'.")
    except Exception as e:
        logging.error(f"[gauth] Failed to publish state '{state}' to Redis channel '{REDIS_CHANNEL}': {e}")
#-#


class AccountInfo(pydantic.BaseModel):

    email: str
    account_type: str
    extra_info: str

    def __init__(self, email: str, account_type: str, extra_info: str = ""):
        super().__init__(email=email, account_type=account_type, extra_info=extra_info)

    def to_description(self):
        return f"""Account for email: {self.email} of type: {self.account_type}. Extra info for: {self.extra_info}"""


def get_accounts_file() -> str:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--accounts-file",
        type=str,
        default="/app/config/.accounts.json",
        help="Path to accounts configuration file",
    )
    args, _ = parser.parse_known_args()
    return args.accounts_file


def get_account_info() -> list[AccountInfo]:
    accounts_file = get_accounts_file()
    with open(accounts_file) as f:
        data = json.load(f)
        accounts = data.get("accounts", [])
        return [AccountInfo.model_validate(acc) for acc in accounts]

# Removed unused exception classes: GetCredentialsException, CodeExchangeException, NoRefreshTokenException, NoUserIdException
# Add new exception for auth failure
class AuthenticationError(Exception):
    """Custom exception for failure to authenticate using stored credentials."""
    pass

# --- Redis Client for Credential Storage ---
_redis_cred_client = None

def _get_redis_client():
    """Initializes and returns the Redis client for credential storage."""
    global _redis_cred_client
    if _redis_cred_client is None:
        try:
            _redis_cred_client = redis.Redis(host=REDIS_HOST, port=REDIS_PORT, decode_responses=True)
            _redis_cred_client.ping()
            logging.info(f"[gauth] Connected to Redis for Credential Storage at {REDIS_HOST}:{REDIS_PORT}")
        except redis.exceptions.ConnectionError as e:
            logging.error(f"[gauth] FATAL: Could not connect to Redis for Credential Storage at {REDIS_HOST}:{REDIS_PORT}. Error: {e}")
            _redis_cred_client = None # Ensure it stays None if connection fails
    return _redis_cred_client

def _get_redis_key_for_token(user_id: str) -> str:
    """Generates the Redis key for storing a user's refresh token."""
    return f"gsuite:refresh_token:{user_id}"

def store_refresh_token_in_redis(user_id: str, refresh_token: str):
    """Stores the user's refresh token securely in Redis."""
    redis_client = _get_redis_client()
    if not redis_client:
        logging.error(f"[gauth] Cannot store refresh token for {user_id}: Redis client not connected.")
        return
    try:
        key = _get_redis_key_for_token(user_id)
        redis_client.set(key, refresh_token)
        logging.info(f"[gauth] Stored refresh token for user {user_id} in Redis.")
    except Exception as e:
        logging.error(f"[gauth] Failed to store refresh token for user {user_id} in Redis: {e}")

def _get_refresh_token_from_redis(user_id: str) -> str | None:
    """Retrieves the user's refresh token from Redis."""
    redis_client = _get_redis_client()
    if not redis_client:
        logging.error(f"[gauth] Cannot retrieve refresh token for {user_id}: Redis client not connected.")
        return None
    try:
        key = _get_redis_key_for_token(user_id)
        token = redis_client.get(key)
        if token:
            logging.debug(f"[gauth] Retrieved refresh token for user {user_id} from Redis.")
            return token
        else:
            logging.warning(f"[gauth] No refresh token found in Redis for user {user_id}.")
            return None
    except Exception as e:
        logging.error(f"[gauth] Failed to retrieve refresh token for user {user_id} from Redis: {e}")
        return None

def get_credentials_for_user(user_id: str) -> GoogleCredentials | None:
    """
    Retrieves the stored refresh token for a user from Redis and constructs
    a Credentials object. Handles automatic refresh.

    Args:
        user_id: The unique identifier for the user (e.g., email).

    Returns:
        A valid GoogleCredentials object if a refresh token is found, otherwise None.
    """
    refresh_token = _get_refresh_token_from_redis(user_id)
    if not refresh_token:
        return None

    try:
        # Load client secrets to get client_id and client_secret
        with open(CLIENTSECRETS_LOCATION, 'r') as f:
            client_config = json.load(f).get('web', {})
            client_id = client_config.get('client_id')
            client_secret = client_config.get('client_secret')

        if not client_id or not client_secret:
            logging.error(f"[gauth] Missing client_id or client_secret in {CLIENTSECRETS_LOCATION}")
            return None

        credentials = GoogleCredentials(
            token=None, # Access token will be fetched on demand
            refresh_token=refresh_token,
            token_uri='https://oauth2.googleapis.com/token',
            client_id=client_id,
            client_secret=client_secret,
            scopes=SCOPES
        )

        # Check if token needs refreshing and refresh it.
        # The Credentials object handles this implicitly when used, but we can
        # force a check/refresh here if needed, though it might block.
        # For now, let's rely on the auto-refresh mechanism.
        # try:
        #     if not credentials.valid:
        #         logging.info(f"[gauth] Credentials for {user_id} require refresh.")
        #         credentials.refresh(GoogleAuthRequest())
        #         logging.info(f"[gauth] Credentials for {user_id} refreshed successfully.")
        #         # Note: The new refresh token (if any) is handled internally by the Credentials object.
        #         # We don't need to explicitly re-store it unless the original one was revoked.
        # except RefreshError as e:
        #     logging.error(f"[gauth] Failed to refresh credentials for user {user_id}: {e}. User may need to re-authenticate.")
        #     # Consider deleting the invalid refresh token from Redis here?
        #     # delete_refresh_token_from_redis(user_id)
        #     return None # Indicate failure
        # except Exception as e:
        #      logging.error(f"[gauth] Unexpected error during credential refresh check for {user_id}: {e}")
        #      return None

        logging.info(f"[gauth] Successfully created credentials object for user {user_id} using stored refresh token.")
        return credentials

    except FileNotFoundError:
        logging.error(f"[gauth] Client secrets file not found at {CLIENTSECRETS_LOCATION}")
        return None
    except Exception as e:
        logging.error(f"[gauth] Error creating credentials for user {user_id}: {e}")
        return None

# --- New OAuth Flow Functions ---

def get_auth_url(state: str) -> str | None:
    """Generates the Google OAuth 2.0 authorization URL."""
    try:
        flow = Flow.from_client_secrets_file(
            CLIENTSECRETS_LOCATION,
            scopes=SCOPES,
            redirect_uri=REDIRECT_URI
        )
        # Indicate that the server needs offline access to receive a refresh token
        authorization_url, generated_state = flow.authorization_url(
            access_type='offline',
            prompt='consent', # Force consent screen to ensure refresh token is granted
            state=state # Pass the provided state
        )
        logging.info(f"[gauth] Generated authorization URL with state: {state}")
        return authorization_url
    except FileNotFoundError:
        logging.error(f"[gauth] Client secrets file not found at {CLIENTSECRETS_LOCATION}")
        return None
    except Exception as e:
        logging.error(f"[gauth] Failed to generate authorization URL: {e}")
        return None

def exchange_code(state: str, code: str, user_id_hint: str | None = None) -> GoogleCredentials | None:
    """
    Exchanges the authorization code for credentials (including refresh token)
    and stores the refresh token in Redis.

    Args:
        state: The state parameter received from the callback, used for validation.
        code: The authorization code received from the callback.
        user_id_hint: An optional hint (like email) to associate the token with.
                      The actual user ID will be fetched from the token response.

    Returns:
        The obtained GoogleCredentials object, or None on failure.
    """
    try:
        flow = Flow.from_client_secrets_file(
            CLIENTSECRETS_LOCATION,
            scopes=SCOPES,
            redirect_uri=REDIRECT_URI,
            state=state # Pass state for validation during token fetch
        )

        logging.info(f"[gauth] Exchanging authorization code for state: {state}")
        flow.fetch_token(code=code)

        credentials = flow.credentials
        if not credentials:
            logging.error(f"[gauth] Failed to fetch token: Credentials object is None.")
            return None

        if not credentials.refresh_token:
            logging.error(f"[gauth] Failed to obtain refresh token. User might not have granted offline access.")
            # This is a critical failure for long-term access.
            return None # Indicate failure

        # --- Get User ID (Email) from Credentials --- 
        # We need the user's email to use as the primary key in Redis.
        # We can get this by making a call to the userinfo endpoint.
        user_info = get_user_info(credentials)
        if not user_info or 'email' not in user_info:
            logging.error(f"[gauth] Failed to retrieve user email after exchanging code. Cannot store refresh token.")
            # If we have a hint, maybe use that? Risky if hint is wrong.
            if user_id_hint:
                 logging.warning(f"[gauth] Attempting to use provided user_id_hint '{user_id_hint}' for storage.")
                 user_id = user_id_hint
            else:
                 return None # Cannot proceed without a user ID
        else:
            user_id = user_info['email']
            logging.info(f"[gauth] Successfully retrieved user email: {user_id}")

        # --- Store Refresh Token --- 
        store_refresh_token_in_redis(user_id, credentials.refresh_token)

        # Notify aggregator (using the original state passed in)
        notify_aggregator_success(state)

        logging.info(f"[gauth] Successfully exchanged code, stored refresh token for {user_id}, and notified aggregator.")
        return credentials

    except FileNotFoundError:
        logging.error(f"[gauth] Client secrets file not found at {CLIENTSECRETS_LOCATION}")
        return None
    except Exception as e:
        # Includes potential errors during flow.fetch_token (e.g., invalid code, state mismatch)
        logging.error(f"[gauth] Failed to exchange authorization code: {e}")
        return None

def get_user_info(credentials: GoogleCredentials) -> dict | None:
    """Fetches user information (like email) using the provided credentials."""
    try:
        # Use the google-auth library's transport mechanism if possible
        authed_session = GoogleAuthRequest()
        credentials.refresh(authed_session) # Ensure credentials are valid

        # Use the authorized session to make the request to the userinfo endpoint
        userinfo_response = requests.get(
            'https://www.googleapis.com/oauth2/v3/userinfo',
            headers={'Authorization': f'Bearer {credentials.token}'}
        )
        userinfo_response.raise_for_status() # Raise HTTPError for bad responses (4xx or 5xx)
        user_info = userinfo_response.json()
        logging.debug(f"[gauth] Fetched user info: {user_info}")
        return user_info
    except RefreshError as e:
        logging.error(f"[gauth] Failed to refresh credentials before fetching user info: {e}")
        return None
    except requests.exceptions.RequestException as e:
        logging.error(f"[gauth] Failed to fetch user info: {e}")
        return None
    except Exception as e:
        logging.error(f"[gauth] An unexpected error occurred while fetching user info: {e}")
        return None

# --- Service Client Creation ---

def get_google_service(service_name: str, version: str, user_id: str):
    """
    Builds and returns a Google API service client using credentials retrieved for the user.

    Args:
        service_name: The name of the Google API service (e.g., 'gmail', 'calendar', 'drive').
        version: The version of the API service (e.g., 'v1', 'v3').
        user_id: The user ID (email) to retrieve credentials for.

    Returns:
        An authorized Google API service client object, or None if authentication fails.
    """
    credentials = get_credentials_for_user(user_id)
    if not credentials:
        logging.error(f"[gauth] Could not get credentials for user {user_id} to build '{service_name}' service.")
        return None

    try:
        service = build(service_name, version, credentials=credentials, cache_discovery=False) # Disable discovery cache
        logging.info(f"[gauth] Successfully built '{service_name}' service client for user {user_id}.")
        return service
    except HttpError as error:
        logging.error(f"[gauth] An API error occurred building '{service_name}' service for {user_id}: {error}")
        # Check if it's an auth error (e.g., token revoked)
        if error.resp.status in [401, 403]:
             logging.warning(f"[gauth] Authentication error for {user_id}. Refresh token might be invalid. User may need to re-authenticate.")
             # Consider deleting the potentially invalid refresh token
             # delete_refresh_token_from_redis(user_id)
        return None
    except Exception as e:
        logging.error(f"[gauth] An unexpected error occurred building '{service_name}' service for {user_id}: {e}")
        return None


# Removed get_credentials_dir and _get_credential_filename (using Redis now)
# Removed get_authenticated_credentials and store_refreshed_credentials (using Redis now)
# Removed unused functions placeholders as they will be re-added with new logic
