"""Google authentication using service account with domain-wide delegation."""

import os
import logging
from google.oauth2 import service_account
from googleapiclient.discovery import build
from googleapiclient.errors import HttpError

logger = logging.getLogger(__name__)

# Service account key path from environment
SERVICE_ACCOUNT_KEY = os.environ.get("GOOGLE_SERVICE_ACCOUNT_KEY", "/app/secrets/oauth-bot-key.json")

# Required scopes for all APIs
SCOPES = [
    "https://mail.google.com/",
    "https://www.googleapis.com/auth/calendar", 
    "https://www.googleapis.com/auth/drive"
]

def get_google_service(service_name: str, version: str, user_email: str):
    """
    Build a Google API service using service account with domain-wide delegation.
    
    Args:
        service_name: The API name ('gmail', 'calendar', 'drive')
        version: API version ('v1' for gmail, 'v3' for calendar/drive)
        user_email: The @indepreneur.io email to impersonate
        
    Returns:
        Authenticated Google API service client
    """
    try:
        # Load service account credentials
        credentials = service_account.Credentials.from_service_account_file(
            SERVICE_ACCOUNT_KEY,
            scopes=SCOPES
        )
        
        # Impersonate the user
        delegated_credentials = credentials.with_subject(user_email)
        
        # Build and return the service
        service = build(service_name, version, credentials=delegated_credentials, cache_discovery=False)
        logger.info(f"Built {service_name} service for {user_email}")
        return service
        
    except FileNotFoundError:
        logger.error(f"Service account key not found at {SERVICE_ACCOUNT_KEY}")
        raise
    except Exception as e:
        logger.error(f"Failed to build {service_name} service for {user_email}: {e}")
        raise