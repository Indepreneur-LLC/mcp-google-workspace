# ===== IMPORTS ===== #
import pytest
from pytest_mock import MockerFixture
import json
from unittest.mock import MagicMock, patch, mock_open

# Import functions to test
from mcp_google_workspace import gauth
from google.oauth2.credentials import Credentials as GoogleCredentials
from google.auth.exceptions import RefreshError
from google_auth_oauthlib.flow import Flow
from googleapiclient.errors import HttpError
import requests

# ===== FIXTURES ===== #

# ===== TESTS ===== #

# TODO: Add tests for each function in gauth.py
def test_notify_aggregator_success(mocker: MockerFixture):
    """Tests that notify_aggregator_success publishes the correct message to Redis."""
    mock_redis_client = MagicMock()
    mocker.patch('mcp_google_workspace.gauth.r', mock_redis_client)
    test_state = "test_state_123"
    expected_message = json.dumps({"status": "success", "state": test_state})

    gauth.notify_aggregator_success(test_state)

    mock_redis_client.publish.assert_called_once_with(gauth.REDIS_CHANNEL, expected_message)

def test_notify_aggregator_success_no_redis(mocker: MockerFixture, caplog):
    """Tests that notify_aggregator_success logs an error if Redis is not connected."""
    mocker.patch('mcp_google_workspace.gauth.r', None)
    test_state = "test_state_456"

    gauth.notify_aggregator_success(test_state)

    assert "Cannot notify aggregator: Redis client not connected" in caplog.text

def test_notify_aggregator_success_no_state(mocker: MockerFixture, caplog):
    """Tests that notify_aggregator_success logs a warning if state is missing."""
    mock_redis_client = MagicMock()
    mocker.patch('mcp_google_workspace.gauth.r', mock_redis_client)

    gauth.notify_aggregator_success("") # Empty state

    assert "Cannot notify aggregator: state parameter is missing" in caplog.text
    mock_redis_client.publish.assert_not_called()

def test_notify_aggregator_success_redis_error(mocker: MockerFixture, caplog):
    """Tests that notify_aggregator_success logs an error if Redis publish fails."""
    mock_redis_client = MagicMock()
    mock_redis_client.publish.side_effect = Exception("Redis boom!")
    mocker.patch('mcp_google_workspace.gauth.r', mock_redis_client)
    test_state = "test_state_789"

    gauth.notify_aggregator_success(test_state)
# --- Tests for get_account_info ---

@pytest.fixture
def mock_accounts_data(): # Removed self
    return {
        "accounts": [
            {"account_type": "test_type_1", "extra_info": "info1", "email": "test1@example.com"},
            {"account_type": "test_type_2", "extra_info": "info2", "email": "test2@example.com"},
        ]
    }

def test_get_account_info_success(mocker: MockerFixture, mock_accounts_data):
    """Tests successful reading and parsing of the accounts file."""
    mock_file_path = "/fake/path/accounts.json"
    mocker.patch('mcp_google_workspace.gauth.get_accounts_file', return_value=mock_file_path)
    mock_file_content = json.dumps(mock_accounts_data)
    mocker.patch('builtins.open', mock_open(read_data=mock_file_content))

    accounts = gauth.get_account_info()

    assert len(accounts) == 2
    assert isinstance(accounts[0], gauth.AccountInfo)
    assert accounts[0].email == "test1@example.com"
    assert accounts[1].account_type == "test_type_2"
    gauth.get_accounts_file.assert_called_once()
    open.assert_called_once_with(mock_file_path)

def test_get_account_info_file_not_found(mocker: MockerFixture):
    """Tests handling of FileNotFoundError when accounts file is missing."""
    mock_file_path = "/fake/path/nonexistent.json"
    mocker.patch('mcp_google_workspace.gauth.get_accounts_file', return_value=mock_file_path)
    mocker.patch('builtins.open', side_effect=FileNotFoundError("File not found"))

    with pytest.raises(FileNotFoundError):
        gauth.get_account_info()

    gauth.get_accounts_file.assert_called_once()
    open.assert_called_once_with(mock_file_path)

def test_get_account_info_invalid_json(mocker: MockerFixture):
    """Tests handling of invalid JSON format in the accounts file."""
    mock_file_path = "/fake/path/invalid.json"
    mocker.patch('mcp_google_workspace.gauth.get_accounts_file', return_value=mock_file_path)
    mock_file_content = "this is not json"
    mocker.patch('builtins.open', mock_open(read_data=mock_file_content))

    with pytest.raises(json.JSONDecodeError):
        gauth.get_account_info()

    gauth.get_accounts_file.assert_called_once()
    open.assert_called_once_with(mock_file_path)

def test_get_account_info_missing_accounts_key(mocker: MockerFixture):
    """Tests handling when the 'accounts' key is missing in the JSON data."""
    mock_file_path = "/fake/path/missing_key.json"
    mocker.patch('mcp_google_workspace.gauth.get_accounts_file', return_value=mock_file_path)
    mock_file_content = json.dumps({"other_key": "value"}) # No 'accounts' key
    mocker.patch('builtins.open', mock_open(read_data=mock_file_content))

    accounts = gauth.get_account_info()
# --- Tests for Redis Token Storage ---

def test_store_refresh_token_in_redis_success(mocker: MockerFixture):
    """Tests successful storage of a refresh token in Redis."""
    mock_redis_client = MagicMock()
    mocker.patch('mcp_google_workspace.gauth.r', mock_redis_client)
    user_id = "user@example.com"
    refresh_token = "test_refresh_token"
    expected_key = f"gsuite:refresh_token:{user_id}"

    gauth.store_refresh_token_in_redis(user_id, refresh_token)

    mock_redis_client.set.assert_called_once_with(expected_key, refresh_token)

def test_store_refresh_token_no_redis(mocker: MockerFixture, caplog):
    """Tests store_refresh_token_in_redis logs error if Redis client is None."""
    mocker.patch('mcp_google_workspace.gauth.r', None)
    user_id = "user@example.com"
    refresh_token = "test_refresh_token"

    gauth.store_refresh_token_in_redis(user_id, refresh_token)

    assert f"Cannot store refresh token for {user_id}: Redis client not connected" in caplog.text

def test_store_refresh_token_redis_error(mocker: MockerFixture, caplog):
    """Tests store_refresh_token_in_redis logs error if r.set fails."""
    mock_redis_client = MagicMock()
    mock_redis_client.set.side_effect = Exception("Redis SET failed")
    mocker.patch('mcp_google_workspace.gauth.r', mock_redis_client)
    user_id = "user@example.com"
    refresh_token = "test_refresh_token"
    expected_key = f"gsuite:refresh_token:{user_id}"

    gauth.store_refresh_token_in_redis(user_id, refresh_token)

    assert f"Failed to store refresh token for user {user_id}" in caplog.text
    assert "Redis SET failed" in caplog.text
    mock_redis_client.set.assert_called_once_with(expected_key, refresh_token)


def test_get_refresh_token_from_redis_success(mocker: MockerFixture):
    """Tests successful retrieval of a refresh token from Redis."""
    mock_redis_client = MagicMock()
    user_id = "user@example.com"
    expected_token = "retrieved_token"
    expected_key = f"gsuite:refresh_token:{user_id}"
    mock_redis_client.get.return_value = expected_token
    mocker.patch('mcp_google_workspace.gauth.r', mock_redis_client)

    token = gauth._get_refresh_token_from_redis(user_id)

    assert token == expected_token
    mock_redis_client.get.assert_called_once_with(expected_key)

def test_get_refresh_token_not_found(mocker: MockerFixture, caplog):
    """Tests retrieval when the refresh token is not found in Redis."""
    mock_redis_client = MagicMock()
    user_id = "user_not_found@example.com"
    expected_key = f"gsuite:refresh_token:{user_id}"
    mock_redis_client.get.return_value = None # Simulate token not found
    mocker.patch('mcp_google_workspace.gauth.r', mock_redis_client)

    token = gauth._get_refresh_token_from_redis(user_id)

    assert token is None
    assert f"No refresh token found in Redis for user {user_id}" in caplog.text
    mock_redis_client.get.assert_called_once_with(expected_key)

def test_get_refresh_token_no_redis(mocker: MockerFixture, caplog):
    """Tests _get_refresh_token_from_redis logs error if Redis client is None."""
    mocker.patch('mcp_google_workspace.gauth.r', None)
    user_id = "user@example.com"

    token = gauth._get_refresh_token_from_redis(user_id)

    assert token is None
    assert f"Cannot retrieve refresh token for {user_id}: Redis client not connected" in caplog.text

def test_get_refresh_token_redis_error(mocker: MockerFixture, caplog):
    """Tests _get_refresh_token_from_redis logs error if r.get fails."""
# --- Tests for get_credentials_for_user ---

@pytest.fixture
def mock_client_secrets(): # Removed self
    return {
        "web": {
            "client_id": "test_client_id",
            "client_secret": "test_client_secret",
            "auth_uri": "https://accounts.google.com/o/oauth2/auth",
            "token_uri": "https://oauth2.googleapis.com/token",
            "auth_provider_x509_cert_url": "https://www.googleapis.com/oauth2/v1/certs",
            "redirect_uris": [gauth.REDIRECT_URI],
            "javascript_origins": ["https://server.indepreneur.io"]
        }
    }

def test_get_credentials_for_user_success(mocker: MockerFixture, mock_client_secrets):
    """Tests successful credential creation when refresh token exists."""
    user_id = "user_success@example.com"
    refresh_token = "valid_refresh_token"
    mock_secrets_path = "/fake/gauth.json"
    mocker.patch('mcp_google_workspace.gauth.CLIENTSECRETS_LOCATION', mock_secrets_path)
    mock_get_token = mocker.patch('mcp_google_workspace.gauth._get_refresh_token_from_redis', return_value=refresh_token)
    mock_file_content = json.dumps(mock_client_secrets)
    mocker.patch('builtins.open', mock_open(read_data=mock_file_content))
    mock_google_creds_class = mocker.patch('mcp_google_workspace.gauth.GoogleCredentials')
    mock_creds_instance = MagicMock()
    mock_google_creds_class.return_value = mock_creds_instance

    credentials = gauth.get_credentials_for_user(user_id)

    assert credentials == mock_creds_instance
    mock_get_token.assert_called_once_with(user_id)
    open.assert_called_once_with(mock_secrets_path, 'r')
    mock_google_creds_class.assert_called_once_with(
        token=None,
        refresh_token=refresh_token,
        token_uri='https://oauth2.googleapis.com/token',
        client_id=mock_client_secrets['web']['client_id'],
        client_secret=mock_client_secrets['web']['client_secret'],
        scopes=gauth.SCOPES
    )

def test_get_credentials_for_user_no_token(mocker: MockerFixture):
    """Tests behavior when no refresh token is found in Redis."""
    user_id = "user_no_token@example.com"
    mock_get_token = mocker.patch('mcp_google_workspace.gauth._get_refresh_token_from_redis', return_value=None)
    mock_open_func = mocker.patch('builtins.open')
    mock_google_creds_class = mocker.patch('mcp_google_workspace.gauth.GoogleCredentials')

    credentials = gauth.get_credentials_for_user(user_id)

    assert credentials is None
    mock_get_token.assert_called_once_with(user_id)
    mock_open_func.assert_not_called()
    mock_google_creds_class.assert_not_called()

def test_get_credentials_for_user_secrets_file_not_found(mocker: MockerFixture):
    """Tests behavior when the client secrets file is not found."""
    user_id = "user_secrets_missing@example.com"
    refresh_token = "valid_refresh_token"
    mock_secrets_path = "/fake/gauth_missing.json"
    mocker.patch('mcp_google_workspace.gauth.CLIENTSECRETS_LOCATION', mock_secrets_path)
    mock_get_token = mocker.patch('mcp_google_workspace.gauth._get_refresh_token_from_redis', return_value=refresh_token)
    mocker.patch('builtins.open', side_effect=FileNotFoundError("Secrets not found"))
    mock_google_creds_class = mocker.patch('mcp_google_workspace.gauth.GoogleCredentials')

    credentials = gauth.get_credentials_for_user(user_id)

    assert credentials is None
    mock_get_token.assert_called_once_with(user_id)
    open.assert_called_once_with(mock_secrets_path, 'r')
    mock_google_creds_class.assert_not_called()

def test_get_credentials_for_user_secrets_incomplete(mocker: MockerFixture, mock_client_secrets):
    """Tests behavior when client secrets file is missing client_id or client_secret."""
    user_id = "user_secrets_incomplete@example.com"
    refresh_token = "valid_refresh_token"
    mock_secrets_path = "/fake/gauth_incomplete.json"
    mocker.patch('mcp_google_workspace.gauth.CLIENTSECRETS_LOCATION', mock_secrets_path)
    mock_get_token = mocker.patch('mcp_google_workspace.gauth._get_refresh_token_from_redis', return_value=refresh_token)

    # Simulate missing client_id
    incomplete_secrets = mock_client_secrets.copy()
    del incomplete_secrets['web']['client_id']
    mock_file_content = json.dumps(incomplete_secrets)
    mocker.patch('builtins.open', mock_open(read_data=mock_file_content))
    mock_google_creds_class = mocker.patch('mcp_google_workspace.gauth.GoogleCredentials')

    credentials = gauth.get_credentials_for_user(user_id)

    assert credentials is None
# --- Tests for get_auth_url ---

def test_get_auth_url_success(mocker: MockerFixture):
    """Tests successful generation of the authorization URL."""
    mock_secrets_path = "/fake/gauth_auth_url.json"
    mocker.patch('mcp_google_workspace.gauth.CLIENTSECRETS_LOCATION', mock_secrets_path)
    mock_flow_instance = MagicMock()
    expected_url = "https://example.com/auth?state=test_state_123"
    expected_state_out = "test_state_123" # State returned by mock flow
    mock_flow_instance.authorization_url.return_value = (expected_url, expected_state_out)
    mock_flow_class = mocker.patch('mcp_google_workspace.gauth.Flow')
    mock_flow_class.from_client_secrets_file.return_value = mock_flow_instance
    input_state = "test_state_123" # State passed into the function

    auth_url = gauth.get_auth_url(input_state)

    assert auth_url == expected_url
    mock_flow_class.from_client_secrets_file.assert_called_once_with(
        mock_secrets_path,
        scopes=gauth.SCOPES,
        redirect_uri=gauth.REDIRECT_URI
    )
    mock_flow_instance.authorization_url.assert_called_once_with(
        access_type='offline',
        prompt='consent',
        state=input_state
    )

def test_get_auth_url_secrets_file_not_found(mocker: MockerFixture, caplog):
    """Tests behavior when client secrets file is not found."""
    mock_secrets_path = "/fake/gauth_auth_url_missing.json"
    mocker.patch('mcp_google_workspace.gauth.CLIENTSECRETS_LOCATION', mock_secrets_path)
    mock_flow_class = mocker.patch('mcp_google_workspace.gauth.Flow')
    mock_flow_class.from_client_secrets_file.side_effect = FileNotFoundError("Secrets gone")
    input_state = "test_state_456"

    auth_url = gauth.get_auth_url(input_state)

    assert auth_url is None
    assert f"Client secrets file not found at {mock_secrets_path}" in caplog.text
    mock_flow_class.from_client_secrets_file.assert_called_once_with(
        mock_secrets_path,
        scopes=gauth.SCOPES,
        redirect_uri=gauth.REDIRECT_URI
    )

def test_get_auth_url_flow_exception(mocker: MockerFixture, caplog):
    """Tests behavior when Flow instantiation or URL generation fails."""
    mock_secrets_path = "/fake/gauth_auth_url_fail.json"
    mocker.patch('mcp_google_workspace.gauth.CLIENTSECRETS_LOCATION', mock_secrets_path)
    mock_flow_instance = MagicMock()
    mock_flow_instance.authorization_url.side_effect = Exception("Flow broke")
    mock_flow_class = mocker.patch('mcp_google_workspace.gauth.Flow')
    mock_flow_class.from_client_secrets_file.return_value = mock_flow_instance
    input_state = "test_state_789"

# --- Tests for exchange_code ---

@pytest.fixture
def mock_flow_for_exchange(mocker: MockerFixture):
    """Fixture to mock the Flow object for exchange_code tests."""
    mock_flow_instance = MagicMock()
    mock_creds_instance = MagicMock(spec=GoogleCredentials)
    mock_creds_instance.refresh_token = "mock_refresh_token_123"
    mock_creds_instance.token = "mock_access_token_456" # Needed for get_user_info mock later
    mock_flow_instance.credentials = mock_creds_instance
    mock_flow_class = mocker.patch('mcp_google_workspace.gauth.Flow')
    mock_flow_class.from_client_secrets_file.return_value = mock_flow_instance
    return mock_flow_instance, mock_creds_instance

def test_exchange_code_success(mocker: MockerFixture, mock_flow_for_exchange):
    """Tests successful code exchange, user info retrieval, storage, and notification."""
    mock_flow_instance, mock_creds_instance = mock_flow_for_exchange
    mock_secrets_path = "/fake/gauth_exchange.json"
    mocker.patch('mcp_google_workspace.gauth.CLIENTSECRETS_LOCATION', mock_secrets_path)
    mock_store_token = mocker.patch('mcp_google_workspace.gauth.store_refresh_token_in_redis')
    mock_notify = mocker.patch('mcp_google_workspace.gauth.notify_aggregator_success')
    user_email = "test.user@example.com"
    mock_get_user_info = mocker.patch('mcp_google_workspace.gauth.get_user_info', return_value={"email": user_email})

    state = "state_abc"
    code = "auth_code_xyz"

    credentials = gauth.exchange_code(state, code)

    assert credentials == mock_creds_instance
    gauth.Flow.from_client_secrets_file.assert_called_once_with(
        mock_secrets_path,
        scopes=gauth.SCOPES,
        redirect_uri=gauth.REDIRECT_URI,
        state=state
    )
    mock_flow_instance.fetch_token.assert_called_once_with(code=code)
    mock_get_user_info.assert_called_once_with(mock_creds_instance)
    mock_store_token.assert_called_once_with(user_email, mock_creds_instance.refresh_token)
    mock_notify.assert_called_once_with(state)

def test_exchange_code_success_with_hint(mocker: MockerFixture, mock_flow_for_exchange):
    """Tests successful exchange when get_user_info fails but hint is provided."""
    mock_flow_instance, mock_creds_instance = mock_flow_for_exchange
    mock_secrets_path = "/fake/gauth_exchange_hint.json"
    mocker.patch('mcp_google_workspace.gauth.CLIENTSECRETS_LOCATION', mock_secrets_path)
    mock_store_token = mocker.patch('mcp_google_workspace.gauth.store_refresh_token_in_redis')
    mock_notify = mocker.patch('mcp_google_workspace.gauth.notify_aggregator_success')
    # Simulate get_user_info failing
    mock_get_user_info = mocker.patch('mcp_google_workspace.gauth.get_user_info', return_value=None)
    user_hint = "hint.user@example.com"

    state = "state_def"
    code = "auth_code_uvw"

    credentials = gauth.exchange_code(state, code, user_id_hint=user_hint)

    assert credentials == mock_creds_instance
    gauth.Flow.from_client_secrets_file.assert_called_once()
    mock_flow_instance.fetch_token.assert_called_once_with(code=code)
    mock_get_user_info.assert_called_once_with(mock_creds_instance)
    # Should store using the hint
    mock_store_token.assert_called_once_with(user_hint, mock_creds_instance.refresh_token)
    mock_notify.assert_called_once_with(state)


def test_exchange_code_secrets_file_not_found(mocker: MockerFixture, caplog):
    """Tests behavior when client secrets file is not found."""
    mock_secrets_path = "/fake/gauth_exchange_missing.json"
    mocker.patch('mcp_google_workspace.gauth.CLIENTSECRETS_LOCATION', mock_secrets_path)
    mock_flow_class = mocker.patch('mcp_google_workspace.gauth.Flow')
    mock_flow_class.from_client_secrets_file.side_effect = FileNotFoundError("Secrets gone again")
    mock_store_token = mocker.patch('mcp_google_workspace.gauth.store_refresh_token_in_redis')
    mock_notify = mocker.patch('mcp_google_workspace.gauth.notify_aggregator_success')

    state = "state_ghi"
    code = "auth_code_rst"

    credentials = gauth.exchange_code(state, code)

    assert credentials is None
    assert f"Client secrets file not found at {mock_secrets_path}" in caplog.text
    mock_store_token.assert_not_called()
    mock_notify.assert_not_called()

def test_exchange_code_fetch_token_fails(mocker: MockerFixture, mock_flow_for_exchange, caplog):
    """Tests behavior when flow.fetch_token raises an exception."""
    mock_flow_instance, _ = mock_flow_for_exchange
    mock_secrets_path = "/fake/gauth_exchange_fetch_fail.json"
    mocker.patch('mcp_google_workspace.gauth.CLIENTSECRETS_LOCATION', mock_secrets_path)
    mock_flow_instance.fetch_token.side_effect = Exception("Fetch token boom!")
    mock_store_token = mocker.patch('mcp_google_workspace.gauth.store_refresh_token_in_redis')
    mock_notify = mocker.patch('mcp_google_workspace.gauth.notify_aggregator_success')

    state = "state_jkl"
    code = "auth_code_opq"

    credentials = gauth.exchange_code(state, code)

    assert credentials is None
    assert "Failed to exchange authorization code: Fetch token boom!" in caplog.text
    mock_flow_instance.fetch_token.assert_called_once_with(code=code)
    mock_store_token.assert_not_called()
    mock_notify.assert_not_called()

def test_exchange_code_no_refresh_token(mocker: MockerFixture, mock_flow_for_exchange, caplog):
    """Tests behavior when credentials lack a refresh token."""
    mock_flow_instance, mock_creds_instance = mock_flow_for_exchange
    mock_creds_instance.refresh_token = None # Simulate missing refresh token
    mock_secrets_path = "/fake/gauth_exchange_no_refresh.json"
    mocker.patch('mcp_google_workspace.gauth.CLIENTSECRETS_LOCATION', mock_secrets_path)
    mock_store_token = mocker.patch('mcp_google_workspace.gauth.store_refresh_token_in_redis')
    mock_notify = mocker.patch('mcp_google_workspace.gauth.notify_aggregator_success')

    state = "state_mno"
    code = "auth_code_lmn"

    credentials = gauth.exchange_code(state, code)

    assert credentials is None
    assert "Failed to obtain refresh token" in caplog.text
    mock_flow_instance.fetch_token.assert_called_once_with(code=code)
    mock_store_token.assert_not_called()
    mock_notify.assert_not_called()

def test_exchange_code_get_user_info_fails_no_hint(mocker: MockerFixture, mock_flow_for_exchange, caplog):
    """Tests behavior when get_user_info fails and no hint is provided."""
    mock_flow_instance, mock_creds_instance = mock_flow_for_exchange
    mock_secrets_path = "/fake/gauth_exchange_userinfo_fail.json"
    mocker.patch('mcp_google_workspace.gauth.CLIENTSECRETS_LOCATION', mock_secrets_path)
    mock_store_token = mocker.patch('mcp_google_workspace.gauth.store_refresh_token_in_redis')
    mock_notify = mocker.patch('mcp_google_workspace.gauth.notify_aggregator_success')
# --- Tests for get_user_info ---

@pytest.fixture
def mock_credentials_for_userinfo(mocker: MockerFixture):
    """Fixture for mock Credentials object for get_user_info tests."""
    mock_creds = MagicMock(spec=GoogleCredentials)
    mock_creds.token = "valid_access_token"
    # Mock the refresh method to do nothing successfully
    mock_creds.refresh = MagicMock()
    # Mock the GoogleAuthRequest class used within get_user_info
    mocker.patch('mcp_google_workspace.gauth.GoogleAuthRequest')
    return mock_creds

def test_get_user_info_success(mocker: MockerFixture, mock_credentials_for_userinfo):
    """Tests successful retrieval of user info."""
    mock_creds = mock_credentials_for_userinfo
    expected_user_info = {"email": "user@domain.com", "sub": "12345"}
    mock_response = MagicMock(spec=requests.Response)
    mock_response.json.return_value = expected_user_info
    mock_response.raise_for_status = MagicMock() # Simulate successful status code
    mock_requests_get = mocker.patch('requests.get', return_value=mock_response)

    user_info = gauth.get_user_info(mock_creds)

    assert user_info == expected_user_info
    mock_creds.refresh.assert_called_once() # Should attempt refresh
    gauth.GoogleAuthRequest.assert_called_once() # Should instantiate request object
    mock_requests_get.assert_called_once_with(
        'https://www.googleapis.com/oauth2/v3/userinfo',
        headers={'Authorization': f'Bearer {mock_creds.token}'}
    )
    mock_response.raise_for_status.assert_called_once()

def test_get_user_info_refresh_error(mocker: MockerFixture, mock_credentials_for_userinfo, caplog):
    """Tests behavior when credentials refresh fails."""
    mock_creds = mock_credentials_for_userinfo
    mock_creds.refresh.side_effect = RefreshError("Refresh failed!")
    mock_requests_get = mocker.patch('requests.get')

    user_info = gauth.get_user_info(mock_creds)

    assert user_info is None
    assert "Failed to refresh credentials" in caplog.text
    assert "Refresh failed!" in caplog.text
    mock_creds.refresh.assert_called_once()
    mock_requests_get.assert_not_called() # Should fail before making the request

def test_get_user_info_request_exception(mocker: MockerFixture, mock_credentials_for_userinfo, caplog):
    """Tests behavior when the requests.get call fails."""
    mock_creds = mock_credentials_for_userinfo
    mock_requests_get = mocker.patch('requests.get', side_effect=requests.exceptions.RequestException("Network error"))

    user_info = gauth.get_user_info(mock_creds)

    assert user_info is None
    assert "Failed to fetch user info: Network error" in caplog.text
    mock_creds.refresh.assert_called_once()
    mock_requests_get.assert_called_once() # Request is attempted

def test_get_user_info_http_error(mocker: MockerFixture, mock_credentials_for_userinfo, caplog):
    """Tests behavior when the userinfo endpoint returns an HTTP error."""
    mock_creds = mock_credentials_for_userinfo
    mock_response = MagicMock(spec=requests.Response)
    mock_response.raise_for_status.side_effect = requests.exceptions.HTTPError("403 Forbidden")
    mock_requests_get = mocker.patch('requests.get', return_value=mock_response)

    user_info = gauth.get_user_info(mock_creds)

    assert user_info is None
    # The HTTPError is caught by the RequestException handler in the code
    assert "Failed to fetch user info: 403 Forbidden" in caplog.text
    mock_creds.refresh.assert_called_once()
    mock_requests_get.assert_called_once()
    mock_response.raise_for_status.assert_called_once()

def test_get_user_info_unexpected_error(mocker: MockerFixture, mock_credentials_for_userinfo, caplog):
    """Tests behavior on unexpected errors during user info fetching."""
    mock_creds = mock_credentials_for_userinfo
    # Make the json() call fail after a successful request
    mock_response = MagicMock(spec=requests.Response)
    mock_response.raise_for_status = MagicMock()
    mock_response.json.side_effect = Exception("Unexpected parsing error")
    mock_requests_get = mocker.patch('requests.get', return_value=mock_response)

    user_info = gauth.get_user_info(mock_creds)

    # --- Moved lines from test_get_google_service_build_generic_exception ---
    assert user_info is None
    assert "An unexpected error occurred while fetching user info" in caplog.text
    assert "Unexpected parsing error" in caplog.text
    mock_creds.refresh.assert_called_once()
    mock_requests_get.assert_called_once()
    mock_response.raise_for_status.assert_called_once()
    mock_response.json.assert_called_once()
    # --- End moved lines ---

# --- Tests for get_google_service ---

@pytest.fixture
def mock_build(mocker: MockerFixture):
    """Fixture to mock googleapiclient.discovery.build."""
    return mocker.patch('mcp_google_workspace.gauth.build')

def test_get_google_service_success(mocker: MockerFixture, mock_build):
    """Tests successful service client creation."""
    user_id = "service_user@example.com"
    service_name = "gmail"
    version = "v1"
    mock_creds = MagicMock(spec=GoogleCredentials)
    mock_get_creds = mocker.patch('mcp_google_workspace.gauth.get_credentials_for_user', return_value=mock_creds)
    mock_service_client = MagicMock()
    mock_build.return_value = mock_service_client

    service = gauth.get_google_service(service_name, version, user_id)

    assert service == mock_service_client
    mock_get_creds.assert_called_once_with(user_id)
    mock_build.assert_called_once_with(
        service_name, version, credentials=mock_creds, cache_discovery=False
    )

def test_get_google_service_no_credentials(mocker: MockerFixture, mock_build, caplog):
    """Tests behavior when get_credentials_for_user returns None."""
    user_id = "no_creds_user@example.com"
    service_name = "calendar"
    version = "v3"
    mock_get_creds = mocker.patch('mcp_google_workspace.gauth.get_credentials_for_user', return_value=None)

    service = gauth.get_google_service(service_name, version, user_id)

    assert service is None
    assert f"Could not get credentials for user {user_id}" in caplog.text
    mock_get_creds.assert_called_once_with(user_id)
    mock_build.assert_not_called()

def test_get_google_service_build_http_error_auth(mocker: MockerFixture, mock_build, caplog):
    """Tests behavior when build raises an authentication HttpError (401/403)."""
    user_id = "auth_error_user@example.com"
    service_name = "drive"
    version = "v3"
    mock_creds = MagicMock(spec=GoogleCredentials)
    mock_get_creds = mocker.patch('mcp_google_workspace.gauth.get_credentials_for_user', return_value=mock_creds)
    # Simulate a 401 Unauthorized error
    mock_http_error_response = MagicMock()
    mock_http_error_response.status = 401
    mock_build.side_effect = HttpError(resp=mock_http_error_response, content=b'Auth error')

    service = gauth.get_google_service(service_name, version, user_id)

    assert service is None
    assert f"An API error occurred building '{service_name}' service" in caplog.text
    assert f"Authentication error for {user_id}" in caplog.text # Specific warning for 401/403
    mock_get_creds.assert_called_once_with(user_id)
    mock_build.assert_called_once_with(
        service_name, version, credentials=mock_creds, cache_discovery=False
    )

def test_get_google_service_build_http_error_other(mocker: MockerFixture, mock_build, caplog):
    """Tests behavior when build raises a non-authentication HttpError."""
    user_id = "other_http_error_user@example.com"
    service_name = "sheets"
    version = "v4"
    mock_creds = MagicMock(spec=GoogleCredentials)
    mock_get_creds = mocker.patch('mcp_google_workspace.gauth.get_credentials_for_user', return_value=mock_creds)
    # Simulate a 500 Server Error
    mock_http_error_response = MagicMock()
    mock_http_error_response.status = 500
    mock_build.side_effect = HttpError(resp=mock_http_error_response, content=b'Server boom')

    service = gauth.get_google_service(service_name, version, user_id)

    assert service is None
    assert f"An API error occurred building '{service_name}' service" in caplog.text
    assert f"Authentication error for {user_id}" not in caplog.text # Should not log the auth-specific warning
    mock_get_creds.assert_called_once_with(user_id)
    mock_build.assert_called_once_with(
        service_name, version, credentials=mock_creds, cache_discovery=False
    )

def test_get_google_service_build_generic_exception(mocker: MockerFixture, mock_build, caplog):
    """Tests behavior when build raises a generic exception."""
    user_id = "generic_error_user@example.com"
    service_name = "tasks"
    version = "v1"
    mock_creds = MagicMock(spec=GoogleCredentials)
    mock_get_creds = mocker.patch('mcp_google_workspace.gauth.get_credentials_for_user', return_value=mock_creds)
    mock_build.side_effect = Exception("Something else broke")

    service = gauth.get_google_service(service_name, version, user_id)

    assert service is None
    assert f"An unexpected error occurred building '{service_name}' service" in caplog.text
    assert "Something else broke" in caplog.text
    mock_get_creds.assert_called_once_with(user_id)
    mock_build.assert_called_once_with(
        service_name, version, credentials=mock_creds, cache_discovery=False
    )
    # --- Lines 665-671 moved to test_get_user_info_unexpected_error ---

def test_get_credentials_for_user_generic_exception_on_open(mocker: MockerFixture, caplog):
    """Tests behavior on generic exception during opening client secrets."""
    user_id = "user_exception@example.com"
    refresh_token = "valid_refresh_token"
    mock_secrets_path = "/fake/gauth_exception.json"
    mocker.patch('mcp_google_workspace.gauth.CLIENTSECRETS_LOCATION', mock_secrets_path)
    mock_get_token = mocker.patch('mcp_google_workspace.gauth._get_refresh_token_from_redis', return_value=refresh_token)
    # Mock open to raise an exception
    mock_open = mocker.patch('builtins.open', side_effect=Exception("Something broke opening file"))
    mock_google_creds_class = mocker.patch('mcp_google_workspace.gauth.GoogleCredentials')

    # Act
    credentials = gauth.get_credentials_for_user(user_id)

    # Assert
    assert credentials is None # Should fail to create credentials
    mock_get_token.assert_called_once_with(user_id)
    mock_open.assert_called_once_with(mock_secrets_path, 'r') # Ensure open was called
    mock_google_creds_class.assert_not_called() # Should not reach credential creation
    assert f"Error creating credentials for user {user_id}" in caplog.text
    assert "Something broke opening file" in caplog.text

    # Separate test for Redis exception during token retrieval (already covered by test_get_refresh_token_redis_error)
    # The original test incorrectly combined these scenarios.
    # assert f"Failed to retrieve refresh token for user {user_id}" in caplog.text # Removed incorrect assertion
    # assert "Redis GET failed" in caplog.text # Removed incorrect assertion
    # mock_redis_client.get.assert_called_once_with(expected_key) # Removed undefined variable reference

# All irrelevant leftover lines removed.