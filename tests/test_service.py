# ===== IMPORTS ===== #

## ===== 3RD-PARTY ===== ##
from fastapi.testclient import TestClient
##-##

## ===== LOCAL ===== ##
from mcp_google_workspace.server import service
##-##

#-#

# ===== GLOBALS ===== #
EXPECTED_TOOLS = {
    "query_emails", "get_email", "bulk_get_emails", "get_attachment", "create_draft", "delete_draft", "reply_email", "bulk_save_attachments",
    "list_files", "get_file_metadata", "download_file", "upload_file",
    "list_calendars", "get_events", "create_event", "delete_event",
}
#-#

# ===== MODULE BANNER ===== #
"""Checks that the packaged Google service boots and exposes its current contract."""
#-#

# ===== DECLARATIONS ===== #
#-#

# ===== CLASSES ===== #
#-#

# ===== FUNCTIONS ===== #

def test_service_contract():
    response = TestClient(service.app).get("/health")
    assert response.status_code == 200
    assert response.json() == {"status": "healthy", "service": "mcp-google-workspace"}
    assert {tool["public_name"] for tool in service._tools.values()} == {f"google-{name}" for name in EXPECTED_TOOLS}

#-#
