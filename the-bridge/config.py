import os
from dotenv import load_dotenv

load_dotenv()

class Config:
    # Local Audit Log File
    AUDIT_LOG_FILE = os.getenv("AUDIT_LOG_FILE", "gateway_audit.log")

    # OpenSearch
    OPENSEARCH_HOST = os.getenv("OPENSEARCH_HOST", "localhost")
    OPENSEARCH_PORT = int(os.getenv("OPENSEARCH_PORT", 9200))
    OPENSEARCH_USER = os.getenv("OPENSEARCH_USER", "admin")
    OPENSEARCH_PASSWORD = os.getenv("OPENSEARCH_PASSWORD", "admin")
    
    # Splunk
    SPLUNK_HEC_URL = os.getenv("SPLUNK_HEC_URL", "https://localhost:8088/services/collector")
    SPLUNK_HEC_TOKEN = os.getenv("SPLUNK_HEC_TOKEN", "your-token")
    
    # Okta
    OKTA_ISSUER = os.getenv("OKTA_ISSUER", "https://dev-123456.okta.com")
    OKTA_AUDIENCE = os.getenv("OKTA_AUDIENCE", "api://the-bridge")
    
    # MCP Server
    MCP_SERVER_URL = os.getenv("MCP_SERVER_URL", "http://127.0.0.1:8001/messages/")
    
    # OPA
    OPA_URL = os.getenv("OPA_URL", "http://localhost:8181/v1/data/the_bridge/authz/allow")