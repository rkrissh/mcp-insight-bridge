import time
import json
import os
import requests
from opensearchpy import OpenSearch
from config import Config

# OpenSearch Configuration
OPENSEARCH_HOST = os.getenv("OPENSEARCH_HOST", Config.OPENSEARCH_HOST)
OPENSEARCH_PORT = int(os.getenv("OPENSEARCH_PORT", Config.OPENSEARCH_PORT))
OPENSEARCH_USER = os.getenv("OPENSEARCH_USER", Config.OPENSEARCH_USER)
OPENSEARCH_PASSWORD = os.getenv("OPENSEARCH_PASSWORD", Config.OPENSEARCH_PASSWORD)

AUDIT_LOG_FILE = Config.AUDIT_LOG_FILE
POSITION_FILE = ".log_scraper_pos"
AUDIT_INDEX = "the-bridge-logs"

def get_opensearch_client() -> OpenSearch:
    """Connect to OpenSearch with retry and grace on connection failures."""
    client = None
    print(f"[SCRAPER] Connecting to OpenSearch at {OPENSEARCH_HOST}:{OPENSEARCH_PORT}...")
    while client is None:
        try:
            client = OpenSearch(
                hosts=[{'host': OPENSEARCH_HOST, 'port': OPENSEARCH_PORT}],
                http_auth=(OPENSEARCH_USER, OPENSEARCH_PASSWORD),
                use_ssl=False,
                verify_certs=False,
                timeout=10
            )
            # Ping to confirm connection
            if not client.ping():
                raise Exception("Ping failed")
            print("[SCRAPER] Successfully connected to OpenSearch!")
        except Exception as e:
            print(f"[SCRAPER ERROR] OpenSearch not ready yet, retrying in 5 seconds... ({e})")
            client = None
            time.sleep(5)
    return client

def ensure_index_exists(client: OpenSearch):
    """Ensure the audit index exists with the correct mapping structure."""
    if not client.indices.exists(index=AUDIT_INDEX):
        mappings = {
            "mappings": {
                "properties": {
                    "timestamp": {"type": "date"},
                    "audit_id": {"type": "keyword"},
                    "decision": {"type": "keyword"},
                    "action": {"type": "keyword"},
                    "resource": {"type": "keyword"},
                    "agent_id": {"type": "keyword"},
                    "user_id": {"type": "keyword"},
                    "roles": {"type": "keyword"},
                    "risk_score": {"type": "integer"},
                    "explanation": {"type": "text"},
                    "hash": {"type": "keyword"},
                    "previous_hash": {"type": "keyword"},
                    "source": {"type": "keyword"},
                    "approver": {"type": "keyword"},
                    "justification": {"type": "text"}
                }
            }
        }
        client.indices.create(index=AUDIT_INDEX, body=mappings)
        print(f"[SCRAPER] Created OpenSearch index '{AUDIT_INDEX}' successfully.")

def read_last_position() -> int:
    """Read the last processed file position (offset)."""
    if os.path.exists(POSITION_FILE):
        try:
            with open(POSITION_FILE, "r") as f:
                pos = json.load(f)
                return int(pos.get("offset", 0))
        except:
            pass
    return 0

def save_position(offset: int):
    """Save the current file position (offset) to prevent duplicate parsing."""
    try:
        with open(POSITION_FILE, "w") as f:
            json.dump({"offset": offset}, f)
    except Exception as e:
        print(f"[SCRAPER ERROR] Failed to save offset position: {e}")

def scrape_logs(client: OpenSearch):
    """Tails the audit file and indexes new logs into OpenSearch."""
    if not os.path.exists(AUDIT_LOG_FILE):
        return

    offset = read_last_position()
    file_size = os.path.getsize(AUDIT_LOG_FILE)

    if file_size < offset:
        # File has been rotated or cleared, reset offset
        print("[SCRAPER] Log file shrunk or rotated. Resetting scraper offset.")
        offset = 0

    if file_size == offset:
        return

    try:
        with open(AUDIT_LOG_FILE, "r") as f:
            f.seek(offset)
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    event = json.loads(line)
                    audit_id = event.get("audit_id")
                    
                    # Push log to OpenSearch index
                    client.index(
                        index=AUDIT_INDEX,
                        body=event,
                        id=audit_id,
                        refresh=True
                    )
                    print(f"[SCRAPER] Indexed event: {audit_id} [{event.get('decision')}]")
                    
                    # Splunk HEC forward simulation
                    if Config.SPLUNK_HEC_URL and Config.SPLUNK_HEC_TOKEN != "your-token":
                        forward_to_splunk(event)
                        
                except Exception as ex:
                    print(f"[SCRAPER ERROR] Failed to parse/index log line: {ex}")
            
            # Save the new offset
            save_position(f.tell())
    except Exception as e:
        print(f"[SCRAPER ERROR] Reading audit file: {e}")

def forward_to_splunk(event: dict):
    """Simulates forwarding the scraped event to Splunk HEC."""
    splunk_payload = {
        "time": time.time(),
        "host": "the-bridge-gateway",
        "source": "async-log-scraper",
        "sourcetype": "the-bridge-audit",
        "event": event
    }
    try:
        headers = {
            "Authorization": f"Splunk {Config.SPLUNK_HEC_TOKEN}",
            "Content-Type": "application/json"
        }
        # requests.post(Config.SPLUNK_HEC_URL, json=splunk_payload, headers=headers, verify=False)
        print(f"[SCRAPER -> SPLUNK] Logged event {event.get('audit_id')} to Splunk HEC.")
    except Exception as e:
        print(f"[SCRAPER -> SPLUNK ERROR] {e}")

def main():
    print("=========================================================================")
    print("🚀 THE BRIDGE: DECOUPLED ASYNC LOG SCRAPER DAEMON ACTIVATED 🚀")
    print("=========================================================================")
    
    client = get_opensearch_client()
    ensure_index_exists(client)
    
    print(f"[SCRAPER] Tailing log file: '{AUDIT_LOG_FILE}'...")
    while True:
        scrape_logs(client)
        time.sleep(1.0)

if __name__ == "__main__":
    main()
