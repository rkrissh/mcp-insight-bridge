import json
import hashlib
import uuid
import os
from datetime import datetime
from typing import Dict, List, Optional
from config import Config

class AuditLogger:
    def __init__(self):
        # Local file path for audit events
        self.log_file_path = Config.AUDIT_LOG_FILE
        # Ensure log file directory exists
        log_dir = os.path.dirname(os.path.abspath(self.log_file_path))
        if log_dir and not os.path.exists(log_dir):
            os.makedirs(log_dir, exist_ok=True)
            
        # Splunk configurations (preserved for compatibility/reference)
        self.splunk_url = Config.SPLUNK_HEC_URL
        self.splunk_token = Config.SPLUNK_HEC_TOKEN
        
        # Local Syslog LEEF file path
        self.syslog_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "qradar_syslog.log")
    
    def log_decision(self, decision_data: Dict) -> str:
        """Log a decision locally to the audit file (decoupled async ingestion)."""
        audit_id = str(uuid.uuid4())
        previous_hash = self._get_latest_hash()
        
        # Build structured event payload
        event_data = {
            "audit_id": audit_id,
            "timestamp": datetime.utcnow().isoformat(),
            "decision": decision_data.get("decision"),
            "action": decision_data.get("action"),
            "resource": decision_data.get("resource"),
            "agent_id": decision_data.get("agent_id"),
            "user_id": decision_data.get("user_id"),
            "roles": decision_data.get("roles", []),
            "risk_score": decision_data.get("risk_score", 0),
            "explanation": decision_data.get("explanation"),
            "source": decision_data.get("source", "unknown"),
            "approver": decision_data.get("approver"),
            "justification": decision_data.get("justification"),
            "previous_hash": previous_hash
        }
        
        # Cryptographic Hash Chaining for immutability
        event_json = json.dumps(event_data, sort_keys=True)
        event_data["hash"] = hashlib.sha256((event_json + previous_hash).encode()).hexdigest()
        
        # Append log line to local audit file
        try:
            with open(self.log_file_path, "a") as f:
                f.write(json.dumps(event_data) + "\n")
        except Exception as e:
            print(f"[AUDIT LOGGER ERROR] Failed to write to local log file: {e}")
            
        # Log to QRadar (syslog/LEEF) locally
        self._log_to_qradar(event_data)
        
        return audit_id
        
    def _log_to_qradar(self, event: Dict):
        """Format and log event in QRadar LEEF (Log Event Extended Format)."""
        try:
            leef_msg = (
                f"LEEF:2.0|TheBridge|Gateway|2.0.0|{event.get('decision')}|"
                f"usrName={event.get('user_id')}\t"
                f"src={event.get('agent_id')}\t"
                f"devTime={event.get('timestamp')}\t"
                f"action={event.get('action')}\t"
                f"resource={event.get('resource')}\t"
                f"riskScore={event.get('risk_score')}\t"
                f"auditId={event.get('audit_id')}\t"
                f"hash={event.get('hash')}"
            )
            print(f"[QRADAR/LEEF] {leef_msg}")
            
            with open(self.syslog_path, "a") as f:
                f.write(leef_msg + "\n")
        except Exception as e:
            print(f"[QRADAR ERROR] {e}")
            
    def _get_latest_hash(self) -> str:
        """Read the last line of the local audit log file to get the latest hash."""
        if not os.path.exists(self.log_file_path):
            return "GENESIS"
            
        try:
            with open(self.log_file_path, "rb") as f:
                # Seek to end of file to find the last line quickly
                f.seek(0, os.SEEK_END)
                end_pos = f.tell()
                if end_pos == 0:
                    return "GENESIS"
                    
                buffer_size = 1024
                pointer = end_pos - buffer_size if end_pos > buffer_size else 0
                f.seek(pointer)
                lines = f.readlines()
                
                if lines:
                    last_line = lines[-1].decode("utf-8").strip()
                    if last_line:
                        record = json.loads(last_line)
                        return record.get("hash", "GENESIS")
        except Exception as e:
            print(f"[AUDIT LOGGER ERROR] Failed to read latest hash: {e}")
            
        return "GENESIS"
        
    def get_hash_chain(self, audit_id: str) -> List[Dict]:
        """Trace the entire cryptographic hash chain for an audit ID locally."""
        chain = []
        if not os.path.exists(self.log_file_path):
            return chain
            
        try:
            # Load all logs from the local file
            all_records = []
            with open(self.log_file_path, "r") as f:
                for line in f:
                    line = line.strip()
                    if line:
                        all_records.append(json.loads(line))
                        
            # Find the starting record
            current = None
            for rec in all_records:
                if rec.get("audit_id") == audit_id:
                    current = rec
                    break
                    
            if current:
                chain.append(current)
                # Trace back
                while current.get("previous_hash") != "GENESIS":
                    prev = None
                    for rec in all_records:
                        if rec.get("hash") == current.get("previous_hash"):
                            prev = rec
                            break
                    if prev:
                        current = prev
                        chain.insert(0, current)
                    else:
                        break
        except Exception as e:
            print(f"[AUDIT LOGGER ERROR] Failed to trace hash chain: {e}")
            
        return chain