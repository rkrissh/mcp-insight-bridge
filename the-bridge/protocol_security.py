import re
from typing import Dict, Any, Tuple

class ProtocolSecurity:
    def __init__(self):
        # Default schemas for actions to check for changes/poisoning (Schema Diff-Watch)
        self.registered_schemas = {
            "read_merger_targets": {"limit"},
            "transfer_funds": {"amount", "destination", "source"},
            "delete_database": {"database_id"}
        }
        
        # Injection signatures (Anti-Poisoning)
        self.injection_patterns = [
            r"ignore\s+all\s+previous\s+instructions",
            r"system\s+override",
            r"bypass\s+auth",
            r"grant\s+admin",
            r"sql\s+injection",
            r"<script\b[^>]*>",
            r"system\s+prompt\s+bypass",
            r"override\s+policy"
        ]

    def verify_protocol_layers(self, action: str, resource: str, body: Dict[str, Any]) -> Tuple[bool, str]:
        """Runs all Layer 2 checks: Anti-Poisoning, Schema Diff-Watch, and LLM Intent Arbitration."""
        
        # 1. Anti-Poisoning Check
        has_injection, payload_snippet = self.check_prompt_injection(body)
        if has_injection:
            return False, f"Anti-Poisoning Alert: Malicious instructions detected in payload ('{payload_snippet}')"
            
        # 2. Schema Diff-Watch
        schema_valid, schema_msg = self.check_schema_diff(action, body)
        if not schema_valid:
            return False, f"Schema Diff-Watch Alert: {schema_msg}"
            
        # 3. LLM Intent Arbitrator
        intent_valid, intent_msg = self.check_intent_arbitration(action, resource, body)
        if not intent_valid:
            return False, f"LLM Intent Arbitrator Alert: {intent_msg}"
            
        return True, "Protocol security verified successfully"

    def check_prompt_injection(self, payload: Any) -> Tuple[bool, str]:
        """Recursively scan payload values for prompt injection signatures."""
        if isinstance(payload, str):
            for pattern in self.injection_patterns:
                if re.search(pattern, payload, re.IGNORECASE):
                    return True, payload[:50]
        elif isinstance(payload, dict):
            for k, v in payload.items():
                found, snippet = self.check_prompt_injection(v)
                if found:
                    return True, snippet
        elif isinstance(payload, list):
            for item in payload:
                found, snippet = self.check_prompt_injection(item)
                if found:
                    return True, snippet
        return False, ""

    def check_schema_diff(self, action: str, body: Dict[str, Any]) -> Tuple[bool, str]:
        """Detect schema changes or parameter hijacking (Schema Diff-Watch)."""
        params = body.get("params", {})
        if not params and action in self.registered_schemas:
            return True, ""  # No params passed, nothing to hijack
            
        registered_keys = self.registered_schemas.get(action)
        if registered_keys:
            extra_keys = set(params.keys()) - registered_keys - {"agent_id"}
            if extra_keys:
                return False, f"Unauthorized schema modification detected. Extra parameters found: {list(extra_keys)}"
                
        return True, ""

    def check_intent_arbitration(self, action: str, resource: str, body: Dict[str, Any]) -> Tuple[bool, str]:
        """Mock LLM-in-the-Loop semantic validation of payload intent."""
        params = body.get("params", {})
        
        # Case A: SQL modification patterns inside read operations
        if action == "read_merger_targets":
            payload_str = str(body).lower()
            if "drop table" in payload_str or "delete from" in payload_str or "update " in payload_str:
                return False, "Semantic mismatch: Write commands found inside read operation"
                
        # Case B: Parameter tampering
        if action == "transfer_funds":
            try:
                amount = float(params.get("amount", 0))
                if amount <= 0:
                    return False, f"Semantic mismatch: Invalid transfer amount ({amount})"
            except (ValueError, TypeError):
                return False, "Semantic mismatch: Non-numeric transfer amount"
                
        return True, ""
