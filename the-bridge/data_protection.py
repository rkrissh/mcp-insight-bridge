import re
from typing import Any, Dict, Tuple

class DataProtection:
    def __init__(self):
        # Regex patterns for various PII types
        self.pii_patterns = {
            "SSN": r"\b\d{3}-\d{2}-\d{4}\b",
            "CREDIT_CARD": r"\b\d{4}[- ]?\d{4}[- ]?\d{4}[- ]?\d{4}\b",
            "API_KEY": r"\b(sk-proj-|AIzaSy)[a-zA-Z0-9_-]{20,}\b",
            "EMAIL": r"\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b"
        }
        
        # Max context character length allowed to proceed without trimming
        self.max_context_length = 1500

    def process_data_protection(self, data: Any) -> Tuple[Any, bool]:
        """Redacts PII and trims data context if necessary."""
        # 1. PII Redaction
        redacted_data, redacted_any = self.redact_pii(data)
        
        # 2. Context Trimming
        trimmed_data = self.trim_context(redacted_data)
        
        return trimmed_data, redacted_any

    def redact_pii(self, payload: Any) -> Tuple[Any, bool]:
        """Recursively search and replace PII in request/response payloads."""
        redacted_any = False
        
        if isinstance(payload, str):
            modified_str = payload
            for pii_type, pattern in self.pii_patterns.items():
                # Avoid redacting user ID emails in subject claims
                if pii_type == "EMAIL" and ("@bank.com" in payload.lower() or "@example.com" in payload.lower()):
                    continue
                matches = re.findall(pattern, modified_str)
                if matches:
                    modified_str = re.sub(pattern, f"[REDACTED_{pii_type}]", modified_str)
                    redacted_any = True
            return modified_str, redacted_any
            
        elif isinstance(payload, dict):
            new_dict = {}
            for k, v in payload.items():
                val, changed = self.redact_pii(v)
                new_dict[k] = val
                if changed:
                    redacted_any = True
            return new_dict, redacted_any
            
        elif isinstance(payload, list):
            new_list = []
            for item in payload:
                val, changed = self.redact_pii(item)
                new_list.append(val)
                if changed:
                    redacted_any = True
            return new_list, redacted_any
            
        return payload, redacted_any

    def trim_context(self, payload: Any) -> Any:
        """Enforces context trimming limits to prevent data dumping."""
        if isinstance(payload, str):
            if len(payload) > self.max_context_length:
                return payload[:self.max_context_length] + "... [CONTEXT TRUNCATED FOR SECURITY]"
        elif isinstance(payload, dict) and "data" in payload:
            payload = payload.copy()
            payload["data"] = self.trim_context(payload["data"])
        return payload
