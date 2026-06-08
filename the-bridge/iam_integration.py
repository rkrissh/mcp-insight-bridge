import jwt
import requests
from kubernetes import client as k8s_client
from datetime import datetime
from typing import Optional, Dict, Any

class IAMIntegration:
    def __init__(self):
        self.okta_issuer = "https://dev-123456.okta.com"
        self.okta_audience = "api://the-bridge"
        
    def validate_okta_token(self, token: str) -> Optional[Dict]:
        """Validate Okta JWT token and extract claims."""
        try:
            # In production: verify signature with Okta's public key
            payload = jwt.decode(
                token,
                options={"verify_signature": False, "verify_exp": False},  # Disable for demo
                audience=self.okta_audience
            )
            
            # Check issuer
            if payload.get("iss") != self.okta_issuer:
                return None
                
            # Check expiry
            import time
            if payload.get("exp", 0) < time.time() - 3600:  # Allow 1 hour leeway
                return None
                
            return {
                "user_id": payload.get("sub"),
                "roles": payload.get("groups", []),
                "department": payload.get("department"),
                "geo": payload.get("geo"),
                "security_clearance": payload.get("security_clearance", "Internal"),
                "entitlements": payload.get("entitlements", []),
                "restrictions": payload.get("restrictions", []),
                "context": payload.get("context", {})
            }
        except jwt.InvalidTokenError:
            return None
    
    def get_azure_ad_context(self, user_id: str) -> Dict:
        """Fetch Azure AD conditional access context."""
        # Mock for demo - replace with Microsoft Graph API
        return {
            "groups": ["M&A Team - UK", "Internal Data Access"],
            "mfa_status": "verified",
            "device_compliance": "compliant",
            "risk_score": 15,  # 0-100
            "sign_in_location": "London, UK"
        }
    
    def get_k8s_rbac_context(self, namespace: str, service_account: str) -> Dict:
        """Fetch Kubernetes RBAC permissions."""
        # Mock for demo - replace with K8s API
        return {
            "namespace": namespace,
            "service_account": service_account,
            "cluster_roles": ["read-pods", "list-services", "view-configmaps"],
            "network_policies": ["allow-internal-only", "deny-external-egress"],
            "allowed_verbs": ["get", "list", "watch"]
        }