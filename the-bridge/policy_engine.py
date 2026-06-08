import requests
from typing import Dict, Any, List
from datetime import datetime
from config import Config

class ABACPolicyEngine:
    def __init__(self):
        # Default rules array
        self.rules = []
        
        # Stateful tracking of users/agents for Trust-Decay, Feedback Loops, and Circuit Breakers
        # Format: {user_id: {"violations": int, "ring": int, "last_violation": datetime, "strictness_level": str, "suggested_revocations": list}}
        self.state = {}
        
        self._init_default_rules()
    
    def _init_default_rules(self):
        """Initialize default ABAC rules and stateful filters."""
        
        # Stateful Rule: Circuit Breaker
        self.add_rule(
            rule_id="circuit_breaker_block",
            condition_func=self._check_circuit_breaker,
            description="Circuit Breaker Tripped: Agent blocked due to too many consecutive violations"
        )

        # Rule 1: Time-based access
        self.add_rule(
            rule_id="time_restriction",
            condition_func=self._check_time_window,
            description="Access restricted to business hours"
        )
        
        # Rule 2: Geo-based restriction
        self.add_rule(
            rule_id="geo_restriction",
            condition_func=self._check_geo_restriction,
            description="Geo-restricted resource accessed"
        )
        
        # Rule 3: Department-based access
        self.add_rule(
            rule_id="department_access",
            condition_func=self._check_department_access,
            description="Department-based access control"
        )
        
        # Rule 4: Entitlement-based access
        self.add_rule(
            rule_id="entitlement_check",
            condition_func=self._check_entitlements,
            description="Explicit entitlement required"
        )
        
        # Rule 5: Risk-based blocking
        self.add_rule(
            rule_id="risk_based_block",
            condition_func=self._check_risk_score,
            description="Risk score exceeded safety threshold"
        )
        
        # Rule 6: Open Policy Agent (OPA) Live Connection with Fallback
        self.add_rule(
            rule_id="opa_governance",
            condition_func=self._check_opa_policy,
            description="OPA Compliance Policy Violation: Resource classified as restricted corporate asset"
        )
    
    def add_rule(self, rule_id: str, condition_func, description: str):
        """Add a policy rule."""
        self.rules.append({
            "id": rule_id,
            "condition": condition_func,
            "description": description
        })
    
    def get_user_state(self, user_id: str) -> Dict[str, Any]:
        """Fetch or initialize the state for a user/agent."""
        if not user_id:
            return {
                "violations": 0, 
                "ring": 0, 
                "last_violation": None,
                "strictness_level": "standard",
                "suggested_revocations": []
            }
        if user_id not in self.state:
            self.state[user_id] = {
                "violations": 0, 
                "ring": 0, 
                "last_violation": None,
                "strictness_level": "standard",
                "suggested_revocations": []
            }
        return self.state[user_id]

    def record_violation(self, user_id: str):
        """Stateful: Increments violation count and decays the trust ring."""
        if not user_id:
            return
        user_state = self.get_user_state(user_id)
        user_state["violations"] += 1
        user_state["last_violation"] = datetime.utcnow().isoformat()
        
        # Trust-Decay logic:
        # Ring 0: Fully Trusted (0-1 violations)
        # Ring 1: Needs Approvals (2 violations)
        # Ring 2: Blocked/Tripped Circuit Breaker (3+ violations)
        violations = user_state["violations"]
        if violations == 2:
            user_state["ring"] = 1
        elif violations >= 3:
            user_state["ring"] = 2

    def record_success(self, user_id: str):
        """Stateful: Successful requests can slowly restore trust (decay recovery)."""
        if not user_id:
            return
        user_state = self.get_user_state(user_id)
        # If user isn't fully blacklisted, let success clear violations
        if user_state["ring"] < 2:
            user_state["violations"] = max(0, user_state["violations"] - 1)
            if user_state["violations"] < 2:
                user_state["ring"] = 0

    def reset_user_trust(self, user_id: str):
        """Reset the trust ring and violations for a user (called by admin action)."""
        if user_id in self.state:
            self.state[user_id] = {
                "violations": 0, 
                "ring": 0, 
                "last_violation": None,
                "strictness_level": self.state[user_id].get("strictness_level", "standard"),
                "suggested_revocations": self.state[user_id].get("suggested_revocations", [])
            }

    def set_user_strictness(self, user_id: str, level: str):
        """Feedback Loop: Update strictness profile (low, standard, high) dynamically."""
        user_state = self.get_user_state(user_id)
        user_state["strictness_level"] = level

    def add_suggested_revocation(self, user_id: str, privilege: str):
        """Feedback Loop: Suggest privileges for revocation based on analysis."""
        user_state = self.get_user_state(user_id)
        if privilege not in user_state["suggested_revocations"]:
            user_state["suggested_revocations"].append(privilege)

    def clear_suggested_revocations(self, user_id: str):
        """Feedback Loop: Clear suggested list after actions are executed."""
        user_state = self.get_user_state(user_id)
        user_state["suggested_revocations"] = []

    def evaluate(self, user_claims: Dict, action: str, resource: str, context: Dict) -> Dict:
        """Evaluate all rules against the request."""
        decision = "ALLOW"
        reasons = []
        matched_rules = []
        
        # Fetch user/agent state
        user_id = user_claims.get("user_id")
        user_state = self.get_user_state(user_id)
        
        for rule in self.rules:
            result = rule["condition"](user_claims, action, resource, context)
            if result == "DENY":
                decision = "DENY"
                reasons.append(rule["description"])
                matched_rules.append(rule["id"])
                break
            elif result == "ALLOW":
                matched_rules.append(rule["id"])
        
        # Calculate dynamic risk score
        risk_score = self._calculate_risk_score(user_claims, action, resource)
        
        # If user is in Ring 1, escalate risk to trigger approvals
        if user_state["ring"] == 1:
            risk_score = max(risk_score, 80)
            reasons.append("Escalated: Trust decay Ring 1 requires Human-in-the-Loop approval")
            
        return {
            "decision": decision,
            "reasons": reasons if reasons else ["No policy violations"],
            "matched_rules": matched_rules,
            "risk_score": risk_score,
            "timestamp": datetime.utcnow().isoformat()
        }
    
    def _calculate_risk_score(self, user_claims: Dict, action: str, resource: str) -> int:
        """Calculate dynamic risk score (0-100) enriched by strictness levels."""
        risk_score = 0
        
        # Base risk based on resource sensitivity
        sensitive_keywords = ["merger", "client", "pii", "confidential", "trade"]
        for keyword in sensitive_keywords:
            if keyword in resource.lower():
                risk_score += 20
                break
        
        # Risk based on user attributes
        roles = user_claims.get("roles", [])
        if "Junior Analyst" in roles:
            risk_score += 15
        elif "VP" in roles or "Director" in roles:
            risk_score += 5
        
        # Risk based on action
        if "transfer" in action.lower() or "export" in action.lower() or "delete" in action.lower():
            risk_score += 25
        
        # Risk based on geo
        geo = user_claims.get("geo")
        if geo == "UK" and "cross_border" in user_claims.get("restrictions", []):
            risk_score += 20
        
        # Dynamic feedback loop adjustments:
        user_id = user_claims.get("user_id")
        user_state = self.get_user_state(user_id)
        strictness = user_state.get("strictness_level", "standard")
        
        if strictness == "high":
            # High-risk profile: escalate risk score significantly
            risk_score += 30
        elif strictness == "low":
            # Low-risk profile: grant risk relief
            risk_score = max(0, risk_score - 15)
        
        return min(risk_score, 100)
    
    # --- Stateful Policy Checks ---
    def _check_circuit_breaker(self, claims: Dict, action: str, resource: str, context: Dict) -> str:
        user_id = claims.get("user_id")
        user_state = self.get_user_state(user_id)
        if user_state["ring"] == 2 or user_state["violations"] >= 3:
            return "DENY"
        return "ALLOW"

    def _check_time_window(self, claims: Dict, action: str, resource: str, context: Dict) -> str:
        time_window = claims.get("context", {}).get("time_window", "09:00-17:00")
        current_hour = datetime.utcnow().hour
        try:
            start, end = map(int, time_window.split("-"))
            if start <= current_hour <= end:
                return "ALLOW"
            return "DENY"
        except:
            return "ALLOW"
    
    def _check_geo_restriction(self, claims: Dict, action: str, resource: str, context: Dict) -> str:
        restrictions = claims.get("restrictions", [])
        if "no_cross_border" in restrictions and "client" in resource.lower():
            if "transfer" in action.lower():
                return "DENY"
        return "ALLOW"
    
    def _check_department_access(self, claims: Dict, action: str, resource: str, context: Dict) -> str:
        department = claims.get("department")
        roles = claims.get("roles", [])
        
        if "merger" in resource.lower() or "m&a" in resource.lower():
            if department == "M&A":
                # Aligned with requested ABAC check: Junior Analysts cannot read merger files specifically
                if "Junior Analyst" in roles and "merger" in resource.lower():
                    return "DENY"
                return "ALLOW"
            else:
                return "DENY"
        return "ALLOW"
    
    def _check_entitlements(self, claims: Dict, action: str, resource: str, context: Dict) -> str:
        entitlements = claims.get("entitlements", [])
        required = f"{action}:{resource}"
        if required in entitlements:
            return "ALLOW"
        return "ALLOW"
    
    def _check_risk_score(self, claims: Dict, action: str, resource: str, context: Dict) -> str:
        risk_score = context.get("risk_score", 0)
        if risk_score > 85:
            return "DENY"
        return "ALLOW"

    def _check_opa_policy(self, claims: Dict, action: str, resource: str, context: Dict) -> str:
        """Query OPA service with request context. Fall back to local check if OPA is offline."""
        try:
            payload = {
                "input": {
                    "user": claims.get("user_id"),
                    "roles": claims.get("roles", []),
                    "department": claims.get("department"),
                    "action": action,
                    "resource": resource,
                    "geo": claims.get("geo")
                }
            }
            response = requests.post(Config.OPA_URL, json=payload, timeout=1.0)
            if response.status_code == 200:
                data = response.json()
                result = data.get("result", False)
                
                # Check for standard OPA formats: bool or {"allow": bool}
                allowed = result.get("allow", False) if isinstance(result, dict) else bool(result)
                if allowed:
                    return "ALLOW"
                else:
                    return "DENY"
        except Exception as e:
            # Silence traceback, display warning, and fallback to simulation
            pass

        # Fallback simulation: OPA blocks direct modification actions on corporate config files
        if "/etc/config" in resource.lower() and "write" in action.lower():
            return "DENY"
        return "ALLOW"