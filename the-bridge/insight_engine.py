from opensearchpy import OpenSearch
from datetime import datetime, timedelta
from typing import Dict
import json
import uuid

class InsightEngine:
    def __init__(self):
        try:
            self.client = OpenSearch(
                hosts=[{'host': 'localhost', 'port': 9200}],
                http_auth=('admin', 'admin'),
                timeout=5
            )
        except:
            self.client = None
            
        self.audit_index = "the-bridge-logs"
        self.insights_index = "the-bridge-insights"
        
        # Stateful privilege list for demo right-sizing revocation workflow
        self.privileges = [
            {"user": "jason.richards@bank.com", "resource": "/data/merger_targets", "action": "read"},
            {"user": "jason.richards@bank.com", "resource": "/data/client_portfolios", "action": "read"},
            {"user": "sarah.lee@bank.com", "resource": "/data/trade_simulations", "action": "execute"},
            {"user": "sarah.lee@bank.com", "resource": "/data/public_reports", "action": "read"}
        ]
    
    def analyze_unused_privileges(self, days_back: int = 30) -> Dict:
        """Find privileges that haven't been used in N days."""
        logs = []
        if self.client:
            try:
                # Get all logs from last N days
                query = {
                    "query": {
                        "range": {
                            "timestamp": {
                                "gte": f"now-{days_back}d"
                            }
                        }
                    },
                    "size": 10000
                }
                response = self.client.search(index=self.audit_index, body=query)
                logs = [hit["_source"] for hit in response["hits"]["hits"]]
            except:
                pass
        
        # Build usage map
        usage_map = {}
        for log in logs:
            user = log.get("user_id")
            resource = log.get("resource")
            action = log.get("action")
            key = f"{user}:{resource}:{action}"
            usage_map[key] = usage_map.get(key, 0) + 1
        
        # Get all known privileges from state
        all_privileges = self._get_all_privileges()
        
        # Find unused
        unused = []
        for priv in all_privileges:
            key = f"{priv['user']}:{priv['resource']}:{priv['action']}"
            if key not in usage_map:
                unused.append({
                    "privilege": priv,
                    "days_unused": days_back,
                    "recommendation": "Revoke",
                    "risk_score": self._calculate_privilege_risk(priv)
                })
        
        return {
            "unused_count": len(unused),
            "unused_privileges": unused,
            "analysis_date": datetime.utcnow().isoformat()
        }
    
    def _get_all_privileges(self) -> list:
        """Returns the stateful IAM privileges."""
        return self.privileges

    def revoke_privilege(self, user: str, resource: str, action: str):
        """Statefully revoke a privilege (right-sizing workflow)."""
        self.privileges = [
            p for p in self.privileges
            if not (p["user"] == user and p["resource"] == resource and p["action"] == action)
        ]
    
    def _calculate_privilege_risk(self, privilege: dict) -> int:
        """Calculate risk score for a privilege."""
        risk = 0
        if "merger" in privilege["resource"].lower():
            risk += 40
        if "client" in privilege["resource"].lower():
            risk += 30
        if "trade" in privilege["resource"].lower():
            risk += 20
        return min(risk, 100)
    
    def generate_recommendations(self) -> Dict:
        """Generate right-sizing recommendations."""
        unused_analysis = self.analyze_unused_privileges()
        
        recommendations = []
        for priv in unused_analysis["unused_privileges"][:10]:
            recommendations.append({
                "id": str(uuid.uuid4()),
                "type": "revoke",
                "user": priv["privilege"]["user"],
                "resource": priv["privilege"]["resource"],
                "action": priv["privilege"]["action"],
                "reason": f"Unused for {priv['days_unused']} days",
                "risk_score": priv["risk_score"],
                "impact": self._estimate_impact(priv["privilege"])
            })
        
        return {
            "recommendations": recommendations,
            "summary": {
                "total_recommendations": len(recommendations),
                "high_risk": len([r for r in recommendations if r["risk_score"] > 70]),
                "medium_risk": len([r for r in recommendations if 30 < r["risk_score"] <= 70]),
                "low_risk": len([r for r in recommendations if r["risk_score"] <= 30])
            }
        }
    
    def _estimate_impact(self, privilege: dict) -> str:
        """Estimate impact of revoking a privilege."""
        if "merger" in privilege["resource"].lower():
            return "HIGH - M&A operations may be affected"
        elif "client" in privilege["resource"].lower():
            return "MEDIUM - Client reporting may be affected"
        else:
            return "LOW - Minimal impact"
    
    def store_recommendations(self, recommendations: Dict):
        """Store recommendations in OpenSearch."""
        self.client.index(
            index=self.insights_index,
            body=recommendations,
            id=f"recommendations-{datetime.utcnow().strftime('%Y%m%d')}"
        )