from opensearchpy import OpenSearch
import networkx as nx
from typing import Dict, List, Any

class SimulationEngine:
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
        self.graph = nx.DiGraph()
    
    def build_dependency_graph(self):
        """Build dependency graph from audit logs with a fallback to mock data."""
        self.graph.clear()
        
        # Default mock permissions as fallback
        mock_data = [
            ("sarah.lee@bank.com", "/data/merger_targets", "read_merger_targets"),
            ("sarah.lee@bank.com", "/data/trade_simulations", "execute"),
            ("jason.richards@bank.com", "/data/client_portfolios", "read"),
            ("dave.miller@bank.com", "/data/trade_simulations", "execute")
        ]
        
        success = False
        if self.client:
            try:
                if self.client.indices.exists(index=self.audit_index):
                    query = {
                        "query": {"term": {"decision.keyword": "ALLOW"}},
                        "size": 1000
                    }
                    response = self.client.search(index=self.audit_index, body=query)
                    hits = response["hits"]["hits"]
                    
                    if hits:
                        for hit in hits:
                            source = hit["_source"]
                            user = source.get("user_id")
                            resource = source.get("resource")
                            action = source.get("action")
                            
                            if user and resource:
                                self.graph.add_node(user, type="user")
                                self.graph.add_node(resource, type="resource")
                                self.graph.add_edge(user, resource, action=action)
                        success = True
            except Exception as e:
                print(f"[SIMULATION WARNING] Failed to query OpenSearch for graph, using fallback: {e}")

        if not success:
            # Populate fallback
            for user, resource, action in mock_data:
                self.graph.add_node(user, type="user")
                self.graph.add_node(resource, type="resource")
                self.graph.add_edge(user, resource, action=action)
    
    def simulate_revocation(self, user_id: str, resource_pattern: str) -> Dict:
        """Simulate impact of revoking access."""
        self.build_dependency_graph()
        
        if user_id not in self.graph:
            return {"error": "User not found in dependency graph"}
        
        # Find impacted resources
        impacted_resources = []
        for resource in self.graph.successors(user_id):
            if resource_pattern in resource:
                impacted_resources.append(resource)
        
        # Find dependent users
        dependent_users = set()
        for resource in impacted_resources:
            for user in self.graph.predecessors(resource):
                if user != user_id:
                    dependent_users.add(user)
        
        # Calculate blast radius metrics
        return {
            "user": user_id,
            "revocation_target": resource_pattern,
            "impacted_resources_count": len(impacted_resources),
            "impacted_resources": impacted_resources[:10],
            "dependent_users_count": len(dependent_users),
            "dependent_users": list(dependent_users)[:10],
            "risk_assessment": {
                "high": len([r for r in impacted_resources if "merger" in r.lower() or "client" in r.lower()]),
                "medium": len([r for r in impacted_resources if "internal" in r.lower()]),
                "low": len([r for r in impacted_resources if "public" in r.lower()])
            },
            "recommendation": "Proceed with caution - review high-impact resources first"
        }
    
    def dry_run_policy_change(self, new_policy_rules: List[Dict]) -> Dict:
        """Simulate the effect of applying new policy rules."""
        logs = []
        
        # Pull logs from OpenSearch if active
        if self.client:
            try:
                if self.client.indices.exists(index=self.audit_index):
                    query = {
                        "query": {"range": {"timestamp": {"gte": "now-7d"}}},
                        "size": 500
                    }
                    response = self.client.search(index=self.audit_index, body=query)
                    logs = [hit["_source"] for hit in response["hits"]["hits"]]
            except:
                pass

        # Fallback logs if OpenSearch is empty/offline
        if not logs:
            logs = [
                {"timestamp": datetime.utcnow().isoformat(), "user_id": "sarah.lee@bank.com", "action": "read_merger_targets", "resource": "/data/merger_targets", "decision": "ALLOW"},
                {"timestamp": datetime.utcnow().isoformat(), "user_id": "sarah.lee@bank.com", "action": "read_merger_targets", "resource": "/data/merger_targets", "decision": "ALLOW"},
                {"timestamp": datetime.utcnow().isoformat(), "user_id": "jason.richards@bank.com", "action": "read", "resource": "/data/client_portfolios", "decision": "ALLOW"},
                {"timestamp": datetime.utcnow().isoformat(), "user_id": "dave.miller@bank.com", "action": "read_merger_targets", "resource": "/data/merger_targets", "decision": "DENY"},
                {"timestamp": datetime.utcnow().isoformat(), "user_id": "jason.richards@bank.com", "action": "delete_database", "resource": "client_portfolio_db", "decision": "DENY"}
            ]
        
        # Simulate
        would_block = []
        would_allow = []
        
        for log in logs:
            blocked = False
            for rule in new_policy_rules:
                if rule["type"] == "block":
                    if "resource" in rule and rule["resource"] in log.get("resource", ""):
                        blocked = True
                        break
                    if "action" in rule and rule["action"] in log.get("action", ""):
                        blocked = True
                        break
            
            if blocked:
                would_block.append(log)
            else:
                would_allow.append(log)
        
        return {
            "current_allowed": len(logs),
            "dry_run_allowed": len(would_allow),
            "dry_run_blocked": len(would_block),
            "blocked_percentage": (len(would_block) / len(logs)) * 100 if logs else 0,
            "sample_blocked": would_block[:5]
        }