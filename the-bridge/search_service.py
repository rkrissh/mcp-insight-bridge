from opensearchpy import OpenSearch
from typing import Dict, List, Any

class SearchService:
    def __init__(self):
        self.client = OpenSearch(
            hosts=[{'host': 'localhost', 'port': 9200}],
            http_auth=('admin', 'admin')
        )
        self.index = "the-bridge-logs"
    
    def keyword_search(self, query_string: str) -> Dict:
        """Standard query DSL search."""
        query = {
            "query": {
                "query_string": {
                    "query": query_string
                }
            },
            "sort": [{"timestamp": "desc"}],
            "size": 100
        }
        return self.client.search(index=self.index, body=query)
    
    def nlp_search(self, natural_language: str) -> Dict:
        """Convert natural language to OpenSearch query."""
        # For demo: simple keyword mapping
        query_parts = []
        
        if "blocked" in natural_language.lower():
            query_parts.append("decision:BLOCK")
        elif "allowed" in natural_language.lower():
            query_parts.append("decision:ALLOW")
        
        if "agent" in natural_language.lower():
            # Extract agent name (simplified)
            words = natural_language.split()
            for word in words:
                if "agent" in word.lower():
                    query_parts.append(f"agent_id:*{word}*")
        
        if "m&a" in natural_language.lower() or "merger" in natural_language.lower():
            query_parts.append("resource:*merger*")
        
        if "last week" in natural_language.lower():
            query_parts.append("timestamp:now-7d")
        
        query_string = " AND ".join(query_parts) if query_parts else "*"
        return self.keyword_search(query_string)
    
    def search_by_user(self, user_id: str) -> List[Dict]:
        """Search all logs for a specific user."""
        query = {
            "query": {
                "term": {"user_id": user_id}
            },
            "sort": [{"timestamp": "desc"}]
        }
        response = self.client.search(index=self.index, body=query)
        return [hit["_source"] for hit in response["hits"]["hits"]]
    
    def search_by_resource(self, resource_pattern: str) -> List[Dict]:
        """Search logs by resource pattern."""
        query = {
            "query": {
                "wildcard": {"resource": f"*{resource_pattern}*"}
            },
            "sort": [{"timestamp": "desc"}]
        }
        response = self.client.search(index=self.index, body=query)
        return [hit["_source"] for hit in response["hits"]["hits"]]