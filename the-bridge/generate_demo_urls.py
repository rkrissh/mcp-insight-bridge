import jwt
import datetime
import time
from run_agents_demo import scenarios

def get_jwt_token(sc):
    token_agent = "inspector-agent-01"
    payload = {
        "iss": "https://dev-123456.okta.com",
        "aud": "api://the-bridge",
        "exp": int(time.time()) + 86400,  # Valid for 24 hours
        "sub": sc["user"],
        "groups": sc["roles"],
        "department": sc["department"],
        "geo": sc["geo"],
        "restrictions": sc["restrictions"],
        "entitlements": [f"agent:{token_agent}"],
        "context": {
            "time_window": sc.get("time_window", "00:00-23:00")
        }
    }
    return jwt.encode(payload, "secret", algorithm="HS256")

def main():
    print("=========================================================================")
    print("🛡️  THE BRIDGE: MCP SECURITY GATEWAY DEMO URL GENERATOR 🛡️")
    print("Generate fresh SSE connection URLs with JWT tokens for the MCP Inspector.")
    print("=========================================================================\n")
    
    for idx, sc in scenarios.items():
        token = get_jwt_token(sc)
        sse_url = f"http://localhost:8000/sse?token={token}"
        
        print(f"🎬 Scenario {idx}: {sc['title']}")
        print(f"📄 Description: {sc['desc']}")
        print(f"🔗 Inspector SSE URL:")
        print(f"{sse_url}")
        print("-" * 80 + "\n")

if __name__ == "__main__":
    main()
