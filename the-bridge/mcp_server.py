from fastapi import FastAPI, Request
from mcp.server.sse import SseServerTransport
from mcp.server.fastmcp import FastMCP

# Initialize FastMCP Server
mcp = FastMCP("SecureBankServer")

@mcp.tool()
def read_merger_targets(limit: int = 10) -> str:
    """Read company merger targets."""
    return "Target list: Project Titan, Project Apollo, Project Phoenix"

@mcp.tool()
def transfer_funds(amount: float, source: str, destination: str) -> str:
    """Execute capital transfer."""
    return f"Successfully transferred ${amount} from {source} to {destination}."

@mcp.tool()
def delete_database(database_id: str) -> str:
    """Perform permanent database deletion."""
    return f"Database '{database_id}' permanently deleted."

# FastMCP provides sse_app() natively, which returns a Starlette app exposing /sse and /messages
app = mcp.sse_app()

if __name__ == "__main__":
    import uvicorn
    print("Starting FastMCP Server on http://127.0.0.1:8001 ...")
    uvicorn.run("mcp_server:app", host="127.0.0.1", port=8001)
