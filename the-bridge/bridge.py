from fastapi import FastAPI, Request, HTTPException, Depends, Response
from fastapi.responses import StreamingResponse
import httpx
import json
import os
from typing import Dict, Any, List, Tuple
from datetime import datetime
import uuid
from opensearchpy import OpenSearch

import logging
logger = logging.getLogger("uvicorn")

from config import Config

# OpenSearch client for querying logs
os_query_client = None
try:
    os_query_client = OpenSearch(
        hosts=[{'host': Config.OPENSEARCH_HOST, 'port': Config.OPENSEARCH_PORT}],
        http_auth=(Config.OPENSEARCH_USER, Config.OPENSEARCH_PASSWORD),
        use_ssl=False,
        timeout=3.0
    )
except Exception as e:
    logger.warning(f"[QUERY CLIENT] Failed to initialize OpenSearch client: {e}")

from iam_integration import IAMIntegration
from policy_engine import ABACPolicyEngine
from audit_logger import AuditLogger
from protocol_security import ProtocolSecurity
from data_protection import DataProtection
from insight_engine import InsightEngine
from simulation_engine import SimulationEngine

# Import FastMCP server instance locally to run tools in process
from mcp_server import mcp

app = FastAPI(title="The Bridge", version="2.0.0")

# Initialize governance components
iam = IAMIntegration()
policy_engine = ABACPolicyEngine()
audit_logger = AuditLogger()
protocol_security = ProtocolSecurity()
data_protection = DataProtection()
insight_engine = InsightEngine()
simulation_engine = SimulationEngine()

# Stateful store for Human-in-the-Loop pending approvals
pending_approvals = {}

# Stateful store for completed ticket resolutions (so polling CLI clients can retrieve results)
resolved_tickets = {}

async def run_governance_pipeline(
    body: Dict[str, Any], 
    token: str, 
    simulate_mtls_fail: bool
) -> Tuple[str, Dict[str, Any], str]:
    """
    Unifies the 7-Layer security pipeline for both simplified dashboard payloads 
    and official JSON-RPC 2.0 client requests.
    
    Returns: (status_code, response_data, audit_id)
    """
    # ----------------- LAYER 1: TRANSPORT SECURITY -----------------
    if simulate_mtls_fail:
        audit_id = audit_logger.log_decision({
            "decision": "DENY",
            "action": body.get("action", "unknown"),
            "resource": body.get("resource", "unknown"),
            "agent_id": body.get("agent_id", "unknown"),
            "source": "transport_security",
            "explanation": "Transport Security Alert: mTLS certificate validation failed (Handshake Rejected)"
        })
        return "blocked", {"error": "Handshake Rejected: invalid mTLS credentials"}, audit_id
        
    # Validate Okta JWT token
    user_claims = iam.validate_okta_token(token)
    if not user_claims:
        audit_id = audit_logger.log_decision({
            "decision": "AUTH_FAILED",
            "action": body.get("action", "unknown"),
            "resource": body.get("resource", "unknown"),
            "agent_id": body.get("agent_id", "unknown"),
            "source": "IAM",
            "explanation": "Invalid or expired Okta JWT token"
        })
        return "unauthorized", {"error": "Invalid OAuth token"}, audit_id
        
    # Token Scoping check
    req_agent_id = body.get("agent_id", "unknown")
    scoped_agent = user_claims.get("entitlements", [])
    for ent in scoped_agent:
        if ent.startswith("agent:") and ent != f"agent:{req_agent_id}":
            audit_id = audit_logger.log_decision({
                "decision": "DENY",
                "action": body.get("action", "unknown"),
                "resource": body.get("resource", "unknown"),
                "agent_id": req_agent_id,
                "user_id": user_claims["user_id"],
                "source": "IAM",
                "explanation": f"Token Scoping Mismatch: Token scoped for {ent} but request sent by agent:{req_agent_id}"
            })
            return "blocked", {"error": "Forbidden: Token scoping mismatch for agent identity"}, audit_id

    # ----------------- LAYER 2: PROTOCOL SECURITY -----------------
    action = body.get("action", "unknown")
    resource = body.get("resource", "unknown")
    
    protocol_ok, protocol_error = protocol_security.verify_protocol_layers(action, resource, body)
    if not protocol_ok:
        policy_engine.record_violation(user_claims["user_id"])
        audit_id = audit_logger.log_decision({
            "decision": "DENY",
            "action": action,
            "resource": resource,
            "agent_id": req_agent_id,
            "user_id": user_claims["user_id"],
            "roles": user_claims["roles"],
            "risk_score": 90,
            "explanation": protocol_error,
            "source": "protocol_security"
        })
        return "blocked", {"error": protocol_error}, audit_id

    # ----------------- LAYER 4: DATA PROTECTION (Request Filter) -----------------
    body_filtered, redacted_in_req = data_protection.process_data_protection(body)

    # ----------------- LAYER 3: POLICY ENGINE -----------------
    azure_context = iam.get_azure_ad_context(user_claims["user_id"])
    k8s_context = iam.get_k8s_rbac_context(namespace="default", service_account="bridge-agent")
    
    policy_context = {
        "risk_score": azure_context.get("risk_score", 0),
        "sign_in_location": azure_context.get("sign_in_location", "unknown"),
        "device_compliance": azure_context.get("device_compliance", "unknown"),
        "k8s_allowed_verbs": k8s_context.get("allowed_verbs", [])
    }
    
    policy_result = policy_engine.evaluate(
        user_claims=user_claims,
        action=action,
        resource=resource,
        context=policy_context
    )
    
    # Check if policy engine returned an outright block
    if policy_result["decision"] == "DENY":
        policy_engine.record_violation(user_claims["user_id"])
        audit_id = audit_logger.log_decision({
            "decision": "DENY",
            "action": action,
            "resource": resource,
            "agent_id": req_agent_id,
            "user_id": user_claims["user_id"],
            "roles": user_claims["roles"],
            "risk_score": policy_result["risk_score"],
            "explanation": " | ".join(policy_result["reasons"]),
            "source": "policy_engine"
        })
        return "blocked", {"error": " | ".join(policy_result["reasons"])}, audit_id

    # ----------------- LAYER 5: EXECUTION CONTROL (Human-in-the-Loop) -----------------
    risk_score = policy_result["risk_score"]
    explanation_str = " | ".join(policy_result["reasons"])
    if redacted_in_req:
        explanation_str += " (Request PII Masked by DLP)"

    if risk_score >= 80:
        audit_id = audit_logger.log_decision({
            "decision": "PENDING",
            "action": action,
            "resource": resource,
            "agent_id": req_agent_id,
            "user_id": user_claims["user_id"],
            "roles": user_claims["roles"],
            "risk_score": risk_score,
            "explanation": explanation_str + " | Pending Human-in-the-Loop approval ticket",
            "source": "execution_control"
        })
        return "pending", {
            "explanation": explanation_str,
            "user_claims": user_claims,
            "risk_score": risk_score,
            "body": body_filtered
        }, audit_id

    # ----------------- LAYER 5/6: FORWARD EXECUTION -----------------
    execution_result = await execute_mcp_forward(body_filtered, req_agent_id, user_claims)
    policy_engine.record_success(user_claims["user_id"])
    
    # ----------------- LAYER 4: DATA PROTECTION (Response Filter) -----------------
    final_output, redacted_in_res = data_protection.process_data_protection(execution_result)
    
    explanation_final = "Authorized access"
    if redacted_in_res:
        explanation_final += " (Response PII Masked by DLP)"
        
    audit_id = audit_logger.log_decision({
        "decision": "ALLOW",
        "action": action,
        "resource": resource,
        "agent_id": req_agent_id,
        "user_id": user_claims["user_id"],
        "roles": user_claims["roles"],
        "risk_score": risk_score,
        "explanation": explanation_final,
        "source": "bridge"
    })
    
    return "allowed", final_output, audit_id


# --- Direct REST endpoints for CLI scripts & Streamlit Console ---

@app.get("/mcp/tools")
async def get_tools_list():
    """Retrieve registered tools list directly from the in-process FastMCP instance (Session-Free)."""
    tools = await mcp.list_tools()
    return [
        {
            "name": t.name,
            "description": t.description,
            "inputSchema": t.inputSchema
        }
        for t in tools
    ]


@app.post("/mcp/call")
async def call_mcp_tool_direct(request: Request):
    """
    Directly execute an MCP tool on the FastMCP instance, 
    running it through the 7-Layer governance rules.
    """
    body = await request.json()
    headers = request.headers
    
    # Extract token
    token = extract_token(request)
    simulate_mtls = headers.get("X-Simulate-mTLS-Fail") == "true"
    
    tool_name = body.get("tool_name")
    arguments = body.get("arguments", {})
    agent_id = body.get("agent_id", "inspector-agent-01")
    
    # Map tool name to target resource for rules
    resource = "/data/unknown"
    if tool_name == "read_merger_targets":
        resource = "/data/merger_targets"
    elif tool_name == "transfer_funds":
        resource = "/data/client_portfolios"
    elif tool_name == "delete_database":
        resource = arguments.get("database_id", "/data/unknown")
        
    body_eval = {
        "action": tool_name,
        "resource": resource,
        "agent_id": agent_id,
        "params": arguments
    }
    
    status, result, audit_id = await run_governance_pipeline(body_eval, token, simulate_mtls)
    
    if status == "unauthorized":
        raise HTTPException(status_code=401, detail="Invalid OAuth token")
    elif status == "blocked":
        return {
            "status": "blocked",
            "reason": result.get("error"),
            "audit_id": audit_id
        }
    elif status == "pending":
        # Save ticket in pending queue
        pending_approvals[audit_id] = {
            "audit_id": audit_id,
            "timestamp": datetime.utcnow().isoformat(),
            "body": body_eval,
            "user_claims": result["user_claims"],
            "risk_score": result["risk_score"],
            "explanation": result["explanation"],
            "protocol_type": "direct_call"
        }
        return {
            "status": "pending",
            "reason": "Request requires human compliance sign-off via Slack/dashboard approval queue",
            "risk_score": result["risk_score"],
            "audit_id": audit_id
        }
        
    # Allowed: Execute locally
    try:
        execution_res = await mcp.call_tool(tool_name, arguments)
        text_outputs = [item.text if hasattr(item, "text") else str(item) for item in execution_res]
        output_data = {"result": "\n".join(text_outputs)}
        
        # Apply DLP Response Masking
        final_output, _ = data_protection.process_data_protection(output_data)
        
        return {
            "status": "allowed",
            "data": final_output,
            "audit_id": audit_id
        }
    except Exception as e:
        return {
            "status": "error",
            "reason": f"Execution error: {e}",
            "audit_id": audit_id
        }


@app.post("/mcp/proxy")
async def mcp_proxy(request: Request):
    """Legacy endpoint proxying simplified JSON format to local FastMCP."""
    body = await request.json()
    headers = request.headers
    
    # Translate to direct tool call format
    tool_name = body.get("action")
    resource = body.get("resource")
    agent_id = body.get("agent_id")
    params = body.get("params", {})
    
    token = extract_token(request)
    simulate_mtls = headers.get("X-Simulate-mTLS-Fail") == "true"
    
    body_eval = {
        "action": tool_name,
        "resource": resource,
        "agent_id": agent_id,
        "params": params
    }
    
    status, result, audit_id = await run_governance_pipeline(body_eval, token, simulate_mtls)
    
    if status == "unauthorized":
        raise HTTPException(status_code=401, detail="Invalid OAuth token")
    elif status == "blocked":
        return {"status": "blocked", "reason": result.get("error"), "audit_id": audit_id}
    elif status == "pending":
        pending_approvals[audit_id] = {
            "audit_id": audit_id,
            "timestamp": datetime.utcnow().isoformat(),
            "body": body_eval,
            "user_claims": result["user_claims"],
            "risk_score": result["risk_score"],
            "explanation": result["explanation"],
            "protocol_type": "custom"
        }
        return {
            "status": "pending",
            "reason": "Request requires human compliance approval",
            "risk_score": result["risk_score"],
            "audit_id": audit_id
        }
        
    # Allowed: Execute locally
    try:
        execution_res = await mcp.call_tool(tool_name, params)
        text_outputs = [item.text if hasattr(item, "text") else str(item) for item in execution_res]
        output_data = {"result": "\n".join(text_outputs)}
        final_output, _ = data_protection.process_data_protection(output_data)
        
        return {"status": "allowed", "data": final_output, "audit_id": audit_id}
    except Exception as e:
        return {"status": "error", "reason": str(e), "audit_id": audit_id}
# ----------------- LAYER 7: OBSERVABILITY & STANDARDS PROXIES -----------------

def extract_token(request: Request) -> str:
    # 1. Try Authorization header
    auth_header = request.headers.get("Authorization", "")
    if auth_header.startswith("Bearer "):
        token = auth_header.replace("Bearer ", "", 1).strip()
    elif auth_header:
        token = auth_header.strip()
    else:
        token = ""
        
    # 2. Try custom 'token' header
    if not token:
        token_header = request.headers.get("token", "")
        if token_header:
            token = token_header.strip()
        
    # 3. Try query parameter 'token'
    if not token:
        token_param = request.query_params.get("token", "")
        if token_param:
            token = token_param.strip()
        
    # 4. Try query parameter 'authorization'
    if not token:
        auth_param = request.query_params.get("authorization", "")
        if auth_param.startswith("Bearer "):
            token = auth_param.replace("Bearer ", "", 1).strip()
        elif auth_param:
            token = auth_param.strip()
            
    # 5. DEMO FALLBACK: Default to Sarah Lee's valid JWT token if client fails to send it
    if not token:
        token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJodHRwczovL2Rldi0xMjM0NTYub2t0YS5jb20iLCJhdWQiOiJhcGk6Ly90aGUtYnJpZGdlIiwiZXhwIjoxNzgwNzc3MTgwLCJzdWIiOiJzYXJhaC5sZWVAYmFuay5jb20iLCJncm91cHMiOlsiVlAiLCJEaXJlY3RvciJdLCJkZXBhcnRtZW50IjoiTSZBIiwiZ2VvIjoiTG9uZG9uLCBVSyIsInJlc3RyaWN0aW9ucyI6W10sImVudGl0bGVtZW50cyI6WyJhZ2VudDppbnNwZWN0b3ItYWdlbnQtMDEiXSwiY29udGV4dCI6eyJ0aW1lX3dpbmRvdyI6IjAwOjAwLTIzOjAwIn19.cqu9VG8EWaACMxSPtoJ5P-nK_b-kYKQIc89kRbnzAWc"
        logger.warning(f"[DEMO FALLBACK] No token provided by client. Using fallback token for Sarah Lee.")
        
    return token

@app.get("/sse")
async def handle_sse_proxy(request: Request):
    """Establishes a transparent async streaming proxy connection to the backend FastMCP server."""
    backend_url = "http://127.0.0.1:8001/sse"
    token = extract_token(request)
    
    async def generate():
        async with httpx.AsyncClient(timeout=None) as client:
            async with client.stream(
                "GET", 
                backend_url, 
                params=request.query_params,
                headers={k: v for k, v in request.headers.items() if k.lower() != "host"}
            ) as response:
                endpoint_sent = False
                event_buffer = ""
                
                async for chunk in response.aiter_bytes():
                    if endpoint_sent:
                        yield chunk
                    else:
                        event_buffer += chunk.decode("utf-8", errors="ignore")
                        if "\r\n\r\n" in event_buffer or "\n\n" in event_buffer:
                            delimiter = "\r\n\r\n" if "\r\n\r\n" in event_buffer else "\n\n"
                            parts = event_buffer.split(delimiter, 1)
                            first_event = parts[0]
                            rest = parts[1] if len(parts) > 1 else ""
                            
                            modified_lines = []
                            for line in first_event.split("\n"):
                                clean_line = line.strip("\r")
                                if clean_line.startswith("data: /messages") and token:
                                    separator = "&" if "?" in clean_line else "?"
                                    clean_line = f"{clean_line}{separator}token={token}"
                                if line.endswith("\r"):
                                    modified_lines.append(clean_line + "\r")
                                else:
                                    modified_lines.append(clean_line)
                            
                            modified_event = "\n".join(modified_lines) + delimiter
                            yield modified_event.encode("utf-8")
                            if rest:
                                yield rest.encode("utf-8")
                            endpoint_sent = True
                        elif len(event_buffer) > 2000:
                            yield event_buffer.encode("utf-8")
                            endpoint_sent = True

    return StreamingResponse(
        generate(), 
        media_type="text/event-stream"
    )


@app.post("/messages/")
@app.post("/messages")
async def handle_messages_proxy(request: Request):
    """Handles standard JSON-RPC 2.0 message endpoints for the official external Inspector."""
    body = await request.json()
    headers = request.headers
    query_str = str(request.query_params)
    
    is_jsonrpc = body.get("jsonrpc") == "2.0"
    method = body.get("method")
    
    token = extract_token(request)
    auth_header = headers.get("Authorization", "")
    logger.warning(f"[DEBUG] Received Auth Header: '{auth_header}'")
    logger.warning(f"[DEBUG] Extracted Token: '{token}'")
    simulate_mtls = headers.get("X-Simulate-mTLS-Fail") == "true"
    
    if not is_jsonrpc:
        raise HTTPException(status_code=400, detail="Invalid protocol. Expected JSON-RPC 2.0")
        
    if method == "tools/list":
        return await forward_raw_jsonrpc(body, query_str)
        
    if method == "tools/call":
        params = body.get("params", {})
        action = params.get("name", "unknown")
        args = params.get("arguments", {})
        
        resource = "/data/unknown"
        if action == "read_merger_targets":
            resource = "/data/merger_targets"
        elif action == "transfer_funds":
            resource = "/data/client_portfolios"
        elif action == "delete_database":
            resource = args.get("database_id", "/data/unknown")
            
        body_eval = {
            "action": action,
            "resource": resource,
            "agent_id": args.get("agent_id", "inspector-agent-01"),
            "params": args
        }
        
        status, result, audit_id = await run_governance_pipeline(body_eval, token, simulate_mtls)
        
        if status == "unauthorized":
            return {"jsonrpc": "2.0", "error": {"code": -32001, "message": "Authentication Required"}, "id": body.get("id")}
        elif status == "blocked":
            return {"jsonrpc": "2.0", "error": {"code": -32003, "message": f"Blocked by Gateway: {result.get('error')}"}, "id": body.get("id")}
        elif status == "pending":
            pending_approvals[audit_id] = {
                "audit_id": audit_id,
                "timestamp": datetime.utcnow().isoformat(),
                "body": body_eval,
                "raw_jsonrpc": body,
                "user_claims": result["user_claims"],
                "risk_score": result["risk_score"],
                "explanation": result["explanation"],
                "protocol_type": "jsonrpc"
            }
            return {
                "jsonrpc": "2.0",
                "error": {"code": -32002, "message": f"Escalated: Held as PENDING (Ticket: {audit_id})"},
                "id": body.get("id")
            }
            
        # Forward tool execution to backend server to return results on SSE stream
        return await forward_raw_jsonrpc(body, query_str)
        
    return await forward_raw_jsonrpc(body, query_str)


async def execute_mcp_forward(body: Dict, agent_id: str, user_claims: Dict) -> Dict:
    """Fallback helper to run tools locally on FastMCP instance."""
    try:
        execution_res = await mcp.call_tool(body.get("action"), body.get("params", {}))
        text_outputs = [item.text if hasattr(item, "text") else str(item) for item in execution_res]
        return {"result": "\n".join(text_outputs)}
    except Exception as e:
        return {"error": str(e)}


async def forward_raw_jsonrpc(body: Dict, query_params: str = ""):
    """Forwards standard JSON-RPC 2.0 calls directly to the FastMCP backend."""
    try:
        url = Config.MCP_SERVER_URL
        if query_params:
            url += f"?{query_params}" if "?" not in url else f"&{query_params}"
            
        async with httpx.AsyncClient(timeout=5.0, follow_redirects=True) as client:
            res = await client.post(url, json=body)
            return Response(
                content=res.content,
                status_code=res.status_code,
                headers=dict(res.headers)
            )
    except Exception as e:
        return {"jsonrpc": "2.0", "error": {"code": -32603, "message": f"Server error: {e}"}, "id": body.get("id")}


# --- Human-in-the-Loop endpoints & Ticket Polling ---

@app.get("/audit/ticket/{audit_id}")
async def check_ticket_status(audit_id: str):
    """Check if a pending ticket has been resolved (approved/denied) by the admin."""
    if audit_id in pending_approvals:
        return {"status": "pending"}
    elif audit_id in resolved_tickets:
        return resolved_tickets[audit_id]
    else:
        return {"status": "not_found"}


@app.post("/audit/approve/{audit_id}")
async def approve_request(audit_id: str):
    """Approve a pending request and resolve execution."""
    if audit_id not in pending_approvals:
        raise HTTPException(status_code=404, detail="Approval ticket not found")
        
    ticket = pending_approvals.pop(audit_id)
    body = ticket["body"]
    user_claims = ticket["user_claims"]
    agent_id = body.get("agent_id", "unknown")
    protocol_type = ticket.get("protocol_type", "custom")
    
    # Execute tool locally
    try:
        execution_res = await mcp.call_tool(body.get("action"), body.get("params", {}))
        text_outputs = [item.text if hasattr(item, "text") else str(item) for item in execution_res]
        result = {"result": "\n".join(text_outputs)}
    except Exception as e:
        result = {"error": str(e)}
        
    # Mask response PII
    final_output, _ = data_protection.process_data_protection(result)
    
    # Log allowed decision
    audit_logger.log_decision({
        "decision": "ALLOW",
        "action": body.get("action", "unknown"),
        "resource": body.get("resource", "unknown"),
        "agent_id": agent_id,
        "user_id": user_claims["user_id"],
        "roles": user_claims["roles"],
        "risk_score": ticket["risk_score"],
        "explanation": f"Admin Approved: {ticket['explanation']}",
        "source": "execution_control",
        "approver": "compliance_admin@bank.com",
        "justification": "Authorized temporary administrative execution"
    })
    
    policy_engine.record_success(user_claims["user_id"])
    
    # Store resolution in state
    resolution_data = {
        "status": "approved",
        "data": final_output
    }
    resolved_tickets[audit_id] = resolution_data
    
    return resolution_data


@app.post("/audit/deny/{audit_id}")
async def deny_request(audit_id: str, justification: str = "Request rejected by compliance officer"):
    """Deny a pending request."""
    if audit_id not in pending_approvals:
        raise HTTPException(status_code=404, detail="Approval ticket not found")
        
    ticket = pending_approvals.pop(audit_id)
    body = ticket["body"]
    user_claims = ticket["user_claims"]
    agent_id = body.get("agent_id", "unknown")
    
    # Record violation
    policy_engine.record_violation(user_claims["user_id"])
    
    # Log denied decision
    audit_logger.log_decision({
        "decision": "DENY",
        "action": body.get("action", "unknown"),
        "resource": body.get("resource", "unknown"),
        "agent_id": agent_id,
        "user_id": user_claims["user_id"],
        "roles": user_claims["roles"],
        "risk_score": ticket["risk_score"],
        "explanation": f"Admin Denied: {justification}",
        "source": "execution_control",
        "approver": "compliance_admin@bank.com",
        "justification": justification
    })
    
    resolution_data = {
        "status": "denied",
        "reason": justification
    }
    resolved_tickets[audit_id] = resolution_data
    
    return resolution_data


@app.get("/audit/logs")
async def get_audit_logs(limit: int = 100):
    """Retrieve recent audit logs from OpenSearch or fall back to local log file."""
    # 1. Try querying OpenSearch
    if os_query_client:
        try:
            response = os_query_client.search(
                index="the-bridge-logs",
                body={
                    "size": limit,
                    "sort": [{"timestamp": "desc"}]
                }
            )
            return response["hits"]["hits"]
        except Exception as e:
            pass
            
    # 2. Fallback: Parse from local JSON audit log file
    try:
        if os.path.exists(Config.AUDIT_LOG_FILE):
            logs = []
            with open(Config.AUDIT_LOG_FILE, "r") as f:
                for line in f:
                    line = line.strip()
                    if line:
                        logs.append({"_source": json.loads(line)})
            # Sort descending by timestamp (reverse order since we append to the file)
            logs.reverse()
            return logs[:limit]
    except Exception as e:
        print(f"[ERROR] Fallback local log parser failed: {e}")
        
    return []


@app.get("/audit/pending")
async def get_pending_tickets():
    """Retrieve the list of pending Human-in-the-Loop approval tickets."""
    return list(pending_approvals.values())


@app.get("/trust/state/{user_id}")
async def get_user_trust_state(user_id: str):
    """Retrieve the dynamic trust ring state for a user."""
    return policy_engine.get_user_state(user_id)


@app.post("/trust/reset/{user_id}")
async def reset_user_trust_state(user_id: str):
    """Reset the trust state and clear violations for a user."""
    policy_engine.reset_user_trust(user_id)
    return {"status": "success"}


@app.get("/insights/recommendations")
async def get_insights():
    """Retrieve right-sizing privileges recommendations from the Insight Engine."""
    try:
        return insight_engine.generate_recommendations()
    except Exception as e:
        print(f"[ERROR] Error generating recommendations: {e}")
        return {"recommendations": [], "summary": {}}


@app.post("/insights/revoke")
async def run_privilege_revocation(request: Request):
    """On-Demand workflow: Trigger privilege revocation in the Mock IAM store."""
    body = await request.json()
    user = body.get("user")
    resource = body.get("resource")
    action = body.get("action")
    
    insight_engine.revoke_privilege(user, resource, action)
    policy_engine.clear_suggested_revocations(user)
    
    # Log the compliance action
    audit_logger.log_decision({
        "decision": "ALLOW",
        "action": "revoke_access",
        "resource": resource,
        "agent_id": "compliance_dashboard",
        "user_id": user,
        "risk_score": 10,
        "explanation": f"On-Demand Revocation: Revoked unused privilege '{action}:{resource}' for user {user}.",
        "source": "insight_engine"
    })
    return {"status": "success"}


@app.post("/trust/strictness")
async def update_user_strictness_level(request: Request):
    """Feedback Loop: Update strictness profile (low, standard, high) dynamically."""
    body = await request.json()
    user_id = body.get("user_id")
    level = body.get("level", "standard")
    policy_engine.set_user_strictness(user_id, level)
    return {"status": "success"}


@app.post("/simulate/revocation")
async def run_simulation_revocation(request: Request):
    """Blast Radius Simulator: Build dependency graph and analyze revocation impact."""
    body = await request.json()
    user_id = body.get("user_id")
    resource_pattern = body.get("resource_pattern")
    return simulation_engine.simulate_revocation(user_id, resource_pattern)


@app.post("/simulate/dry-run")
async def run_simulation_dry_run(request: Request):
    """Dry Run: Simulate the block impact of new policy rules on historical logs."""
    body = await request.json()
    new_policy_rules = body.get("new_policy_rules", [])
    return simulation_engine.dry_run_policy_change(new_policy_rules)


@app.get("/simulate/graph")
async def get_simulation_graph():
    """Retrieve NetworkX graph nodes and edges for visualization."""
    simulation_engine.build_dependency_graph()
    nodes = []
    for node in simulation_engine.graph.nodes:
        node_type = simulation_engine.graph.nodes[node].get("type", "unknown")
        nodes.append({"id": node, "type": node_type})
    
    edges = []
    for u, v in simulation_engine.graph.edges:
        action = simulation_engine.graph.edges[u, v].get("action", "")
        edges.append({"source": u, "target": v, "action": action})
        
    return {"nodes": nodes, "edges": edges}


@app.get("/audit/chain/{audit_id}")
async def get_audit_chain(audit_id: str):
    """Trace and return the cryptographic SHA-256 hash chain for an audit log."""
    return audit_logger.get_hash_chain(audit_id)