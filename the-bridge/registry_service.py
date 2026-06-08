import sqlite3
import json
import os
from datetime import datetime
from typing import Dict, Any, List, Optional

DB_FILE = "agent_registry.db"

class RegistryService:
    def __init__(self):
        self._init_db()

    def _init_db(self):
        """Initialize SQLite database for agents and KBs, and pre-seed demo data."""
        conn = sqlite3.connect(DB_FILE)
        cursor = conn.cursor()
        
        # Create agents table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS agents (
                agent_id TEXT PRIMARY KEY,
                owner TEXT NOT NULL,
                purpose TEXT NOT NULL,
                version TEXT NOT NULL,
                status TEXT NOT NULL,
                allowed_tools TEXT NOT NULL, -- JSON string array
                kb_access TEXT NOT NULL,     -- JSON string array
                safety_score REAL DEFAULT 0.0,
                injection_resistance REAL DEFAULT 0.0,
                registered_at TEXT NOT NULL
            )
        """)
        
        # Create knowledge_bases table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS knowledge_bases (
                kb_id TEXT PRIMARY KEY,
                owner TEXT NOT NULL,
                purpose TEXT NOT NULL,
                version TEXT NOT NULL,
                status TEXT NOT NULL,
                classification_level TEXT NOT NULL, -- public, internal, confidential, restricted
                source_type TEXT NOT NULL,
                registered_at TEXT NOT NULL
            )
        """)
        
        conn.commit()
        
        # Preseed default agents if empty
        cursor.execute("SELECT COUNT(*) FROM agents")
        if cursor.fetchone()[0] == 0:
            default_agents = [
                (
                    "inspector-agent-01",
                    "sarah.lee@bank.com",
                    "VP assistant agent designed for M&A operations.",
                    "v1.0.0",
                    "active",
                    json.dumps(["read_merger_targets", "read_merger_targets_off_hours", "transfer_funds"]),
                    json.dumps(["kb-market-indices"]),
                    0.95,
                    0.97,
                    datetime.utcnow().isoformat()
                ),
                (
                    "trading-agent-02",
                    "dave.miller@bank.com",
                    "Automated trade executor agent for Trading desk operations.",
                    "v1.0.2",
                    "active",
                    json.dumps(["calculate_allocations"]),
                    json.dumps([]),
                    0.91,
                    0.89,
                    datetime.utcnow().isoformat()
                )
            ]
            cursor.executemany("""
                INSERT INTO agents (agent_id, owner, purpose, version, status, allowed_tools, kb_access, safety_score, injection_resistance, registered_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, default_agents)
            
        # Preseed default knowledge bases if empty
        cursor.execute("SELECT COUNT(*) FROM knowledge_bases")
        if cursor.fetchone()[0] == 0:
            default_kbs = [
                (
                    "kb-market-indices",
                    "market-research-group@bank.com",
                    "Ingest historical S&P and FTSE metrics for investment reference.",
                    "v1.0.0",
                    "active",
                    "confidential",
                    "opensearch_index",
                    datetime.utcnow().isoformat()
                )
            ]
            cursor.executemany("""
                INSERT INTO knowledge_bases (kb_id, owner, purpose, version, status, classification_level, source_type, registered_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """, default_kbs)
            
        conn.commit()
        conn.close()

    def get_agent(self, agent_id: str) -> Optional[Dict[str, Any]]:
        """Fetch a single agent by ID."""
        conn = sqlite3.connect(DB_FILE)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM agents WHERE agent_id = ?", (agent_id,))
        row = cursor.fetchone()
        conn.close()
        
        if row:
            res = dict(row)
            res["allowed_tools"] = json.loads(res["allowed_tools"])
            res["kb_access"] = json.loads(res["kb_access"])
            return res
        return None

    def get_kb(self, kb_id: str) -> Optional[Dict[str, Any]]:
        """Fetch a single knowledge base by ID."""
        conn = sqlite3.connect(DB_FILE)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM knowledge_bases WHERE kb_id = ?", (kb_id,))
        row = cursor.fetchone()
        conn.close()
        return dict(row) if row else None

    def list_agents(self) -> List[Dict[str, Any]]:
        """List all agents in the registry."""
        conn = sqlite3.connect(DB_FILE)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM agents ORDER BY registered_at DESC")
        rows = cursor.fetchall()
        conn.close()
        
        agents = []
        for r in rows:
            res = dict(r)
            res["allowed_tools"] = json.loads(res["allowed_tools"])
            res["kb_access"] = json.loads(res["kb_access"])
            agents.append(res)
        return agents

    def list_kbs(self) -> List[Dict[str, Any]]:
        """List all knowledge bases in the registry."""
        conn = sqlite3.connect(DB_FILE)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM knowledge_bases ORDER BY registered_at DESC")
        rows = cursor.fetchall()
        conn.close()
        return [dict(r) for r in rows]

    def add_agent(self, agent_id: str, owner: str, purpose: str, version: str, allowed_tools: List[str], kb_access: List[str]) -> bool:
        """Register a new agent in 'intake' status."""
        try:
            conn = sqlite3.connect(DB_FILE)
            cursor = conn.cursor()
            cursor.execute("""
                INSERT OR REPLACE INTO agents (agent_id, owner, purpose, version, status, allowed_tools, kb_access, safety_score, injection_resistance, registered_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                agent_id,
                owner,
                purpose,
                version,
                "intake",
                json.dumps(allowed_tools),
                json.dumps(kb_access),
                0.0,
                0.0,
                datetime.utcnow().isoformat()
            ))
            conn.commit()
            conn.close()
            return True
        except Exception as e:
            print(f"Error adding agent to registry: {e}")
            return False

    def add_kb(self, kb_id: str, owner: str, purpose: str, version: str, classification_level: str, source_type: str) -> bool:
        """Register a new knowledge base in 'active' status."""
        try:
            conn = sqlite3.connect(DB_FILE)
            cursor = conn.cursor()
            cursor.execute("""
                INSERT OR REPLACE INTO knowledge_bases (kb_id, owner, purpose, version, status, classification_level, source_type, registered_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                kb_id,
                owner,
                purpose,
                version,
                "active",
                classification_level,
                source_type,
                datetime.utcnow().isoformat()
            ))
            conn.commit()
            conn.close()
            return True
        except Exception as e:
            print(f"Error adding KB to registry: {e}")
            return False

    def run_mock_eval(self, agent_id: str) -> Optional[Dict[str, float]]:
        """Simulate running automated safety benchmarks on the agent."""
        agent = self.get_agent(agent_id)
        if not agent:
            return None
        
        # Calculate dynamic mock scores based on purpose complexity or tool requirements
        import random
        # Seed pseudo-randomly based on agent_id string to be consistent for the same agent
        random.seed(hash(agent_id))
        
        # Agents with fewer tools or simple purposes score higher; broad access lowers base scores slightly
        num_tools = len(agent["allowed_tools"])
        base_score = 0.98 - (num_tools * 0.02)
        
        safety = round(max(0.70, min(1.0, base_score + random.uniform(-0.03, 0.03))), 2)
        injection = round(max(0.70, min(1.0, base_score - 0.02 + random.uniform(-0.03, 0.03))), 2)
        
        # Save evaluations in the database
        conn = sqlite3.connect(DB_FILE)
        cursor = conn.cursor()
        cursor.execute("""
            UPDATE agents
            SET safety_score = ?, injection_resistance = ?, status = 'reviewing'
            WHERE agent_id = ?
        """, (safety, injection, agent_id))
        conn.commit()
        conn.close()
        
        return {"safety_score": safety, "injection_resistance": injection}

    def approve_agent(self, agent_id: str) -> bool:
        """Approve and allowlist the agent."""
        try:
            conn = sqlite3.connect(DB_FILE)
            cursor = conn.cursor()
            cursor.execute("UPDATE agents SET status = 'active' WHERE agent_id = ?", (agent_id,))
            conn.commit()
            conn.close()
            return True
        except Exception as e:
            print(f"Error approving agent: {e}")
            return False

    def reject_agent(self, agent_id: str) -> bool:
        """Reject and remove/archive the agent."""
        try:
            conn = sqlite3.connect(DB_FILE)
            cursor = conn.cursor()
            cursor.execute("UPDATE agents SET status = 'archived' WHERE agent_id = ?", (agent_id,))
            conn.commit()
            conn.close()
            return True
        except Exception as e:
            print(f"Error rejecting agent: {e}")
            return False

    def deprecate_agent(self, agent_id: str) -> bool:
        """Deprecate the agent (warns client during execution)."""
        try:
            conn = sqlite3.connect(DB_FILE)
            cursor = conn.cursor()
            cursor.execute("UPDATE agents SET status = 'deprecated' WHERE agent_id = ?", (agent_id,))
            conn.commit()
            conn.close()
            return True
        except Exception as e:
            print(f"Error deprecating agent: {e}")
            return False
