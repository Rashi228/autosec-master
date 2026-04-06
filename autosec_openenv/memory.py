"""
memory.py — Experience Memory for Lightweight RL
================================================
Stores and retrieves past security incidents to enable 
'few-shot' learning and policy improvement without GPU training.
"""

import json
import os
from typing import Any, Dict, List, Optional
from pydantic import BaseModel

MEMORY_FILE = "experience_memory.json"

class Experience(BaseModel):
    """A single episode step's experience."""
    state_summary: str
    action: str
    target: str
    reward: float
    feedback: str
    reasoning: str = ""
    success: bool
    timestamp: str
    kill_chain_stage: str = "benign"

class ExperienceMemory:
    def __init__(self, file_path: str = MEMORY_FILE):
        self.file_path = os.path.abspath(file_path) # Always use absolute path
        self.memory: List[Experience] = self.load_memory()

    def load_memory(self) -> List[Experience]:
        """Load experiences from disk, auto-creates if missing."""
        if not os.path.exists(self.file_path):
            print(f"   ℹ️ Creating new memory file at {self.file_path}")
            return []
        try:
            with open(self.file_path, "r") as f:
                data = json.load(f)
                if not isinstance(data, list):
                    print(f"   ⚠️ Warning: Memory file at {self.file_path} is not a list. Resetting.")
                    return []
                cleaned_data = []
                for item in data:
                    if not isinstance(item, dict): continue
                    # ✅ MIGRATION: Add missing fields for older schemas
                    if "timestamp" not in item:
                        item["timestamp"] = "2026-04-01T00:00:00"
                    if "kill_chain_stage" not in item:
                        item["kill_chain_stage"] = "benign"
                    cleaned_data.append(item)
                return [Experience(**item) for item in cleaned_data]
        except (json.JSONDecodeError, KeyError, Exception) as e:
            print(f"   ⚠️ Error loading memory from {self.file_path}: {e}")
            return []

    def save_experience(self, exp: Experience):
        """Add a new experience and persist to disk (with absolute path)."""
        self.memory.append(exp)
        if len(self.memory) > 100:
            self.memory = self.memory[-100:]
            
        try:
            # Use absolute path to avoid directory confusion
            abs_path = os.path.abspath(self.file_path)
            with open(abs_path, "w") as f:
                json.dump([m.model_dump() for m in self.memory], f, indent=2)
                f.flush()
                os.fsync(f.fileno()) # Force write to physical disk
            print(f"   💾 Memory saved: {len(self.memory)} experiences in {abs_path}")
        except Exception as e:
            print(f"   ❌ ERROR saving memory: {e}")

    def retrieve_similar_experience(self, current_state: str, exclude_history: Optional[List[tuple]] = None) -> Optional[Experience]:
        """
        Retrieves the most recent successful experience that matches keywords.
        Avoids redundant actions already taken in the current session.
        """
        keywords = ["FAILED_LOGIN", "PRIVILEGE_ESCALATION", "LATERAL_MOVEMENT", "EXFILTRATION", "PORT_SCAN"]
        active_keywords = [k for k in keywords if k in current_state.upper()]
        
        if not active_keywords:
            return None

        exclude_set = set(exclude_history or [])

        for exp in reversed(self.memory):
            # Only return successful actions that aren't already in our session history
            if exp.success and any(k in exp.state_summary.upper() for k in active_keywords):
                if (exp.action, exp.target) not in exclude_set:
                    return exp
        return None

    def get_failure_warnings(self) -> str:
        """Return a string summarizing recent failures to avoid repeating them."""
        failures = [m for m in self.memory if not m.success][-5:]
        if not failures:
            return ""
        
        warning = "\n⚠️ RECENT FAILURES (Do NOT repeat these mistakes):\n"
        for f in failures:
            warning += f"- Action '{f.action}' on '{f.target}' failed. Reason: {f.feedback}\n"
        return warning
