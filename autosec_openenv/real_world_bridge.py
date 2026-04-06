"""
real_world_bridge.py — SOC Production Ingestion
===============================================
A bridge to ingest real-world security logs into the AutoSec 
Defender Brain. Maps external log formats to Internal models.
"""

import json
import os
import time
from typing import List, Dict, Any
from datetime import datetime

# Import Internal SOC logic
from autosec_openenv.models import SecurityLog, SystemState, Observation, ActionType, Severity, EventType
from inference import _llm_action

# Configuration
LOG_INGESTION_PATH = "real_logs.json"
STATE_FILE = "soc_runtime_state.json"

class SOCProductionBridge:
    """
    Manages the ingestion of external logs and tracks the 
    internal 'Protection State' during real-world operation.
    """

    def __init__(self):
        self.system_state = self._load_state()
        self.action_history = []

    def _load_state(self) -> SystemState:
        """Loads persistent status of blocks and isolations."""
        if os.path.exists(STATE_FILE):
            try:
                with open(STATE_FILE, "r") as f:
                    return SystemState(**json.load(f))
            except:
                pass
        return SystemState()

    def _save_state(self):
        """Save blocks/isolations to disk."""
        with open(STATE_FILE, "w") as f:
            json.dump(self.system_state.model_dump(), f, indent=2)

    def ingest_logs(self, raw_logs: List[Dict[str, Any]]):
        """Processes a batch of external logs through the SOC decision loop."""
        
        # 1. Map raw logs to Internal SecurityLog Model
        processed_logs = []
        for raw in raw_logs:
            try:
                sl = SecurityLog(
                    log_id=raw.get("id") or str(time.time()),
                    timestamp=raw.get("time") or datetime.now().isoformat(),
                    event_type=EventType(raw.get("type", "BENIGN_ACTIVITY")),
                    source_ip=raw.get("src", "0.0.0.0"),
                    hostname=raw.get("host", "unknown"),
                    severity=Severity(raw.get("severity", "LOW")),
                    raw_log=json.dumps(raw),
                    is_malicious=True # In production, we assume we want to triage them
                )
                processed_logs.append(sl)
            except Exception as e:
                print(f"   ⚠️ Log Parse Error: {e}")

        if not processed_logs:
            print("[*] No valid logs to process.")
            return

        # 2. Build Observation
        obs = Observation(
            step_id=int(time.time()),
            task_id="REAL_WORLD_TRIAGE",
            logs=processed_logs,
            system_state=self.system_state,
            done=False
        )

        # 3. Get Defender Action
        print(f"\n[*] SOC ANALYZING BATCH OF {len(processed_logs)} LOGS...")
        action_dict = _llm_action(obs.model_dump(), history=self.action_history)
        
        # 4. Apply Action & Track History
        action_type = action_dict["action_type"]
        target = action_dict["target"]
        reasoning = action_dict["reasoning"]

        self.action_history.append((action_type, target))
        if len(self.action_history) > 20: self.action_history.pop(0)

        print(f"   >>> DECISION: {action_type} on {target}")
        print(f"   >>> REASONING: {reasoning}")

        # 5. Update State if action is a containment move
        if action_type == ActionType.BLOCK_IP:
            if target not in self.system_state.blocked_ips:
                self.system_state.blocked_ips.append(target)
                self.system_state.active_threats = max(0, self.system_state.active_threats - 1)
        elif action_type == ActionType.ISOLATE_HOST:
            if target not in self.system_state.isolated_hosts:
                self.system_state.isolated_hosts.append(target)
                self.system_state.active_threats = max(0, self.system_state.active_threats - 1)

        self._save_state()
        print(f"[*] State Updated. Blocked IPs: {len(self.system_state.blocked_ips)} | Isolated Hosts: {len(self.system_state.isolated_hosts)}")

def simulate_real_logs():
    """Generates a small 'Real World' log file for testing."""
    sample_logs = [
        {"type": "FAILED_LOGIN", "src": "194.16.1.5", "host": "web-prod-01", "severity": "MEDIUM"},
        {"type": "LATERAL_MOVEMENT", "src": "10.0.5.12", "host": "dc-01", "severity": "HIGH"}
    ]
    with open(LOG_INGESTION_PATH, "w") as f:
        json.dump(sample_logs, f)
    print(f"[*] Sample real-world logs created at {LOG_INGESTION_PATH}")

if __name__ == "__main__":
    # Create sample logs if missing
    if not os.path.exists(LOG_INGESTION_PATH):
        simulate_real_logs()

    # Load and process
    bridge = SOCProductionBridge()
    with open(LOG_INGESTION_PATH, "r") as f:
        incoming = json.load(f)
    
    bridge.ingest_logs(incoming)
