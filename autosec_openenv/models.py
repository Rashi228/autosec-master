"""
models.py — Core Data Contracts for AutoSec 
==========================================
Defines the Pydantic schemas for logs, states, and actions.
"""

from enum import Enum
from typing import List, Optional, Dict, Any
from pydantic import BaseModel, Field

class Severity(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"

class EventType(str, Enum):
    PORT_SCAN = "PORT_SCAN"
    FAILED_LOGIN = "FAILED_LOGIN"
    SUCCESSFUL_LOGIN = "SUCCESSFUL_LOGIN"
    MALWARE_EXECUTION = "MALWARE_EXECUTION"
    PRIVILEGE_ESCALATION = "PRIVILEGE_ESCALATION"
    LATERAL_MOVEMENT = "LATERAL_MOVEMENT"
    DATA_EXFILTRATION = "DATA_EXFILTRATION"
    C2_HEARTBEAT = "C2_HEARTBEAT"
    PROCESS_TERMINATION = "PROCESS_TERMINATION"
    FILE_DELETION = "FILE_DELETION"
    BENIGN_ACTIVITY = "BENIGN_ACTIVITY"

class StrategyType(str, Enum):
    DETECT = "DETECT"
    INVESTIGATE = "INVESTIGATE"
    CONTAIN = "CONTAIN"
    REMEDIATE = "REMEDIATE"
    NONE = "NONE"

class TacticType(str, Enum):
    INSPECT_LOGS = "INSPECT_LOGS"
    ISOLATE_HOST = "ISOLATE_HOST"
    BLOCK_IP = "BLOCK_IP"
    NO_ACTION = "NO_ACTION"

class ActionType(str, Enum):
    BLOCK_IP = "BLOCK_IP"
    ISOLATE_HOST = "ISOLATE_HOST"
    TERMINATE_PROCESS = "TERMINATE_PROCESS"
    RESET_CREDENTIALS = "RESET_CREDENTIALS"
    NO_ACTION = "NO_ACTION"
    MONITOR = "MONITOR"

class AttackType(str, Enum):
    RECONNAISSANCE = "RECONNAISSANCE"
    BRUTE_FORCE = "BRUTE_FORCE"
    LATERAL_MOVEMENT = "LATERAL_MOVEMENT"
    EXFILTRATION = "EXFILTRATION"

class SystemStatus(str, Enum):
    NORMAL = "NORMAL"
    DEGRADED = "DEGRADED"
    CRITICAL = "CRITICAL"
    RECOVERING = "RECOVERING"

class SecurityLog(BaseModel):
    log_id: str
    timestamp: str
    event_type: EventType
    source_ip: str
    hostname: str
    severity: Severity
    raw_log: str
    is_malicious: bool = False
    attack_stage: Optional[str] = None

class SystemState(BaseModel):
    status: SystemStatus = SystemStatus.NORMAL
    compromise_level: float = 0.0 # 0.0 to 100.0
    active_threats: int = 0
    blocked_ips: List[str] = Field(default_factory=list)
    isolated_hosts: List[str] = Field(default_factory=list)
    reset_users: List[str] = Field(default_factory=list)

class Observation(BaseModel):
    step_id: int
    task_id: str
    logs: List[SecurityLog] = Field(default_factory=list)
    system_state: Dict[str, Any] = Field(default_factory=dict)
    
    # Structured Features for RL Agents
    num_active_threats: int = 0
    threat_severity_sum: int = 0
    recent_event_types: List[str] = Field(default_factory=list)
    impact_score: float = 0.0 # 0.0 to 1.0 (CriticalITY of compromised assets)
    
class Reward(BaseModel):
    value: float = Field(default=0.0, ge=0.0, le=1.0)
    deterministic_score: float = Field(default=0.0, ge=0.0, le=1.0)
    feedback: str = ""
    is_terminal: bool = False

class Action(BaseModel):
    strategy: StrategyType = StrategyType.NONE
    tactic: TacticType = TacticType.NO_ACTION
    action_type: ActionType
    target: str # IP, Hostname, or User
    reasoning: str = ""

class AttackAction(BaseModel):
    attack_type: str
    target_host: str
    source_ip: str
    reasoning: str = ""

class EpisodeResult(BaseModel):
    task_id: str
    total_steps: int
    final_grader_score: float
    cumulative_reward: float
    threats_resolved: int
    threats_total: int
    false_positives: int
    persona_scores: Dict[str, Any] = Field(default_factory=dict)
    summary: str

class TaskInfo(BaseModel):
    task_id: str
    name: str
    difficulty: str
    description: str
    max_steps: int
