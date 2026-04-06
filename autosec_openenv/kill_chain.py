"""
kill_chain.py — Cyber Kill Chain Detection Logic
================================================
Maps security logs to standardized attack stages.
Used to help the Defender Agent prioritize actions.
"""

from enum import Enum
from typing import List, Optional
from autosec_openenv.models import SecurityLog

class KillChainStage(str, Enum):
    RECONNAISSANCE = "reconnaissance"
    INITIAL_ACCESS = "initial_access"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    LATERAL_MOVEMENT = "lateral_movement"
    EXFILTRATION = "exfiltration"
    C2_COMMUNICATION = "c2_communication"
    CLEANUP = "cleanup"
    BENIGN = "benign"

# Mapping log types to kill chain stages
STAGE_MAPPING = {
    "PORT_SCAN": KillChainStage.RECONNAISSANCE,
    "FAILED_LOGIN": KillChainStage.RECONNAISSANCE,
    "SUCCESSFUL_LOGIN": KillChainStage.INITIAL_ACCESS,
    "PRIVILEGE_ESCALATION": KillChainStage.PRIVILEGE_ESCALATION,
    "LATERAL_MOVEMENT": KillChainStage.LATERAL_MOVEMENT,
    "DATA_EXFILTRATION": KillChainStage.EXFILTRATION,
    "C2_HEARTBEAT": KillChainStage.C2_COMMUNICATION,
    "PROCESS_TERMINATION": KillChainStage.CLEANUP,
    "FILE_DELETION": KillChainStage.CLEANUP,
    "BENIGN_ACTIVITY": KillChainStage.BENIGN,
}

# Priority of stages (higher is more critical)
STAGE_PRIORITY = {
    KillChainStage.BENIGN: 0,
    KillChainStage.RECONNAISSANCE: 1,
    KillChainStage.INITIAL_ACCESS: 2,
    KillChainStage.C2_COMMUNICATION: 3,
    KillChainStage.PRIVILEGE_ESCALATION: 4,
    KillChainStage.LATERAL_MOVEMENT: 5,
    KillChainStage.EXFILTRATION: 6,
}

def detect_stage(logs: List[SecurityLog]) -> KillChainStage:
    """
    Analyzes a window of logs and returns the most critical 
    Kill Chain stage detected.
    """
    if not logs:
        return KillChainStage.BENIGN
        
    highest_stage = KillChainStage.BENIGN
    highest_priority = -1
    
    for log in logs:
        # Handle both Pydantic objects and raw dicts from the API
        e_type = log.event_type if hasattr(log, "event_type") else log.get("event_type")
        stage = STAGE_MAPPING.get(e_type, KillChainStage.BENIGN)
        priority = STAGE_PRIORITY.get(stage, 0)
        
        if priority > highest_priority:
            highest_priority = priority
            highest_stage = stage
            
    return highest_stage

def get_recommended_action_category(stage: KillChainStage) -> str:
    """
    Returns the recommended action category based on the attacker's progress.
    """
    if stage in [KillChainStage.RECONNAISSANCE, KillChainStage.INITIAL_ACCESS]:
        return "CONTAINMENT (BLOCK_IP)"
    if stage in [KillChainStage.PRIVILEGE_ESCALATION, KillChainStage.LATERAL_MOVEMENT]:
        return "CONTAINMENT (ISOLATE_HOST)"
    if stage == KillChainStage.EXFILTRATION:
        return "URGENT CONTAINMENT + ESCALATION"
    return "MONITOR / NO_ACTION"
