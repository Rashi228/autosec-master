"""
log_generator.py — Security Log Simulator
==========================================
Generates realistic security logs based on attacker 
and benign activity in the simulation.
"""

from typing import List, Dict, Any
from datetime import datetime
import uuid
import random

from autosec_openenv.models import SecurityLog, Severity, EventType, AttackAction

def generate_malicious_log(attack: AttackAction, step_id: int) -> SecurityLog:
    """
    Transforms an attack action into a high-fidelity security log.
    """
    event_type_map = {
        "BRUTE_FORCE": EventType.FAILED_LOGIN,
        "SUCCESSFUL_LOGIN": EventType.SUCCESSFUL_LOGIN,
        "PRIVILEGE_ESCALATION": EventType.PRIVILEGE_ESCALATION,
        "LATERAL_MOVEMENT": EventType.LATERAL_MOVEMENT,
        "DATA_EXFILTRATION": EventType.DATA_EXFILTRATION,
    }
    
    event_type = event_type_map.get(str(attack.attack_type), EventType.MALWARE_EXECUTION)
    
    # Severity increases as the attacker progresses
    severity = Severity.MEDIUM
    if step_id > 10 or event_type == EventType.DATA_EXFILTRATION:
        severity = Severity.CRITICAL
    elif step_id > 5:
        severity = Severity.HIGH

    return SecurityLog(
        log_id=str(uuid.uuid4())[:8],
        timestamp=datetime.now().isoformat(),
        event_type=event_type,
        source_ip=attack.source_ip,
        hostname=attack.target_host,
        severity=severity,
        raw_log=f"Suspicious {event_type.value} detected on {attack.target_host} from {attack.source_ip}",
        is_malicious=True,
        attack_stage=str(event_type.value)
    )

def generate_benign_logs(hosts: List[str], ip_map: Dict[str, str], count: int = 1) -> List[SecurityLog]:
    """Generates normal system noise."""
    logs = []
    for _ in range(count):
        host = random.choice(hosts)
        logs.append(SecurityLog(
            log_id=str(uuid.uuid4())[:8],
            timestamp=datetime.now().isoformat(),
            event_type=EventType.BENIGN_ACTIVITY,
            source_ip=ip_map.get(host, "10.0.0.1"),
            hostname=host,
            severity=Severity.LOW,
            raw_log=f"User 'system' heartbeat on {host}",
            is_malicious=False
        ))
    return logs
