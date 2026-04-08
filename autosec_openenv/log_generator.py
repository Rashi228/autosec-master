\
\
\
\
\
   

from typing import List, Dict, Any
from datetime import datetime
import uuid
import random

from autosec_openenv.models import SecurityLog, Severity, EventType, AttackAction

def generate_malicious_log(attack: AttackAction, step_id: int) -> SecurityLog:
\
\
\
       
    event_type_map = {
        "BRUTE_FORCE": EventType.FAILED_LOGIN,
        "SUCCESSFUL_LOGIN": EventType.SUCCESSFUL_LOGIN,
        "PRIVILEGE_ESCALATION": EventType.PRIVILEGE_ESCALATION,
        "LATERAL_MOVEMENT": EventType.LATERAL_MOVEMENT,
        "DATA_EXFILTRATION": EventType.DATA_EXFILTRATION,
    }
    
    event_type = event_type_map.get(str(attack.attack_type), EventType.MALWARE_EXECUTION)
    
                              
    severity = Severity.MEDIUM
    if event_type in [EventType.DATA_EXFILTRATION, EventType.PRIVILEGE_ESCALATION]:
        severity = Severity.CRITICAL
    elif step_id > 8 or event_type == EventType.LATERAL_MOVEMENT:
        severity = Severity.HIGH

    return SecurityLog(
        log_id=str(uuid.uuid4())[:8],
        timestamp=datetime.now().isoformat(),
        event_type=event_type,
        source_ip=attack.source_ip,
        hostname=attack.target_host,
        severity=severity,
        raw_log=f"Suspicious {event_type.value} detected on {attack.target_host} from {attack.source_ip} (PID: {random.randint(1000, 9999)})",
        is_malicious=True,
        attack_stage=str(event_type.value)
    )

def generate_benign_logs(hosts: List[str], ip_map: Dict[str, str], count: int = 1, noisy: bool = False) -> List[SecurityLog]:
\
\
\
       
    logs = []
    for _ in range(count):
        host = random.choice(hosts)
        
        if noisy and random.random() > 0.5:
                                               
            e_type = random.choice([EventType.FAILED_LOGIN, EventType.PORT_SCAN])
            raw = f"Audit Failure: {e_type.value} during automated maintenance on {host}"
            severity = Severity.MEDIUM
        else:
            e_type = EventType.BENIGN_ACTIVITY
            raw = f"User 'system' heartbeat on {host}"
            severity = Severity.LOW

        logs.append(SecurityLog(
            log_id=str(uuid.uuid4())[:8],
            timestamp=datetime.now().isoformat(),
            event_type=e_type,
            source_ip=ip_map.get(host, "10.0.0.1"),
            hostname=host,
            severity=severity,
            raw_log=raw,
            is_malicious=False
        ))
    return logs
