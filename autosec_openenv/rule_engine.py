\
\
\
\
\
   

from typing import Optional, List
from autosec_openenv.models import Action, ActionType, SecurityLog, Severity, EventType


class RuleEngine:
\
\
\
       

    def __init__(self):
        self.malicious_ips = set()
        self.blocked_ips = set()

    def evaluate(self, logs: List[SecurityLog], system_state: dict) -> Optional[Action]:
\
\
\
           
        if not logs:
            return Action(
                action_type=ActionType.NO_ACTION,
                target="none",
                reasoning="Rule Logic: No logs visible this step."
            )

                                                                                            
        active_threats = system_state.get("active_threats", 0)
        all_benign = all(
            log.severity == Severity.LOW and not log.is_malicious 
            for log in logs
        )
        if all_benign and active_threats == 0:
            return Action(
                action_type=ActionType.NO_ACTION,
                target="none",
                reasoning="Rule Logic: All current logs are BENIGN and no active threats detected."
            )

                                                                                 
        blocked = system_state.get("blocked_ips", [])
        isolated = system_state.get("isolated_hosts", [])
        
                                                                           
        all_handled = all(
            (log.source_ip in blocked) or (log.hostname in isolated)
            for log in logs
        )
        
        if all_handled and len(logs) > 0:
             return Action(
                 action_type=ActionType.NO_ACTION,
                 target="none",
                 reasoning="Rule Logic: All activity in this window is from already blocked/isolated sources."
             )

                                                                                
        for log in logs:
            if log.severity == Severity.CRITICAL and log.is_malicious:
                if log.source_ip not in blocked:
                    return Action(
                        action_type=ActionType.BLOCK_IP,
                        target=log.source_ip,
                        reasoning=f"Rule Logic: CRITICAL threat detected from {log.source_ip}."
                    )

        return None                                          
