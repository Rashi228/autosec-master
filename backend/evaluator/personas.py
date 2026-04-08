\
\
\
\
\
\
\
   

from typing import Dict, Any, List
from autosec_openenv.models import Action, ActionType, SystemState, SecurityLog

class MultiPersonaEvaluator:
    def __init__(self):
        pass

    def evaluate_action(self, action: Action, state: SystemState, logs: List[SecurityLog]) -> Dict[str, Any]:
\
\
           
        
                                                                    
        analyst_score = 0.5
        analyst_reasoning = "Neutral triage assessment."
        if action.action_type in [ActionType.BLOCK_IP, ActionType.ISOLATE_HOST]:
            if state.active_threats > 0:
                analyst_score = 0.9
                analyst_reasoning = "Excellent, decisive action during an active threat."
            else:
                analyst_score = 0.2
                analyst_reasoning = "Overly aggressive action when no clear threats are active."
        elif action.action_type == ActionType.MONITOR:
            if state.active_threats == 0:
                analyst_score = 0.8
                analyst_reasoning = "Appropriate monitoring of a stable environment."
            else:
                analyst_score = 0.3
                analyst_reasoning = "Passive monitoring while threats are active."

                                                           
        hunter_score = 0.5
        hunter_reasoning = "Standard log alignment."
        malicious_logs = [log for log in logs if log.is_malicious]
        if action.action_type == ActionType.NO_ACTION and malicious_logs:
            hunter_score = 0.1
            hunter_reasoning = "Missed clear indicators of compromise in recent logs."
        elif action.target and any(action.target in l.raw_log for l in malicious_logs):
            hunter_score = 1.0
            hunter_reasoning = "Target precisely correlates with observed malicious log artifacts."
            
                                                                                    
        responder_score = 0.5
        responder_reasoning = "Containment impact is standard."
        if action.action_type == ActionType.ISOLATE_HOST and action.target == "dc-01":
            responder_score = 0.1
            responder_reasoning = "CRITICAL: Never indiscriminately isolate a Domain Controller without absolute certainty."
        elif action.action_type in [ActionType.BLOCK_IP, ActionType.TERMINATE_PROCESS]:
            responder_score = 0.9
            responder_reasoning = "Targeted disruption limits the blast radius effectively."

                         
        final_score = (analyst_score * 0.3) + (hunter_score * 0.3) + (responder_score * 0.4)

        return {
            "final_persona_score": final_score,
            "personas": {
                "analyst": {"score": analyst_score, "explanation": analyst_reasoning},
                "hunter": {"score": hunter_score, "explanation": hunter_reasoning},
                "responder": {"score": responder_score, "explanation": responder_reasoning}
            }
        }
