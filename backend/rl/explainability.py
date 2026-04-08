\
\
\
\
   

from typing import Dict, Any, List
from autosec_openenv.models import Action, SecurityLog

def generate_action_explanation(action: Action, logs: List[SecurityLog], persona_feedback: Dict[str, Any]) -> Dict[str, Any]:
\
\
       
    
                                       
    evidence = []
    if action.target:
        evidence = [log.raw_log for log in logs if action.target in log.raw_log][-3:]
        
    explanation = {
        "action": action.action_type,
        "target": action.target,
        "strategy": action.strategy,
        "tactic": action.tactic,
        "reasoning": action.reasoning or "Automated policy execution.",
        "confidence": round(persona_feedback.get("final_persona_score", 0.8), 2),
        "evidence": evidence,
        "persona_evaluations": persona_feedback.get("personas", {})
    }
    
    return explanation
