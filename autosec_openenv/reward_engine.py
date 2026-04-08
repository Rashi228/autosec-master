\
\
\
\
\
   

from typing import Dict, Any, Optional
from autosec_openenv.models import Action, ActionType, SystemState, Severity

def calculate_reward(action: Action, state: SystemState, step_info: dict) -> float:
\
\
       
    score = -0.1                      
    
                           
    if action.action_type in [ActionType.BLOCK_IP, ActionType.ISOLATE_HOST]:
        if step_info.get("resolved_threat", False):
            score += 0.8
        else:
            score -= 0.3             
            
                          
    if step_info.get("redundant", False):
        score -= 0.5
        
                     
    if state.active_threats == 0 and state.compromise_level < 5.0:
        score += 1.0                  
        
    return score

def get_reward_feedback(score: float, action: Action) -> str:
    if score > 0.5:
        return f"Excellent. {action.action_type} successfully disrupted the attack."
    if score < 0.0:
        return "Action was ineffective or redundant. Review logs."
    return "Action acknowledged. Monitor for results."
