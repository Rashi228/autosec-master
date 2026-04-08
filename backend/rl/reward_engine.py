import typing
from autosec_openenv.models import Action, SystemState, ActionType, StrategyType

def calculate_reward(action: Action, state: SystemState, step_info: dict) -> float:
\
\
\
\
\
\
\
\
\
\
       
    reward = 0.0
    atype = action.action_type
    
                                          
    if step_info.get("resolved_threat"):
        reward += 1.0
        
                            
    if step_info.get("is_correct_target"):
        reward += 0.4
    elif atype not in [ActionType.NO_ACTION, ActionType.MONITOR]:
        reward -= 0.2
        
                             
    if step_info.get("is_correct_action_type"):
        reward += 0.6
        
                                                                  
    if state.status == "NORMAL":
        reward += 0.05
        
                  
    if step_info.get("is_over_isolation"):
        reward -= 0.7
        
    if step_info.get("is_ip_mismatch"):
        reward -= 0.5
        
    if step_info.get("is_repeated"):
        reward -= 0.3
    
                                
    reward -= 0.02
    
                                                                         
    final_reward = float(reward)
    print(f"DEBUG REWARD: {final_reward:0.2f} | Info: {step_info}")
    
                                          
    return max(0.0, min(1.0, final_reward))
