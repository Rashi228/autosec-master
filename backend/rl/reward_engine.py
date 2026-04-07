import typing
from autosec_openenv.models import Action, SystemState, ActionType, StrategyType

def calculate_reward(action: Action, state: SystemState, step_info: dict) -> float:
    """
    Densified Reward Shaping for SOC Training.
    - Resolved Threat: +1.0
    - Correct Action Type: +0.6 (Was 0.5)
    - Correct Target: +0.4 (Was 0.3)
    - Stability Bonus: +0.05 (No new compromise)
    - Redundant Action: -0.3
    - Mismatch (IP vs Host): -0.5
    - Over-isolation: -0.7
    - Efficiency (Step): -0.02 (Was 0.05)
    """
    reward = 0.0
    atype = action.action_type
    
    # 1. Threat Resolution (High Priority)
    if step_info.get("resolved_threat"):
        reward += 1.0
        
    # 2. Targeting Precision
    if step_info.get("is_correct_target"):
        reward += 0.4
    elif atype not in [ActionType.NO_ACTION, ActionType.MONITOR]:
        reward -= 0.2
        
    # 3. Action Type Accuracy
    if step_info.get("is_correct_action_type"):
        reward += 0.6
        
    # 4. Stability Bonus (reward keeping the system status NORMAL)
    if state.status == "NORMAL":
        reward += 0.05
        
    # 5. Penalties
    if step_info.get("is_over_isolation"):
        reward -= 0.7
        
    if step_info.get("is_ip_mismatch"):
        reward -= 0.5
        
    if step_info.get("is_repeated"):
        reward -= 0.3
    
    # 6. Low Pressure Efficiency
    reward -= 0.02
    
    # 7. DEBUG OVERRIDE: Log the components to stdout for troubleshooting
    final_reward = float(reward)
    print(f"DEBUG REWARD: {final_reward:0.2f} | Info: {step_info}")
    
    # Final clamping to OpenEnv [0.0, 1.0]
    return max(0.0, min(1.0, final_reward))
