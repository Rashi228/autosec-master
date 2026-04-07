import typing
from autosec_openenv.models import Action, SystemState, ActionType, StrategyType

def calculate_reward(action: Action, state: SystemState, step_info: dict) -> float:
    """
    Dense Reward Shaping for AutoSec RL.
    Layers:
    1. Correct Target Bonus (+0.2)
    2. Strategic Alignment Bonus (+0.1)
    3. Threat Resolution Bonus (+0.3)
    4. Error Penalty (-0.1)
    5. Efficiency Penalty (-0.05 per step)
    6. Redundancy Penalty (-0.15 for repeated same target)
    7. Invalid Target Penalty (-0.2 for empty targets on active actions)
    8. Novel Action Bonus (+0.05 for first-time action/target combinations)
    """
    reward = 0.0
    atype = action.action_type
    target = action.target or "none"
    
    # 1. Targeting Precision
    if step_info.get("is_correct_target"):
        reward += 0.2
    elif atype not in [ActionType.NO_ACTION, ActionType.MONITOR]:
        reward -= 0.1 # Penalty for targeting benign entity
        
    # 2. Strategic Alignment
    strategy = action.strategy
    alignment = False
    if strategy == StrategyType.CONTAIN and atype in [ActionType.BLOCK_IP, ActionType.ISOLATE_HOST]:
        alignment = True
    elif strategy == StrategyType.REMEDIATE and atype in [ActionType.RESET_CREDENTIALS, ActionType.TERMINATE_PROCESS]:
        alignment = True
    elif strategy in [StrategyType.DETECT, StrategyType.INVESTIGATE] and atype == ActionType.MONITOR:
        alignment = True
        
    if alignment:
        reward += 0.1
        
    # 3. Threat Resolution
    if step_info.get("resolved_threat"):
        reward += 0.3
        
    # 4. Global Maintenance / Success
    if step_info.get("is_terminal") and state.active_threats == 0:
        reward += 0.4 # Final success bonus
        
    # 5. Efficiency Penalty (Constant pressure to act fast)
    reward -= 0.05
    
    # 6. Redundancy Penalty (punish repeating the same action on same target)
    if step_info.get("is_repeated"):
        reward -= 0.15
    
    # 7. Invalid Target Penalty
    if target in ["none", "", "null", "None"] and atype not in [ActionType.NO_ACTION, ActionType.MONITOR]:
        reward -= 0.2
    
    # 8. Novel Action Bonus (reward fresh action/target combinations)
    if step_info.get("is_novel_action"):
        reward += 0.05
    
    # Clip to [0.0, 1.0] range for OpenEnv spec
    return max(0.0, min(1.0, float(reward)))
