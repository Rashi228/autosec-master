"""
reward_engine.py — RL Reward Shaping
====================================
Assigns numeric values to Defender actions based on specified RL components.
"""

from typing import Dict, Any
from autosec_openenv.models import Action, ActionType, SystemState

def calculate_reward(action: Action, state: SystemState, step_info: dict) -> float:
    """
    Reward logic for Reinforcement Learning training:
    - +10 correct threat detection (Not modeled yet)
    - +15 correct containment action
    - +5 correct investigation step
    - -10 missed threat
    - -5 false positive
    - -2 redundant action
    - -20 unsafe action
    """
    score = 0.0
    
    a_type = action.action_type
    
    # Check redundant action
    if step_info.get("redundant", False):
        score -= 2.0
    # Unsafe action
    elif step_info.get("unsafe", False):
        score -= 20.0
    else:
        # Correct containment action
        if a_type in [ActionType.BLOCK_IP, ActionType.ISOLATE_HOST]:
            if step_info.get("resolved_threat", False):
                score += 15.0
            else:
                score -= 5.0 # False positive

        # Correct investigation (monitor)
        elif a_type == ActionType.MONITOR:
            if state.active_threats > 0:
                score += 5.0 # Good investigation
            else:
                score -= 2.0 # Unnecessary
                
    # Missed threat if no productive action occurs when threats exist
    if a_type == ActionType.NO_ACTION and state.active_threats > 0:
        score -= 10.0

    return score
