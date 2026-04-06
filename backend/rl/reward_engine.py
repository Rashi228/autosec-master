"""
reward_engine.py — RL Reward Shaping
====================================
Assigns numeric values to Defender actions based on specified RL components.
"""

from typing import Dict, Any
from autosec_openenv.models import Action, ActionType, SystemState

def calculate_reward(action: Action, state: SystemState, step_info: dict) -> float:
    """
    Normalized and stable reward function.
    Scale: Approx [-5.0, +10.0] per step.
    """
    score = 0.0
    a_type = action.action_type
    
    # 1. Constant Threat Burden (Pressure to act)
    # -0.5 per active threat. Max penalty -1.5 (if 3 threats)
    score -= (state.active_threats * 0.5)
    
    # 2. Action Evaluation
    if step_info.get("is_repeated", False):
        # Penalize repeating the same action if it didn't work last time
        score -= 1.0
        
    if step_info.get("redundant", False):
        score -= 0.5
    elif step_info.get("unsafe", False):
        score -= 5.0
    else:
        # Correct Targeting Reward (Discovery hint)
        if a_type in [ActionType.BLOCK_IP, ActionType.ISOLATE_HOST]:
            if step_info.get("is_correct_target", False):
                score += 2.0  # Hint: "You are looking at the right place"
                
                if step_info.get("resolved_threat", False):
                    score += 5.0  # Main reward: "You fixed it!"
            else:
                score -= 1.0  # Penalty for wrong target
                
        # Correct investigation (monitor)
        elif a_type == ActionType.MONITOR:
            if state.active_threats > 0:
                score += 0.5  # Small reward for watching active threats
            else:
                score -= 0.5

    # 3. Intermediate Progress
    if step_info.get("threat_reduced", False):
        score += 1.0

    # Ensure result is within a stable float range for PPO
    return float(score)
