"""
reward_engine.py — RL Reward Shaping
====================================
Assigns numeric values to Defender actions based on 
threat resolution and cost.
"""

from typing import Dict, Any, Optional
from autosec_openenv.models import Action, ActionType, SystemState, Severity

def calculate_reward(action: Action, state: SystemState, step_info: dict) -> float:
    """
    Reward logic for Reinforcement Learning training.
    """
    score = -0.1 # Base cost of action
    
    # 🟢 Containment Rewards
    if action.action_type in [ActionType.BLOCK_IP, ActionType.ISOLATE_HOST]:
        if step_info.get("resolved_threat", False):
            score += 0.8
        else:
            score -= 0.3 # FP Penalty
            
    # 🔴 Redundancy Penalty
    if step_info.get("redundant", False):
        score -= 0.5
        
    # 🔵 Outcome Bonus
    if state.active_threats == 0 and state.compromise_level < 5.0:
        score += 1.0 # Mission success
        
    return score

def get_reward_feedback(score: float, action: Action) -> str:
    if score > 0.5:
        return f"Excellent. {action.action_type} successfully disrupted the attack."
    if score < 0.0:
        return "Action was ineffective or redundant. Review logs."
    return "Action acknowledged. Monitor for results."
