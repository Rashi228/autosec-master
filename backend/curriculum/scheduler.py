"""
scheduler.py — Curriculum Learning Engine
=========================================
Dynamically adjusts the difficulty of the simulated environment based on 
the RL agent's running success rate and reward trend.
"""

from enum import Enum
from typing import Dict, Any

class DifficultyLevel(str, Enum):
    BASIC = "BASIC"
    INTERMEDIATE = "INTERMEDIATE"
    ADVANCED = "ADVANCED"

class CurriculumScheduler:
    def __init__(self):
        self.current_difficulty = DifficultyLevel.BASIC
        self.episode_count = 0
        self.success_history = []
        
        # Thresholds for promotion
        self.promotion_threshold = 0.85 # 85% success rate over window
        self.window_size = 20

    def record_episode(self, success: bool, final_reward: float):
        self.episode_count += 1
        self.success_history.append(success)
        
        if len(self.success_history) > self.window_size:
            self.success_history.pop(0)
            
        self._evaluate_progression()

    def _evaluate_progression(self):
        if len(self.success_history) < self.window_size:
            return
            
        success_rate = sum(self.success_history) / self.window_size
        
        if success_rate >= self.promotion_threshold:
            if self.current_difficulty == DifficultyLevel.BASIC:
                self.current_difficulty = DifficultyLevel.INTERMEDIATE
                self.success_history.clear()
            elif self.current_difficulty == DifficultyLevel.INTERMEDIATE:
                self.current_difficulty = DifficultyLevel.ADVANCED
                self.success_history.clear()

    def get_environment_params(self) -> Dict[str, Any]:
        """Returns parameters that adjust the simulator's difficulty."""
        if self.current_difficulty == DifficultyLevel.BASIC:
            return {
                "num_hosts": 3,
                "noise_level": 0.1,  # 10% benign logs
                "attacker_speed": 1,  # Attacker moves every step
                "max_active_threats": 1
            }
        elif self.current_difficulty == DifficultyLevel.INTERMEDIATE:
            return {
                "num_hosts": 10,
                "noise_level": 0.5,  # 50% benign logs
                "attacker_speed": 1,
                "max_active_threats": 3
            }
        else: # ADVANCED
            return {
                "num_hosts": 50,
                "noise_level": 0.9,  # 90% benign logs (needle in haystack)
                "attacker_speed": 2, # Attacker gets multiple moves
                "max_active_threats": 5
            }
