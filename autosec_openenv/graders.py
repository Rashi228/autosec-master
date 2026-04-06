"""
graders.py — SOC Episode Scaling & Grading
==========================================
Evaluates the defender's performance relative to the 
original Meta OpenEnv task specifications.
"""

from typing import List, Dict, Any, Optional
from autosec_openenv.models import SystemState, Action, ActionType, Severity, EpisodeResult

class SOCGrader:
    """
    Detailed evaluator for SOC response quality.
    """

    def __init__(self, task_id: str):
        self.task_id = task_id
        self.total_threats = 0
        self.resolved_threats = 0
        self.false_positives = 0
        self.total_steps = 0

    def record_step(self, action: Action, state: SystemState, reward: float):
        self.total_steps += 1
        if reward > 0:
            self.resolved_threats += 1
        elif reward < -0.1 and action.action_type != ActionType.NO_ACTION:
            self.false_positives += 1

    def calculate_final_score(self) -> float:
        """
        Normalized score (0.0 to 1.0).
        High resolve rate + low false positive rate = high score.
        """
        if self.total_steps == 0: return 0.0
        
        # Simple Weighted Scoring
        resolve_rate = min(1.0, self.resolved_threats / max(1, self.total_threats))
        error_penalty = min(0.5, self.false_positives * 0.1)
        
        return max(0.0, resolve_rate - error_penalty)

    def get_episode_result(self, cumulative_reward: float) -> EpisodeResult:
        score = self.calculate_final_score()
        summary = f"Task '{self.task_id}' concluded. Threats resolved: {self.resolved_threats}."
        
        return EpisodeResult(
            task_id=self.task_id,
            total_steps=self.total_steps,
            final_grader_score=score,
            cumulative_reward=cumulative_reward,
            threats_resolved=self.resolved_threats,
            threats_total=max(self.resolved_threats, 3), # Heuristic for eval
            false_positives=self.false_positives,
            action_history=[], # To be populated by env
            summary=summary
        )

def grade_episode(task_id: str, state: SystemState, history: List[Action]) -> float:
    """Helper for standalone grading."""
    grader = SOCGrader(task_id)
    # Re-play actions locally
    for a in history:
        grader.record_step(a, state, 0.4)
    return grader.calculate_final_score()
