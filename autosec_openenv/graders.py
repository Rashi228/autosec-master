"""
graders.py — SOC Episode Scoring & Grading
==========================================
Evaluates defender performance with partial credit scoring.
Formula: (resolved / total) - (errors × 0.02), bounded [0.0, 1.0]
"""

from typing import List, Any
from autosec_openenv.models import SystemState, Action, ActionType, EpisodeResult
from backend.evaluator.personas import MultiPersonaEvaluator


class SOCGrader:
    """
    Grader for OpenEnv SOC scenarios.
    Supports partial credit and persona-weighted scoring.
    """

    def __init__(self, task_id: str):
        self.task_id = task_id
        self.evaluator = MultiPersonaEvaluator()

    def calculate_final_score(
        self,
        final_state: dict,
        threats_resolved: int,
        threats_total: int,   # ← always named threats_total here
        errors: int
    ) -> float:
        """
        Deterministic [0.0, 1.0] base score.
        Inputs are validated and clamped before use.
        """
        threats_total    = max(1, int(threats_total or 1))            # safe default ≥ 1
        threats_resolved = max(0, min(int(threats_resolved or 0), threats_total))
        errors           = max(0, int(errors or 0))

        resolve_rate  = threats_resolved / threats_total               # ∈ [0.0, 1.0]
        error_penalty = errors * 0.02                                  # gentle penalty

        return float(max(0.0, min(1.0, resolve_rate - error_penalty)))

    def get_episode_result(
        self,
        final_state_obj: SystemState,
        total_steps: int,
        cumulative_reward: float,
        threats_resolved: int,
        threats_total: int,
        errors: int,
        action_history: List[Any],
        logs: List[Any]
    ) -> EpisodeResult:
        """
        Computes the full episode result with persona-weighted final score.
        Never crashes — all inputs are validated.
        """
        # Validate all inputs defensively
        threats_total    = max(1, int(threats_total    or 1))
        threats_resolved = max(0, min(int(threats_resolved or 0), threats_total))
        errors           = max(0, int(errors           or 0))
        total_steps      = max(0, int(total_steps      or 0))
        cumulative_reward = float(cumulative_reward     or 0.0)

        # 1. Base score
        base_score = self.calculate_final_score(
            final_state_obj.model_dump(),
            threats_resolved,
            threats_total,
            errors
        )

        # 2. Persona evaluation (last action in history)
        persona_data = {}
        final_score  = base_score
        try:
            if action_history:
                last_raw    = action_history[-1]
                last_action = (
                    Action.model_validate(last_raw)
                    if isinstance(last_raw, dict)
                    else last_raw
                )
                eval_res     = self.evaluator.evaluate_action(last_action, final_state_obj, logs)
                persona_data = eval_res.get("personas", {})
                persona_score = float(eval_res.get("final_persona_score", base_score))
                # Blend: 70% base + 30% persona
                final_score  = (base_score * 0.7) + (persona_score * 0.3)
        except Exception:
            # Persona eval failure must not break grading
            final_score = base_score

        # Ensure final score is always bounded
        final_score = float(max(0.0, min(1.0, final_score)))

        # 3. Build human-readable summary — uses threats_total everywhere (no NameError)
        summary = (
            f"Task '{self.task_id}' concluded. "
            f"Score: {final_score:.2f} "
            f"(Resolved: {threats_resolved}/{threats_total}, "
            f"Errors: {errors}, Penalty: {errors * 0.02:.2f})"
        )

        return EpisodeResult(
            task_id=self.task_id,
            total_steps=total_steps,
            final_grader_score=final_score,
            cumulative_reward=cumulative_reward,
            threats_resolved=threats_resolved,
            threats_total=threats_total,
            false_positives=errors,
            persona_scores=persona_data,
            summary=summary
        )
