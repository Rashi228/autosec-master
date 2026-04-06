"""
rule_engine.py — Deterministic Context-Aware Threat Filtering
===========================================================
This module handles 'No-Brainer' cases to prevent overreactions 
to benign events and ensure decision consistency.
"""

from typing import Optional, List
from autosec_openenv.models import Action, ActionType, SecurityLog, Severity, EventType


class RuleEngine:
    """
    Deterministic rules to prevent false positives and redundant actions.
    Filters out benign activity before the RL/LLM models are consulted.
    """

    def __init__(self):
        self.malicious_ips = set()
        self.blocked_ips = set()

    def evaluate(self, logs: List[SecurityLog], system_state: dict) -> Optional[Action]:
        """
        Evaluate a window of logs against deterministic rules.
        Returns an Action if a rule matches, else None.
        """
        if not logs:
            return Action(
                action_type=ActionType.NO_ACTION,
                target="none",
                reasoning="Rule Logic: No logs visible this step."
            )

        # 1. Benign Filtering: If all logs are benign/low-severity AND no threats are active
        active_threats = system_state.get("active_threats", 0)
        all_benign = all(
            log.severity == Severity.LOW and not log.is_malicious 
            for log in logs
        )
        if all_benign and active_threats == 0:
            return Action(
                action_type=ActionType.NO_ACTION,
                target="none",
                reasoning="Rule Logic: All current logs are BENIGN and no active threats detected."
            )

        # 2. Redundancy Check: Filter logs to see if anything NEW needs attention
        blocked = system_state.get("blocked_ips", [])
        isolated = system_state.get("isolated_hosts", [])
        
        # If ALL logs are for already-handled targets, THEN we can suppress
        all_handled = all(
            (log.source_ip in blocked) or (log.hostname in isolated)
            for log in logs
        )
        
        if all_handled and len(logs) > 0:
             return Action(
                 action_type=ActionType.NO_ACTION,
                 target="none",
                 reasoning="Rule Logic: All activity in this window is from already blocked/isolated sources."
             )

        # 3. Critical Signal: Immediate response to high-severity malicious logs
        for log in logs:
            if log.severity == Severity.CRITICAL and log.is_malicious:
                if log.source_ip not in blocked:
                    return Action(
                        action_type=ActionType.BLOCK_IP,
                        target=log.source_ip,
                        reasoning=f"Rule Logic: CRITICAL threat detected from {log.source_ip}."
                    )

        return None  # No deterministic match, pass to RL/LLM
