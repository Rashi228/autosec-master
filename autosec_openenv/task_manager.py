"""
task_manager.py — SOC Scenario Configuration
============================================
Defines the different simulation tasks (Episodes) 
based on Meta OpenEnv specifications.
"""

from typing import Dict, Any, List, Optional
from autosec_openenv.models import TaskInfo

SCENARIOS = {
    "task_easy": TaskInfo(
        task_id="task_easy",
        name="L1: Perimeter Breach",
        difficulty="EASY",
        description="A single host is experiencing a brute-force attack. High visibility, immediate logs.",
        max_steps=5
    ),
    "task_medium": TaskInfo(
        task_id="task_medium",
        name="L2: Lateral Movement",
        difficulty="MEDIUM",
        description="An attacker has gained a foothold. LOG DELAY: Indicators appear 1 step after the event.",
        max_steps=10
    ),
    "task_hard": TaskInfo(
        task_id="task_hard",
        name="L3: Advanced Exfiltration",
        difficulty="HARD",
        description="A stealthy attacker is exfiltrating data. STEALTH: 50% chance for attacker actions to be 'silent' (no logs).",
        max_steps=15
    )
}

class TaskManager:
    """
    Manager for loading and transitioning between SOC scenarios.
    """

    @staticmethod
    def list_tasks() -> List[TaskInfo]:
        return list(SCENARIOS.values())

    @staticmethod
    def get_task(task_id: str) -> TaskInfo:
        return SCENARIOS.get(task_id, SCENARIOS["task_easy"])

def load_scenario(task_id: str) -> TaskInfo:
    """Helper for simulation environment."""
    return TaskManager.get_task(task_id)
