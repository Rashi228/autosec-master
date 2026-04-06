"""
task_manager.py — SOC Scenario Configuration
============================================
Defines the different simulation tasks (Episodes) 
based on Meta OpenEnv specifications.
"""

from typing import Dict, Any, List, Optional
from autosec_openenv.models import TaskInfo

SCENARIOS = {
    "task_01": TaskInfo(
        task_id="task_01",
        name="Brute Force Containment",
        difficulty="EASY",
        description="Stop an external brute-force attack on a single host.",
        max_steps=10
    ),
    "task_02": TaskInfo(
        task_id="task_02",
        name="Privilege Escalation & Lateral Movement",
        difficulty="MEDIUM",
        description="Contain an attacker attempting to escalate to Domain Admin.",
        max_steps=15
    ),
    "task_03": TaskInfo(
        task_id="task_03",
        name="Data Exfiltration Discovery",
        difficulty="HARD",
        description="Identify and disrupt a covert data exfiltration channel.",
        max_steps=20
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
        return SCENARIOS.get(task_id, SCENARIOS["task_01"])

def load_scenario(task_id: str) -> TaskInfo:
    """Helper for simulation environment."""
    return TaskManager.get_task(task_id)
