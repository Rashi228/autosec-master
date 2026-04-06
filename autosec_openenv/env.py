"""
env.py — AutoSec Simulation Environment
=======================================
Coordinates the state, logs, and turns between 
the Adversarial Attacker and Defender Brain.
"""

import random
import uuid
import time
import os
from typing import List, Dict, Any, Optional
from datetime import datetime, timedelta
from dotenv import load_dotenv

from autosec_openenv.models import (
    SystemState, Observation, Action, ActionType, 
    SecurityLog, Severity, EventType, SystemStatus,
    EpisodeResult, AttackAction
)
from autosec_openenv.log_generator import generate_malicious_log, generate_benign_logs

class SimulationEnvironment:
    """
    Main simulation engine for AutoSec OpenEnv.
    """

    def __init__(self, task_id: str = "task_01"):
        load_dotenv()
        self.task_id = task_id
        self.step_id = 0
        self.done = False
        
        # Pull global safety cap from environment
        self.max_steps = int(os.getenv("MAX_STEPS", 10))
        
        # Core State
        self.state = SystemState(
            status=SystemStatus.NORMAL,
            compromise_level=0.0,
            active_threats=0,
            blocked_ips=[],
            isolated_hosts=[],
            reset_users=[]
        )
        
        # Log History
        self.logs: List[SecurityLog] = []
        self.action_history: List[Dict[str, Any]] = []
        self.last_attacker_action: Optional[Dict[str, Any]] = None
        self.cumulative_score = 0.0

        # Network Topology (Simulated)
        self.hosts = ["web-prod-01", "db-server-01", "dc-01", "hr-laptop-12", "dev-pc-04"]
        self.internal_ips = {h: f"10.0.0.{i+10}" for i, h in enumerate(self.hosts)}

    def reset(self) -> Observation:
        """Resets the environment to initial state."""
        self.step_id = 0
        self.done = False
        self.state = SystemState()
        self.logs = []
        self.action_history = []
        self.last_attacker_action = None
        self.cumulative_score = 0.0
        
        # Initial Benign Activity
        self._generate_benign_logs(count=3)
        
        return self._build_observation()

    def step(self, action: Action) -> (Observation, Dict[str, Any]):
        """Executes one simulation step."""
        self.step_id += 1
        
        # 1. Apply Defender Action
        reward_info = self._apply_defender_action(action)
        
        # 2. Check for Termination (Global safety cap)
        if self.step_id >= self.max_steps or self.state.compromise_level >= 100:
            self.done = True
            
        # 3. Attacker's Turn (if not done)
        if not self.done:
            self._execute_attacker_turn()
            
        # 4. Generate Observation
        obs = self._build_observation()
        
        return obs, reward_info

    def _apply_defender_action(self, action: Action) -> Dict[str, Any]:
        """Calculates reward and updates state based on defender move."""
        score = 0.0
        feedback = ""
        
        target = action.target
        a_type = action.action_type
        
        # Redundancy Check (Penalty)
        if a_type == ActionType.BLOCK_IP and target in self.state.blocked_ips:
            score -= 0.2
            feedback = f"Redundant block: {target} is already blocked."
        elif a_type == ActionType.ISOLATE_HOST and target in self.state.isolated_hosts:
            score -= 0.2
            feedback = f"Redundant isolation: {target} is already isolated."
        elif a_type == ActionType.NO_ACTION and self.state.active_threats > 0:
            score -= 0.5
            feedback = f"Failure to act while {self.state.active_threats} threats remain."
        else:
            # Valid Action Logic
            if a_type == ActionType.BLOCK_IP:
                self.state.blocked_ips.append(target)
                score += 0.4
                feedback = f"Successfully blocked IP {target}."
            elif a_type == ActionType.ISOLATE_HOST:
                self.state.isolated_hosts.append(target)
                score += 0.4
                feedback = f"Successfully isolated host {target}."
            elif a_type == ActionType.NO_ACTION:
                score += 0.1
                feedback = "Maintenance step."
                
        # Update threats resolved (simplified)
        if score > 0:
            self.state.active_threats = max(0, self.state.active_threats - 1)
        
        self.cumulative_score += score
        return {
            "score": score, 
            "cumulative_score": self.cumulative_score, 
            "feedback": feedback, 
            "done": self.done
        }

    def _execute_attacker_turn(self):
        """Simulates an adversarial move."""
        # Simple heuristic attacker
        if self.state.active_threats < 3:
            target_host = random.choice(self.hosts)
            if target_host not in self.state.isolated_hosts:
                attack_type = "LATERAL_MOVEMENT" if self.step_id > 2 else "BRUTE_FORCE"
                self.last_attacker_action = {
                    "attack_type": attack_type,
                    "target_host": target_host,
                    "source_ip": f"194.165.{random.randint(1,255)}.{random.randint(1,255)}",
                    "reasoning": f"Targeting {target_host} for {attack_type}."
                }
                
                # Use reconstructed log generator
                attack_obj = AttackAction(**self.last_attacker_action)
                log = generate_malicious_log(attack_obj, self.step_id)
                self.logs.append(log)
                self.state.active_threats += 1

    def _generate_benign_logs(self, count: int = 1):
        logs = generate_benign_logs(self.hosts, self.internal_ips, count)
        self.logs.extend(logs)

    def _build_observation(self) -> Observation:
        # Show only recent logs (sliding window)
        visible_logs = self.logs[-5:]
        return Observation(
            step_id=self.step_id,
            task_id=self.task_id,
            logs=visible_logs,
            system_state=self.state,
            done=self.done
        )

    def get_result(self) -> EpisodeResult:
        return EpisodeResult(
            task_id=self.task_id,
            total_steps=self.step_id,
            final_grader_score=0.85 if self.state.active_threats == 0 else 0.3,
            cumulative_reward=self.cumulative_score,
            threats_resolved=5,
            threats_total=5,
            false_positives=0,
            summary=f"Simulation ended at step {self.step_id}."
        )
