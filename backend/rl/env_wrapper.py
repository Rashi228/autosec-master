"""
env_wrapper.py — Gymnasium Wrapper for AutoSec RL
=================================================
A Gym wrapper for AutoSec to train PPO agents.
"""

import gymnasium as gym
from gymnasium import spaces
import numpy as np

from autosec_openenv.env import SimulationEnvironment
from autosec_openenv.models import ActionType, Action
from backend.rl.reward_engine import calculate_reward

# Simplified action mapping for RL representation
STRATEGIES = ["DETECT", "INVESTIGATE", "CONTAIN", "REMEDIATE"]
TACTICS = ["INSPECT_LOGS", "ISOLATE_HOST", "BLOCK_IP", "NO_ACTION"]
COMMON_TARGETS = ["web-prod-01", "db-server-01", "dc-01", "hr-laptop-12", "dev-pc-04", "attacker_ip"]

class AutoSecGymEnv(gym.Env):
    """
    OpenAI Gym compatible interface for AutoSec SOC simulator.
    """
    def __init__(self, task_id: str = "task_rl_01"):
        super().__init__()
        self.sim = SimulationEnvironment(task_id=task_id)
        
        # Action space: [Strategy, Tactic, Target]
        # MultiDiscrete representation for hierarchical decision tracking
        self.action_space = spaces.MultiDiscrete([
            len(STRATEGIES), 
            len(TACTICS), 
            len(COMMON_TARGETS)
        ])
        
        # Observation space: Flat vector of system state metrics
        # [compromise_level, active_threats, step_id, log_metrics...]
        self.observation_space = spaces.Box(
            low=0.0, high=100.0, shape=(12,), dtype=np.float32
        )

    def reset(self, seed=None, options=None):
        super().reset(seed=seed)
        obs_obj = self.sim.reset()
        return self._transform_obs(obs_obj), {}

    def step(self, action_multi):
        strategy_idx, tactic_idx, target_idx = action_multi

        tactic = TACTICS[tactic_idx]
        target = COMMON_TARGETS[target_idx]
        
        # Map Hierarchical action to internal ActionType
        a_type = ActionType.NO_ACTION
        if tactic == "isolate_host":
            a_type = ActionType.ISOLATE_HOST
        elif tactic == "block_ip":
            a_type = ActionType.BLOCK_IP
            # In real RL we'd extract IP from state. Mocking for now.
            if target == "attacker_ip" and self.sim.last_attacker_action:
                target = self.sim.last_attacker_action.get("source_ip", target)
        elif tactic == "inspect_logs":
            a_type = ActionType.MONITOR

        action = Action(
            action_type=a_type, 
            target=target,
            reasoning=f"Agent Strategy: {STRATEGIES[strategy_idx]}"
        )
        
        # Pre-step state tracking for reward
        pre_threats = self.sim.state.active_threats
        
        # Execute in Simulator
        obs_obj, sim_reward_info = self.sim.step(action)
        
        post_threats = self.sim.state.active_threats
        
        # Calculate custom RL reward
        step_info = {
            "resolved_threat": post_threats < pre_threats,
            "redundant": "Redundant" in sim_reward_info.get("feedback", ""),
            "unsafe": False # Future logic for unsafe actions
        }
        
        reward = calculate_reward(action, self.sim.state, step_info)
        done = obs_obj.done
        
        return self._transform_obs(obs_obj), reward, done, False, {}

    def _transform_obs(self, obs_obj) -> np.ndarray:
        # Convert Pydantic observation to fixed-length numeric vector
        state = obs_obj.system_state
        vec = [
            float(state.compromise_level),
            float(state.active_threats),
            float(obs_obj.step_id / float(max(1, self.sim.max_steps))),
            float(len(state.blocked_ips) / 10.0),
            float(len(state.isolated_hosts) / 10.0)
        ]
        
        logs = obs_obj.logs[-2:]
        for log in logs:
            vec.append(1.0 if log.is_malicious else 0.0)
            vec.append(float(len(log.raw_log) / 500.0))
            
        while len(vec) < 12:
            vec.append(0.0)
            
        return np.array(vec, dtype=np.float32)

def make_env(task_id: str = "task_01"):
    return AutoSecGymEnv(task_id=task_id)
