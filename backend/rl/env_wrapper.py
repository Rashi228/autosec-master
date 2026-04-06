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
        self.sim.max_steps = 30 
        self.last_action_multi = None
        
        # Action space: [Strategy, Tactic, Target]
        self.action_space = spaces.MultiDiscrete([
            len(STRATEGIES), 
            len(TACTICS), 
            len(COMMON_TARGETS)
        ])
        
        # Observation space: 15-feature structured vector
        self.observation_space = spaces.Box(
            low=0.0, high=1.0, shape=(15,), dtype=np.float32
        )

    def reset(self, seed=None, options=None):
        super().reset(seed=seed)
        obs_obj = self.sim.reset()
        self.last_action_multi = None
        return self._transform_obs(obs_obj), {}

    def step(self, action_multi):
        strategy_idx, tactic_idx, target_idx = action_multi
        tactic = TACTICS[tactic_idx]
        target = COMMON_TARGETS[target_idx]
        
        is_repeated = np.array_equal(action_multi, self.last_action_multi)
        self.last_action_multi = action_multi.copy()
        
        # Map Hierarchical action to internal ActionType
        a_type = ActionType.NO_ACTION
        if tactic == "ISOLATE_HOST":
            a_type = ActionType.ISOLATE_HOST
        elif tactic == "BLOCK_IP":
            a_type = ActionType.BLOCK_IP
            if target == "attacker_ip" and self.sim.last_attacker_action:
                target = self.sim.last_attacker_action.get("source_ip", target)
        elif tactic == "INSPECT_LOGS":
            a_type = ActionType.MONITOR

        action = Action(
            action_type=a_type, 
            target=target,
            reasoning=f"Agent Strategy: {STRATEGIES[strategy_idx]}"
        )
        
        # Pre-step state tracking
        pre_threats = self.sim.state.active_threats
        
        # Determine "Correct Target" from internal simulation truth
        hosts_under_attack = {log.hostname for log in self.sim.logs if log.is_malicious}
        ips_under_attack = {log.source_ip for log in self.sim.logs if log.is_malicious and log.source_ip}
        is_correct_target = (target in hosts_under_attack) or (target in ips_under_attack)
        
        # Execute in Simulator
        obs_obj, sim_reward_info = self.sim.step(action)
        post_threats = self.sim.state.active_threats
        
        # Calculate custom RL reward
        step_info = {
            "resolved_threat": post_threats < pre_threats,
            "threat_reduced": post_threats < pre_threats,
            "is_correct_target": is_correct_target,
            "is_repeated": is_repeated,
            "redundant": "Redundant" in sim_reward_info.get("feedback", ""),
            "unsafe": False 
        }
        
        reward = calculate_reward(action, self.sim.state, step_info)
        done = obs_obj.done
        
        # Normalized Terminal Rewards
        if done:
            if self.sim.state.active_threats == 0:
                reward += 10.0 # Stable terminal reward
            else:
                reward -= 5.0  
        
        return self._transform_obs(obs_obj), float(reward), done, False, {}

    def _transform_obs(self, obs_obj) -> np.ndarray:
        """
        Structured 15-feature vector:
        [0] Compromise Level (0-1)
        [1] Threat Count (0-1)
        [2] Step Progress (0-1)
        [3-7] Host Status: Is host[i] under attack? (0/1)
        [8] Attacker IP: Is attacker_ip active? (0/1)
        [9-13] Defence Status: Is host[i] isolated? (0/1)
        [14] Last log maliciousness (0/1)
        """
        state = obs_obj.system_state
        vec = [
            float(state.compromise_level / 100.0),
            float(state.active_threats / 5.0),
            float(obs_obj.step_id / 30.0)
        ]
        
        # 3-7: Binary status for each host
        malicious_hosts = {log.hostname for log in obs_obj.logs if log.is_malicious}
        for h in COMMON_TARGETS[:5]: # First 5 are hosts
            vec.append(1.0 if h in malicious_hosts else 0.0)
            
        # 8: Attacker IP awareness
        malicious_ips = {log.source_ip for log in obs_obj.logs if log.is_malicious and log.source_ip}
        vec.append(1.0 if len(malicious_ips) > 0 else 0.0)
        
        # 9-13: Isolation flags
        for h in COMMON_TARGETS[:5]:
            vec.append(1.0 if h in state.isolated_hosts else 0.0)
            
        # 14: Last log signal
        last_log_malicious = obs_obj.logs[-1].is_malicious if obs_obj.logs else False
        vec.append(1.0 if last_log_malicious else 0.0)
        
        return np.array(vec, dtype=np.float32)

    def set_threat_capacity(self, capacity: int):
        """Helper for curriculum learning."""
        self.sim.threat_capacity = capacity
        print(f"[*] Environment threat capacity set to {capacity}")

def make_env(task_id: str = "task_01"):
    return AutoSecGymEnv(task_id=task_id)
