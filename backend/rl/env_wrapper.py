\
\
\
\
   

import os
import gymnasium as gym
from gymnasium import spaces
import numpy as np

from autosec_openenv.env import SimulationEnvironment
from autosec_openenv.models import ActionType, Action
from autosec_openenv.kill_chain import detect_stage, KillChainStage, STAGE_PRIORITY
from backend.rl.reward_engine import calculate_reward

                                                 
STRATEGIES = ["DETECT", "INVESTIGATE", "CONTAIN", "REMEDIATE"]
TACTICS = ["INSPECT_LOGS", "ISOLATE_HOST", "BLOCK_IP", "TERMINATE_PROCESS", "NO_ACTION"]
COMMON_TARGETS = ["web-prod-01", "db-server-01", "dc-01", "hr-laptop-12", "dev-pc-04", "attacker_ip"]

class AutoSecGymEnv(gym.Env):
\
\
       
    def __init__(self, task_id: str = "task_hard", seed: int = 42):
        super().__init__()
        self.sim = SimulationEnvironment(task_id=task_id, seed=seed)
        self.sim.max_steps = int(os.getenv("MAX_STEPS", "15"))
        self.last_action_multi = None
        self._seen_action_targets: set = set()                             
        
                                                  
        self.action_space = spaces.MultiDiscrete([
            len(STRATEGIES), 
            len(TACTICS), 
            len(COMMON_TARGETS)
        ])
        
                                                         
        self.observation_space = spaces.Box(
            low=0.0, high=1.0, shape=(15,), dtype=np.float32
        )

    def reset(self, seed=None, options=None):
        super().reset(seed=seed)
        obs_obj, info = self.sim.reset()
        self.last_action_multi = None
        self._seen_action_targets = set()                                  
        
                                                                               
        info["pydantic_obs"] = obs_obj
        return self._transform_obs(obs_obj), info

    def step(self, action_multi):
        strategy_idx, tactic_idx, target_idx = action_multi
        tactic = TACTICS[tactic_idx]
        target = COMMON_TARGETS[target_idx]
        
        is_repeated = np.array_equal(action_multi, self.last_action_multi)
        self.last_action_multi = action_multi.copy()
        
                                                        
        a_type = ActionType.NO_ACTION
        if tactic == "ISOLATE_HOST":
            a_type = ActionType.ISOLATE_HOST
        elif tactic == "TERMINATE_PROCESS":
            a_type = ActionType.TERMINATE_PROCESS
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
        
                                 
        pre_threats = self.sim.state_obj.active_threats
        
                                                                   
        malicious_sources = [log.source_ip for log in self.sim.logs if log.is_malicious]
        malicious_hosts = [log.hostname for log in self.sim.logs if log.is_malicious]
        is_correct_target = (target in malicious_hosts) or (target in malicious_sources)
        
                              
        obs_obj, reward_obj, done, sim_reward_info = self.sim.step(action)
        post_threats = self.sim.state_obj.active_threats
        
                                    
        current_stage = detect_stage(self.sim.logs)
        priority = STAGE_PRIORITY.get(current_stage, 0)
        
                                          
        is_ip = "." in target or (target and target[0].isdigit())
        is_ip_mismatch = False
        if a_type == ActionType.BLOCK_IP and not is_ip:
            is_ip_mismatch = True
        elif a_type == ActionType.ISOLATE_HOST and is_ip:
            is_ip_mismatch = True
            
                                                       
        critical_assets = ["dc-01", "db-server-01", "web-prod-01"]
        is_over_isolation = False
        if a_type == ActionType.ISOLATE_HOST and target in critical_assets:
                                                                  
            if priority < 4:
                is_over_isolation = True
                
                                          
        is_correct_action_type = False
        if priority >= 1:                     
            if a_type in [ActionType.BLOCK_IP, ActionType.ISOLATE_HOST]:
                is_correct_action_type = True
        elif a_type == ActionType.MONITOR:
            is_correct_action_type = True

                                    
        action_key = (str(action.action_type), action.target)
        is_novel = action_key not in self._seen_action_targets
        self._seen_action_targets.add(action_key)
        
        step_info = {
            "resolved_threat": post_threats < pre_threats,
            "threat_reduced": post_threats < pre_threats,
            "is_correct_target": is_correct_target,
            "is_correct_action_type": is_correct_action_type,
            "is_ip_mismatch": is_ip_mismatch,
            "is_over_isolation": is_over_isolation,
            "is_repeated": is_repeated,
            "is_novel_action": is_novel,
            "redundant": "Redundant" in sim_reward_info.get("feedback", ""),
            "unsafe": False 
        }
        
        reward = calculate_reward(action, self.sim.state_obj, step_info)
        
                                                               
        info = {
            "pydantic_obs": obs_obj,
            "pydantic_reward": reward_obj,
            "sim_info": sim_reward_info
        }
        
        return self._transform_obs(obs_obj), float(reward), done, False, info

    def _transform_obs(self, obs_obj) -> np.ndarray:
\
\
\
\
\
\
\
\
\
           
        state = self.sim.state_obj
        vec = [
            float(state.compromise_level / 100.0),
            float(state.active_threats / 5.0),
            float(obs_obj.step_id / 30.0)
        ]
        
                                          
        malicious_hosts = {log.hostname for log in obs_obj.logs if log.is_malicious}
        for h in COMMON_TARGETS[:5]:                    
            vec.append(1.0 if h in malicious_hosts else 0.0)
            
                                  
        malicious_ips = {log.source_ip for log in obs_obj.logs if log.is_malicious and log.source_ip}
        vec.append(1.0 if len(malicious_ips) > 0 else 0.0)
        
                               
        for h in COMMON_TARGETS[:5]:
            vec.append(1.0 if h in state.isolated_hosts else 0.0)
            
                             
        last_log_malicious = obs_obj.logs[-1].is_malicious if obs_obj.logs else False
        vec.append(1.0 if last_log_malicious else 0.0)
        
        return np.array(vec, dtype=np.float32)

    def set_threat_capacity(self, capacity: int):
                                             
        self.sim.threat_capacity = capacity
        print(f"[*] Environment threat capacity set to {capacity}")

def make_env(task_id: str = "task_01"):
    return AutoSecGymEnv(task_id=task_id)
