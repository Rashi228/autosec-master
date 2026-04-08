\
\
\
\
\
   

import gymnasium as gym
from gymnasium import spaces
import numpy as np
from typing import Dict, Any, List

from autosec_openenv.env import SimulationEnvironment
from autosec_openenv.models import ActionType, Action

                                                        
COMMON_TARGETS = [
    "web-prod-01", "db-server-01", "dc-01", 
    "hr-laptop-12", "dev-pc-04", "none"
]

class AutoSecGymEnv(gym.Env):
\
\
       

    def __init__(self, task_id: str = "task_01"):
        super().__init__()
        self.sim = SimulationEnvironment(task_id=task_id)
        
                                                           
                                                               
        self.action_space = spaces.Discrete(len(ActionType) * len(COMMON_TARGETS))
        
                                                                
                                                                     
        self.observation_space = spaces.Box(
            low=0.0, high=100.0, shape=(12,), dtype=np.float32
        )

    def reset(self, seed=None, options=None):
        super().reset(seed=seed)
        obs_obj = self.sim.reset()
        return self._transform_obs(obs_obj), {}

    def step(self, action_idx):
                                                
        action_type_idx = action_idx // len(COMMON_TARGETS)
        target_idx = action_idx % len(COMMON_TARGETS)
        
        action_type = list(ActionType)[action_type_idx]
        target = COMMON_TARGETS[target_idx]
        
                                 
        action = Action(action_type=action_type, target=target)
        obs_obj, reward_info = self.sim.step(action)
        
                          
        reward = reward_info["score"]
        done = obs_obj.done
        
        return self._transform_obs(obs_obj), reward, done, False, {}

    def _transform_obs(self, obs_obj) -> np.ndarray:
                                                                     
        state = obs_obj.system_state
        vec = [
            float(state.compromise_level),
            float(state.active_threats),
            float(obs_obj.step_id / 20.0),                  
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
