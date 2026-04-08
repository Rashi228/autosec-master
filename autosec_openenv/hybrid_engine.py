\
\
\
\
\
\
\
\
\
   

import json
import os
import numpy as np
from typing import Optional, List, Dict, Any

from autosec_openenv.models import Action, ActionType, SecurityLog, Observation
from autosec_openenv.rule_engine import RuleEngine

                                                                                   
try:
    from stable_baselines3 import PPO
    HAS_PPO = True
except ImportError:
    HAS_PPO = False


class DecisionOrchestrator:
\
\
       

    def __init__(self, model_path: Optional[str] = None):
        self.rules = RuleEngine()
        self.memory_path = "experience_memory.json"
        self.ppo_model = None
        
        if model_path and os.path.exists(model_path) and HAS_PPO:
            self.ppo_model = PPO.load(model_path)

    def decide(self, obs: Observation, llm_agent_func) -> Action:
\
\
           
                                                     
        rule_action = self.rules.evaluate(obs.logs, obs.system_state.model_dump())
        if rule_action:
            rule_action.reasoning = f"Source: Rule Engine | {rule_action.reasoning}"
            return rule_action

                                                                
        memory_action = self._consult_memory(obs)
        if memory_action:
            memory_action.reasoning = f"Source: Success-Weighted Memory | {memory_action.reasoning}"
            return memory_action

                                                     
        if self.ppo_model:
            rl_action = self._consult_ppo(obs)
            if rl_action:
                rl_action.reasoning = f"Source: PPO RL Policy | {rl_action.reasoning}"
                return rl_action

                                                   
        llm_action = llm_agent_func(obs)
        llm_action.reasoning = f"Source: LLM Reasoning | {llm_action.reasoning}"
        return llm_action

    def _consult_memory(self, obs: Observation) -> Optional[Action]:
\
\
           
        if not os.path.exists(self.memory_path):
            return None
            
        with open(self.memory_path, 'r') as f:
            data = json.load(f)
            
                                                             
        if not obs.logs: return None
        profile = f"{obs.logs[-1].event_type}_{obs.logs[-1].severity}"
        
        matches = data.get(profile, [])
        if matches:
                                                                   
            sorted_m = sorted(matches, key=lambda x: x.get("success_rate", 0), reverse=True)
            top = sorted_m[0]
            if top.get("success_rate", 0) > 0.7:
                return Action(
                    action_type=ActionType(top["action"]),
                    target=top["target"],
                    reasoning=f"High success-rate match found for {profile}."
                )
        return None

    def _consult_ppo(self, obs: Observation) -> Optional[Action]:
                                                                   
        if not self.ppo_model:
            return None

                                                        
        obs_vec = self._transform_observation(obs)
        
                                 
        action_idx, _states = self.ppo_model.predict(obs_vec, deterministic=True)
        
                                      
        from autosec_openenv.gym_wrapper import COMMON_TARGETS
        
        type_idx = action_idx // len(COMMON_TARGETS)
        target_idx = action_idx % len(COMMON_TARGETS)
        
        action_types = list(ActionType)
        if type_idx >= len(action_types): return None
        
        action_type = action_types[type_idx]
        target = COMMON_TARGETS[target_idx]
        
                                                                
        if action_type == ActionType.NO_ACTION:
            return None

        return Action(
            action_type=action_type,
            target=target,
            reasoning=f"Neural Policy predicted {action_type.value} on {target}."
        )

    def _transform_observation(self, obs: Observation) -> np.ndarray:
                                                                       
        vec = []
        vec.append(float(obs.system_state.compromise_level))
        vec.append(float(obs.system_state.active_threats))
        vec.append(float(obs.step_id / 20.0))
        
        logs = obs.logs[-3:]
        for _ in range(3 - len(logs)):
            vec.extend([0.0, 0.0, 0.0])
            
        for log in logs:
            sev_map = {"LOW": 1.0, "MEDIUM": 5.0, "HIGH": 10.0, "CRITICAL": 20.0}
            vec.append(sev_map.get(log.severity.value, 0.0))
            vec.append(1.0 if log.is_malicious else 0.0)
            vec.append(float(len(log.raw_log) / 500.0))
            
        return np.array(vec, dtype=np.float32)
