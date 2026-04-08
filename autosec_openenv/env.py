\
\
\
\
\
   

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
    EpisodeResult, AttackAction, Reward
)
from backend.rl.reward_engine import calculate_reward
from autosec_openenv.log_generator import generate_malicious_log, generate_benign_logs
from autosec_openenv.graders import SOCGrader
from autosec_openenv.task_manager import load_scenario

class SimulationEnvironment:
\
\
       

    def __init__(self, task_id: str = "task_easy", seed: int = 42):
        load_dotenv()
        self.scenario = load_scenario(task_id)
        self.task_id = task_id
        self.step_id = 0
        self.done = False
                                             
        random.seed(seed)
        
                                 
        self.max_steps = self.scenario.max_steps
        
                    
        self.state_obj = SystemState(
            status=SystemStatus.NORMAL,
            compromise_level=0.0,
            active_threats=0,
            blocked_ips=[],
            isolated_hosts=[],
            reset_users=[]
        )
        
                               
        self.logs: List[SecurityLog] = []
        self.delayed_logs: List[SecurityLog] = []                  
        self.action_history: List[Action] = []
        self.last_attacker_action: Optional[Dict[str, Any]] = None
        self.cumulative_score = 0.0
        self.threat_capacity = 3
        
                            
        self.threats_resolved = 0
        self.threats_total = 0
        self.errors = 0

                          
        self.hosts = ["web-prod-01", "db-server-01", "dc-01", "hr-laptop-12", "dev-pc-04"]
        self.internal_ips = {h: f"10.0.0.{i+10}" for i, h in enumerate(self.hosts)}
        self.grader = SOCGrader(task_id)

    def reset(self) -> tuple[Observation, dict]:
                                                      
        self.step_id = 0
        self.done = False
        self.state_obj = SystemState()
        self.logs = []
        self.action_history = []
        self.last_attacker_action = None
        self.cumulative_score = 0.0
        
                                 
        self._generate_benign_logs(count=3)
        
        return self._build_observation(), {}

    def step(self, action: Action) -> tuple[Observation, Reward, bool, dict]:
                                           
        self.step_id += 1
        self.action_history.append(action)
        
                                  
        reward_info = self._apply_defender_action(action)
        
                                                      
        if self.step_id >= self.max_steps:
            self.done = True
                                                   
            if self.state_obj.active_threats > 0:
                reward_info["score"] -= 0.3
        
        if self.state_obj.compromise_level >= 100:
            self.done = True
            
                                          
        if not self.done:
            self._execute_attacker_turn()
            
                                               
        self._process_side_effects()

                                 
        obs = self._build_observation()
        
                                
        reward_obj = Reward(
            value=max(0.0, min(1.0, reward_info["score"])),
            feedback=reward_info["feedback"],
            is_terminal=self.done
        )
        
        return obs, reward_obj, self.done, reward_info

    def _process_side_effects(self):
                                                   
                                                       
        if self.task_id == "task_medium" and self.delayed_logs:
                                                                                      
            self.logs.extend(self.delayed_logs)
            self.delayed_logs = []

    def state(self) -> dict:
                                                 
        return self.state_obj.model_dump()

    def _apply_defender_action(self, action: Action) -> Dict[str, Any]:
                                                                         
        step_info = {
            "redundant": False,
            "unsafe": False,
            "is_correct_target": False,
            "resolved_threat": False
        }
        
        target = action.target
        a_type = action.action_type
        
                                                                                           
        if a_type == ActionType.BLOCK_IP and target in self.state_obj.blocked_ips:
            step_info["redundant"] = True
        elif a_type == ActionType.ISOLATE_HOST and target in self.state_obj.isolated_hosts:
            step_info["redundant"] = True
        
                                                                            
        malicious_sources = [log.source_ip for log in self.logs if log.is_malicious]
        malicious_hosts   = [log.hostname  for log in self.logs if log.is_malicious]
        
        is_correct = (
            (a_type == ActionType.BLOCK_IP         and target in malicious_sources) or
            (a_type == ActionType.ISOLATE_HOST     and target in malicious_hosts)   or
            (a_type == ActionType.TERMINATE_PROCESS and target in malicious_hosts)
        )
        
        if is_correct and not step_info["redundant"]:
                                                              
            step_info["is_correct_target"] = True
            step_info["resolved_threat"]   = True
            self.state_obj.active_threats  = max(0, self.state_obj.active_threats - 1)
            self.threats_resolved = min(self.threats_total, self.threats_resolved + 1)
        elif not is_correct and a_type not in [ActionType.NO_ACTION, ActionType.MONITOR]:
                                                                                  
            if not step_info["redundant"]:
                self.errors += 1

                             
        if a_type == ActionType.BLOCK_IP:
            self.state_obj.blocked_ips.append(target)
        elif a_type == ActionType.ISOLATE_HOST:
            self.state_obj.isolated_hosts.append(target)
                
                                               
        score = calculate_reward(action, self.state_obj, step_info)
        self.cumulative_score += score
        
        return {
            "score": score, 
            "cumulative_score": self.cumulative_score, 
            "feedback": f"Action {a_type} on {target} processed.", 
            "done": self.done
        }

    def _execute_attacker_turn(self):
                                            
                                   
        if self.state_obj.active_threats < self.threat_capacity:
            target_host = random.choice(self.hosts)
            if target_host not in self.state_obj.isolated_hosts:
                attack_type = "LATERAL_MOVEMENT" if self.step_id > 2 else "BRUTE_FORCE"
                self.last_attacker_action = {
                    "attack_type": attack_type,
                    "target_host": target_host,
                    "source_ip": f"194.165.{random.randint(1,255)}.{random.randint(1,255)}",
                    "reasoning": f"Targeting {target_host} for {attack_type}."
                }
                
                                                 
                attack_obj = AttackAction(**self.last_attacker_action)
                log = generate_malicious_log(attack_obj, self.step_id)
                
                                                
                is_stealthy = False
                if self.task_id == "task_hard" and random.random() < 0.5:
                    is_stealthy = True
                
                if not is_stealthy:
                                                  
                    if self.task_id == "task_medium":
                        self.delayed_logs.append(log)
                    else:
                        self.logs.append(log)
                
                self.state_obj.active_threats += 1
                self.threats_total += 1

    def _generate_benign_logs(self, count: int = 1):
        logs = generate_benign_logs(self.hosts, self.internal_ips, count)
        self.logs.extend(logs)

    def _build_observation(self) -> Observation:
                                                      
        visible_logs = self.logs[-10:]
        
                                                         
        severity_map = {"LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 5}
        total_sev = sum(
            severity_map.get(str(l.severity).upper().split(".")[-1], 0)
            for l in visible_logs if l.is_malicious
        )
        impact = min(1.0, (self.state_obj.compromise_level / 50.0) + (self.state_obj.active_threats * 0.2))

        return Observation(
            step_id=self.step_id,
            task_id=self.task_id,
            logs=visible_logs,
            system_state=self.state_obj.model_dump(),
            num_active_threats=self.state_obj.active_threats,
            threat_severity_sum=total_sev,
            recent_event_types=[l.event_type.value for l in visible_logs][-3:],
            impact_score=float(impact)
        )

    def get_result(self) -> EpisodeResult:
        return self.grader.get_episode_result(
            final_state_obj=self.state_obj,
            total_steps=self.step_id,
            cumulative_reward=self.cumulative_score,
            threats_resolved=self.threats_resolved,
            threats_total=max(self.threats_total, 1),
            errors=self.errors,
            action_history=self.action_history,
            logs=self.logs
        )
