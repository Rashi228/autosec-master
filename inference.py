"""
inference.py — The Primary Defender Brain (LLM Logic)
=====================================================
Calculates the best defensive response using OpenAI/Gemini models.
Includes heuristic filters to ensure high-quality actions.
"""

import os
import sys
import json
import time
import requests
from typing import List, Dict, Any, Optional
from datetime import datetime

from openai import OpenAI
from pydantic import BaseModel
from dotenv import load_dotenv

from autosec_openenv.models import (
    SystemState, Observation, Action, ActionType, 
    SecurityLog, Severity, EventType, SystemStatus,
    EpisodeResult, AttackAction
)
from autosec_openenv.log_generator import generate_malicious_log, generate_benign_logs
from autosec_openenv.memory import ExperienceMemory, Experience
from autosec_openenv.kill_chain import detect_stage

# Load environment variables
load_dotenv()

# Configuration
ENV_BASE_URL = os.getenv("ENV_BASE_URL", "http://localhost:7860")
MODEL_NAME = os.getenv("MODEL_NAME", "gpt-4-turbo")
API_BASE_URL = os.getenv("API_BASE_URL", "https://api.openai.com/v1")
client = OpenAI(api_key=os.getenv("OPENAI_API_KEY"), base_url=API_BASE_URL)

# Shared memory module
memory = ExperienceMemory()

# --- LLM SYSTEM PROMPT ---
SYSTEM_PROMPT = """
You are the Lead Autonomous Security Engineer (AutoSec SOC). 
Your goal is to protect a enterprise network from a persistent human or AI attacker.

CORE MISSION:
1. CONTAIN: Isolate compromised hosts or block malicious IPs immediately.
2. DISRUPT: Terminate malicious processes or reset compromised credentials.
3. RECOVER: Restore system state once threats are contained.

HIERARCHY OF ACTIONS:
- If Active threats > 0, it is a FAILURE to choose NO_ACTION or MONITOR.
- Always check ACTION HISTORY to avoid redundant isolations or blocks.
- Internal infrastructure (dc, db, server) is high-priority for protection.
"""

def _build_user_prompt(obs: Observation, feedback: str = "", history: List[tuple] = None) -> str:
    """Constructs the payload for the LLM agent."""
    
    # 1. Summarize Logs
    log_summary = ""
    for log in obs.logs[-15:]: # Look at last 15 logs
        log_summary += f"- [{log.severity}] {log.event_type} on {log.hostname} (src={log.source_ip})\n"
    
    # 2. Get Memory Support (Passing History to avoid redundancy)
    similar_exp = memory.retrieve_similar_experience(str(obs.logs), exclude_history=history)
    memory_context = ""
    if similar_exp:
        memory_context = f"\nFAST-PATH MEMORY HIT ({similar_exp.kill_chain_stage}): Success with {similar_exp.action} on {similar_exp.target}."
    
    # 3. Get Failure Prevention
    failure_warnings = memory.get_failure_warnings()

    # 4. Format History
    history_str = "\nACTION HISTORY (Current Session):\n"
    if history:
        for action_type, target in history[-5:]:
            history_str += f"- {action_type} on {target}\n"
    else:
        history_str += "- None"

    prompt = f"""
### SITUATION (Step {obs.step_id})
Status: {obs.system_state.status} | Threats: {obs.system_state.active_threats} | Compromise: {obs.system_state.compromise_level}%

### RECENT LOGS
{log_summary or "No recent logs."}

### PROTECTION STATE
Blocked: {obs.system_state.blocked_ips}
Isolated: {obs.system_state.isolated_hosts}
{history_str}

{memory_context}
{failure_warnings}

### FEEDBACK
{feedback or "None."}

What is your move? Return valid JSON.
"""
    return prompt

def _select_best_action(llm_choices: List[Action], obs: Observation, history: List[tuple] = None) -> Action:
    """
    Heuristic selector updated with internal asset priority and history awareness.
    """
    scores = []
    history_set = set(history or [])
    
    visible_targets = set()
    for l in obs.logs:
        visible_targets.add(l.source_ip)
        visible_targets.add(l.hostname)

    for action in llm_choices:
        score = 0.0
        # Ensure we compare against strings
        act_type_str = str(action.action_type).split('.')[-1].upper()
        
        # 🟢 Reward visibility and Internal Assets
        if action.target in visible_targets:
            score += 15.0
        if any(keyword in action.target.lower() for keyword in ["dc", "db", "server", "prod"]):
            score += 10.0
        
        # 🔴 Penalize redundancy (Hard Penalty)
        if (act_type_str, action.target) in history_set:
            score -= 50.0
        if action.action_type == ActionType.BLOCK_IP and action.target in obs.system_state.blocked_ips:
            score -= 50.0
        if action.action_type == ActionType.ISOLATE_HOST and action.target in obs.system_state.isolated_hosts:
            score -= 50.0
            
        # 🔵 Safety rails
        if action.target == "none" and obs.system_state.active_threats > 0:
            score -= 30.0
            
        scores.append(score)
    
    best_idx = scores.index(max(scores))
    return llm_choices[best_idx]


def _llm_action(obs: dict, last_feedback: str = "", history: List[tuple] = None) -> dict:
    """
    Main defender brain updated with session history tracking.
    """
    observation = Observation(**obs)
    
    # 1. Fast-Path Memory Hit
    similar_exp = memory.retrieve_similar_experience(str(observation.logs), exclude_history=history)
    if similar_exp and similar_exp.reward > 0.8:
        return {
            "action_type": similar_exp.action,
            "target": similar_exp.target,
            "reasoning": f"Memory Hit: Success with {similar_exp.action} on {similar_exp.target}."
        }

    # 2. Consult LLM
    try:
        response = client.chat.completions.create(
            model=MODEL_NAME,
            messages=[
                {"role": "system", "content": SYSTEM_PROMPT},
                {"role": "user", "content": _build_user_prompt(observation, last_feedback, history)}
            ],
            response_format={ "type": "json_object" }
        )
        
        content = response.choices[0].message.content
        
        # Robust JSON extraction (in case model ignores response_format)
        if "```json" in content:
            content = content.split("```json")[1].split("```")[0].strip()
        elif "{" in content and "}" in content:
            # Simple heuristic for naked JSON in text
            start = content.find("{")
            end = content.rfind("}") + 1
            content = content[start:end]
            
        raw_res = json.loads(content)
        
        # Handle case-sensitivity and variations
        atype = raw_res.get("action_type") or raw_res.get("action") or "NO_ACTION"
        target = raw_res.get("target") or raw_res.get("destination") or "none"
        reasoning = raw_res.get("reasoning") or raw_res.get("thought") or "Analyzed."

        action = Action(
            action_type=ActionType(str(atype).upper()),
            target=str(target),
            reasoning=str(reasoning)
        )
        
        return action.model_dump()
        
    except Exception as e:
        print(f"   ⚠️ LLM Error: {e}")
        return {"action_type": "NO_ACTION", "target": "none", "reasoning": f"Fallback: {str(e)}"}


def run_episode(task_id: str = "task_01"):
    """Runs evaluation with history tracking."""
    
    print(f"[*] Starting Evaluation: {task_id}...")
    reset_resp = requests.post(f"{ENV_BASE_URL}/v1/reset", json={"task_id": task_id}).json()
    obs = reset_resp["observation"]
    done = obs.get("done", False)
    
    step = 0
    last_feedback = ""
    action_history = [] 
    
    while not done:
        step += 1
        print(f"\nBLUE TEAM ANALYZING...")
        action = _llm_action(obs, last_feedback, history=action_history)
        
        # Add to history (standardized as strings) for subsequent rounds
        act_type_str = str(action["action_type"]).split('.')[-1].upper()
        action_history.append((act_type_str, action["target"]))

        icon = "[LLM REASONING]"
        if "Memory" in action.get("reasoning", ""):
            icon = "[MEMORY HIT]"
            
        print(f"   {icon}")
        print(f"   Action: {action['action_type']:20s} | Target: {action['target']}")
        print(f"   Reasoning: {action['reasoning']}")
        
        # 3. Execute Step
        step_resp = requests.post(
            f"{ENV_BASE_URL}/v1/step", 
            json={"action": action}
        ).json()
        
        reward = step_resp["reward"]
        obs = step_resp["observation"]
        done = reward.get("done", False)
        last_feedback = reward.get("feedback", "")
        
        # 4. Save to Memory (Crucial for learning!)
        exp = Experience(
            state_summary=str(obs.get("logs", ""))[:200],
            action=action["action_type"],
            target=action["target"],
            reward=reward.get("score", 0.0),
            feedback=last_feedback,
            reasoning=action.get("reasoning", ""),
            success=reward.get("score", 0.0) > 0,
            timestamp=datetime.now().isoformat(),
            kill_chain_stage=detect_stage(obs.get("logs", [])).value
        )
        memory.save_experience(exp)

        print(f"   Reward: {reward.get('score'):.3f} | Feedback: {last_feedback}")

    # 5. Final Result
    result = requests.get(f"{ENV_BASE_URL}/v1/result").json()
    print("\n" + "="*50)
    print(" EPISODE COMPLETE")
    print("="*50)
    print(f"   Final Result: {result.get('summary')}")
    print(f"   Final Score:  {result.get('final_grader_score'):.4f}")
    
    return result


if __name__ == "__main__":
    # If run directly, evaluate on task_02 (The hardest baseline)
    run_episode("task_02")
