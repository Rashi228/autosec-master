"""
server_rl.py — Enhanced API Gateway for AutoSec RL
==================================================
Extends the original FastAPI server with RL-specific telemetry,
vector memory endpoints, curriculum difficulty, and explanations.
"""

from fastapi import FastAPI, HTTPException, Body
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from typing import Dict, Any, List
import os
import time

from autosec_openenv.models import Action, ActionType
from backend.rl.reward_engine import calculate_reward
from backend.evaluator.personas import MultiPersonaEvaluator
from backend.curriculum.scheduler import CurriculumScheduler
from backend.memory.vector_db import VectorMemory
from backend.rl.env_wrapper import AutoSecGymEnv
from fastapi import Request
import json
from autosec_openenv.kill_chain import detect_stage, get_stage_index

try:
    from stable_baselines3 import PPO
    _model = PPO.load("./logs/rl_training/autosec_ppo_final")
except Exception as e:
    print(f"Warning: Could not load PPO model. Fallback active. {e}")
    _model = None

import numpy as np

# ─────────────────────────────────────────────────────────────────────────────
# HYBRID BRAIN CONFIGURATION
# ─────────────────────────────────────────────────────────────────────────────
MODEL_NAME        = os.getenv("MODEL_NAME", "gpt-4o")
LLM_CALL_INTERVAL = int(os.getenv("LLM_INTERVAL", "3"))
RANDOM_SEED       = int(os.getenv("RANDOM_SEED", "42"))
ALLOW_FALLBACK    = True

try:
    from openai import OpenAI
    client = OpenAI(api_key=os.getenv("OPENAI_API_KEY")) if os.getenv("OPENAI_API_KEY") else None
except Exception as e:
    print(f"Warning: OpenAI client not initialized: {e}")
    client = None

PPO_HOSTNAMES = ["web-prod-01", "db-server-01", "dc-01", "jump-host-01"]
PPO_TACTICS   = ["INSPECT_LOGS", "BLOCK_IP", "ISOLATE_HOST", "NO_ACTION"]
PPO_TARGETS   = ["web-prod-01", "db-server-01", "dc-01", "jump-host-01", "attacker_ip", "none"]

STAGE_PRIORITY = {
    "reconnaissance": 1,
    "initial_access": 2,
    "privilege_escalation": 3,
    "lateral_movement": 4,
    "exfiltration": 5,
    "benign": 0
}

# ─────────────────────────────────────────────────────────────────────────────
# BRAIN UTILITIES
# ─────────────────────────────────────────────────────────────────────────────

def _smart_policy(obs_obj, history):
    """Deterministic, high-recall safety net."""
    from autosec_openenv.models import ActionType, Action
    malicious_logs = [l for l in obs_obj.logs if l.is_malicious]
    
    # 1. Block malicious IPs (Highest Priority)
    for log in malicious_logs:
        if log.source_ip and log.source_ip != "none":
            act_tup = ("BLOCK_IP", str(log.source_ip))
            if act_tup not in history:
                return Action(action_type=ActionType.BLOCK_IP, target=log.source_ip, 
                            reasoning=f"Policy: neutralizing malicious traffic from {log.source_ip}")
    
    # 2. Isolate compromised hosts
    for log in malicious_logs:
        if log.hostname and log.hostname != "none":
            act_tup = ("ISOLATE_HOST", str(log.hostname))
            if act_tup not in history:
                return Action(action_type=ActionType.ISOLATE_HOST, target=log.hostname,
                            reasoning=f"Policy: emergency isolation of {log.hostname} due to malicious activity")
    
    return Action(action_type=ActionType.MONITOR, target="none", reasoning="Policy: No clear threat detected, continuing monitoring.")

def _try_llm_action(obs_obj, history):
    """Asynchronous LLM reasoning layer."""
    if not client: return None
    try:
        from autosec_openenv.models import ActionType
        system_prompt = "You are an expert SOC Analyst AI. Suggest the single best defensive action (BLOCK_IP, ISOLATE_HOST, MONITOR) to neutralize threats."
        user_content = f"Active Threats: {obs_obj.num_active_threats}\nRecent logs: {[l.model_dump() for l in obs_obj.logs[-5:]]}\nAvoid: {history}"
        
        response = client.chat.completions.create(
            model=MODEL_NAME,
            messages=[{"role": "system", "content": system_prompt}, {"role": "user", "content": user_content}],
            temperature=0,
            max_tokens=60
        )
        raw = response.choices[0].message.content.upper()
        
        # Simple parser
        atype = ActionType.MONITOR
        target = "none"
        if "BLOCK_IP" in raw: atype = ActionType.BLOCK_IP
        elif "ISOLATE_HOST" in raw: atype = ActionType.ISOLATE_HOST
        
        # Extract target from logs if LLM mention it
        for l in obs_obj.logs:
            if l.source_ip and l.source_ip in raw: target = l.source_ip
            if l.hostname and l.hostname in raw: target = l.hostname
            
        return {"action_type": atype, "target": target, "reasoning": f"LLM Strategy: {raw[:50]}"}
    except Exception as e:
        print(f"LLM Error: {e}")
        return None

def _decide_action(step, obs_obj, history):
    """The Triple-Hybrid Coordinator."""
    # 1. Strategic Layer (LLM)
    if step % LLM_CALL_INTERVAL == 0:
        llm_act = _try_llm_action(obs_obj, history)
        if llm_act:
            print(f"🤖 [BRAIN] Strategic Layer (LLM) selected: {llm_act['action_type']} on {llm_act['target']}")
            return llm_act, "LLM"
    
    # 2. Neural Layer (PPO)
    if _model:
        try:
            import inference
            inference.ppo_model = _model
            ppo_act = inference._try_ppo_action(obs_obj, history)
            if ppo_act:
                confidence = ppo_act.get("confidence", 1.0)
                if confidence > 0.40:
                    print(f"🧠 [BRAIN] Neural Layer (PPO) selected: {ppo_act['action_type']} on {ppo_act['target']} (Conf: {confidence:.2f})")
                    return ppo_act, "PPO"
                else:
                    print(f"⚠️ [BRAIN] Neural Layer (PPO) hesitant (Conf: {confidence:.2f}). Deferring.")
        except Exception as e:
            print(f"⚠️ [BRAIN] PPO inference failed: {e}. Deferring.")
    
    # 3. Safety Layer (Policy)
    pol_act = _smart_policy(obs_obj, history)
    print(f"🛡️ [BRAIN] Safety Layer (Policy) selected: {pol_act.action_type} on {pol_act.target}")
    return pol_act.model_dump(), "POLICY"

app = FastAPI(title="AutoSec RL API")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


_env_wrapper = None
_evaluator = MultiPersonaEvaluator()
_scheduler = CurriculumScheduler()
_current_obs = None
_current_pydantic_obs = None
_episode_elapsed_start = 0

# Global Vector Memory (Lazy Loaded)
_memory_db = None

def get_memory():
    global _memory_db
    if _memory_db is None:
        try:
            _memory_db = VectorMemory()
        except Exception as e:
            print(f"⚠️ [MEMORY] Failed to initialize VectorMemory: {e}")
            print("⚠️ [MEMORY] Continuing in memory-less mode.")
            class MockMemory:
                def store_experience(self, *args, **kwargs): pass
                def retrieve_similar_actions(self, *args, **kwargs): return []
            _memory_db = MockMemory()
    return _memory_db


@app.get("/health")
async def health():
    return {"status": "ok", "timestamp": time.time()}

@app.post("/v1/reset")
@app.post("/reset")
async def reset(request: Request):
    try:
        body = await request.body()
        payload = json.loads(body) if body else {}
    except Exception:
        payload = {}
        
    global _env_wrapper, _current_obs, _current_pydantic_obs, _episode_elapsed_start
    # Change default to task_easy as it's the standard entry-level task
    task_id = payload.get("task_id", "task_easy")
    seed    = int(os.getenv("RANDOM_SEED", "42"))
    print(f"Resetting Environment... task={task_id} seed={seed}")
    params = _scheduler.get_environment_params()
    
    _env_wrapper = AutoSecGymEnv(task_id=task_id, seed=seed)
    _current_obs, info = _env_wrapper.reset()
    _episode_elapsed_start = time.time()
    
    pydantic_obs = info["pydantic_obs"]
    _current_pydantic_obs = pydantic_obs
    print(f"Environment reset. Difficulty: {_scheduler.current_difficulty}")
    
    # Return observation both wrapped and at root for maximum compatibility
    response_data = {
        "observation": pydantic_obs.model_dump(mode="json"),
        "info": {
            "status": "ACTIVE",
            "difficulty": str(_scheduler.current_difficulty.value),
            "params": params
        }
    }
    # Add root-level observation fields too
    response_data.update(pydantic_obs.model_dump(mode="json"))
    
    # Tactical Stage Sync
    current_stage = detect_stage(pydantic_obs.logs)
    response_data["info"]["attack_stage"] = get_stage_index(current_stage)
    
    return response_data

@app.post("/v1/step")
@app.post("/step")
async def step(request: Request):
    try:
        body = await request.body()
        payload = json.loads(body) if body else {}
    except Exception:
        payload = {}
        
    global _env_wrapper, _current_obs, _current_pydantic_obs
    print("\n[STEP] Request received")
    
    try:
        if _env_wrapper is None:
            return {"error": "Environment not initialized"}
        
        # 0. Autonomous Auto-Reset Guard
        if _env_wrapper.sim.done:
            print(f"[LOOP] Episode concluded at Step {_env_wrapper.sim.step_id}. Triggering Auto-Reset...")
            current_task = _env_wrapper.sim.task_id
            _env_wrapper = AutoSecGymEnv(task_id=current_task, seed=int(os.getenv("RANDOM_SEED", "42")))
            _current_obs, info = _env_wrapper.reset()
            _current_pydantic_obs = info["pydantic_obs"]
            # Fall through to process the original step request on the fresh environment
        
        # 1. Action Selection: External Pilot vs internal RL
        client_action_data = payload.get("action")
        is_ip_mismatch = payload.get("is_ip_mismatch", False)
        is_over_isolation = payload.get("is_over_isolation", False)
        
        if client_action_data and client_action_data.get("action_type"):
            print("[STEP] External Pilot Action Received.")
            from autosec_openenv.models import ActionType, Action
            
            # Map client dictionary to Action object
            atype_str = client_action_data.get("action_type", "NO_ACTION")
            if "." in atype_str: atype_str = atype_str.split(".")[-1]
            target = client_action_data.get("target", "none")
            
            action_obj = Action(
                action_type=ActionType(atype_str),
                target=target,
                strategy=client_action_data.get("strategy", "DETECT"),
                tactic=client_action_data.get("tactic", "NO_ACTION"),
                reasoning=client_action_data.get("reasoning", "Client Pilot Action")
            )
            
            # Capture Malicious context BEFORE the step (successful blocks erase logs)
            malicious_sources_pre = {str(log.source_ip).strip() for log in _env_wrapper.sim.logs if log.is_malicious}
            malicious_hosts_pre = {str(log.hostname).strip() for log in _env_wrapper.sim.logs if log.is_malicious}

            # Execute directly on simulation
            pre_threats = _env_wrapper.sim.state_obj.active_threats
            obs_obj, reward_obj, done, info_sim = _env_wrapper.sim.step(action_obj)
            post_threats = _env_wrapper.sim.state_obj.active_threats
            
            # Robust mapping for IPs and Hostnames using PRE-STEP context
            clean_target = str(target).strip()
            is_correct_target = (clean_target in malicious_hosts_pre) or (clean_target in malicious_sources_pre)
            
            # 2. IP vs Host Mismatch Detection
            is_ip = "." in target or (target and target[0].isdigit())
            is_ip_mismatch = False
            a_type = action_obj.action_type
            if a_type == ActionType.BLOCK_IP and not is_ip:
                is_ip_mismatch = True
            elif a_type == ActionType.ISOLATE_HOST and is_ip:
                is_ip_mismatch = True
            
            # 3. Correct Action Type logic
            has_threat = _env_wrapper.sim.state_obj.active_threats > 0 or len(malicious_sources_pre) > 0
            is_correct_action_type = (has_threat and a_type in [ActionType.BLOCK_IP, ActionType.ISOLATE_HOST])
            if not has_threat and a_type in [ActionType.MONITOR, ActionType.NO_ACTION]:
                is_correct_action_type = True

            print(f"[REWARD_DEBUG] Target: '{clean_target}' | Correct: {is_correct_target} | ActionMatch: {is_correct_action_type}")
            
            step_info = {
                "resolved_threat": post_threats < pre_threats,
                "is_correct_target": is_correct_target,
                "is_correct_action_type": is_correct_action_type,
                "is_ip_mismatch": is_ip_mismatch,
                "is_over_isolation": is_over_isolation,
                "is_repeated": False
            }
            
            # Override standard simulation reward with stabilized RL reward
            reward = calculate_reward(action_obj, _env_wrapper.sim.state_obj, step_info)
            
            # Synchronize the internal RL vector for future predictions
            _current_obs = _env_wrapper._transform_obs(obs_obj)
            _current_pydantic_obs = obs_obj
            
            # Populate info dictionary for compliance
            info = {
                "pydantic_obs": obs_obj,
                "pydantic_reward": {"value": reward, "feedback": info_sim.get("feedback", "")},
                "sim_info": info_sim
            }
        else:
            # Fall back to internal Hybrid Brain (Autonomous Pilot)
            sim_env = _env_wrapper.sim
            print(f"[STEP] Autonomous Pilot Step {sim_env.step_id + 1}...")
            
            # Use Hybrid Decision logic
            hist_tups = [
                (str(a.get("action_type", "")).split(".")[-1], a.get("target", "none")) if isinstance(a, dict)
                else (str(getattr(a, "action_type", "NO_ACTION")).split(".")[-1], getattr(a, "target", "none"))
                for a in sim_env.action_history
            ]
            if _current_pydantic_obs is None:
                return {"error": "Environment not reset. Call /v1/reset first."}
            action_dict, source = _decide_action(sim_env.step_id + 1, _current_pydantic_obs, hist_tups)
            
            # Map the inferred action_dict back to indices for the Gym step if needed, 
            # or just execute directly on the simulation like the External Pilot does.
            
            from autosec_openenv.models import Action, ActionType
            # Normalize atype: ActionType is str+Enum, so str(atype) yields the string value directly.
            # Handles: ActionType enum object, "ActionType.BLOCK_IP" string, or plain "BLOCK_IP" string.
            atype_raw = action_dict["action_type"]
            if isinstance(atype_raw, ActionType):
                atype = atype_raw  # Already correct type
            else:
                atype_str = str(atype_raw)
                if "." in atype_str:
                    atype_str = atype_str.split(".")[-1]
                atype = ActionType(atype_str)
            
            action_obj = Action(
                action_type=atype,
                target=action_dict["target"],
                strategy="CONTAIN",
                tactic="NO_ACTION",
                reasoning=action_dict.get("reasoning", f"Autonomous {source} Action")
            )
            
            # Capture state pre-step for reward calculation
            malicious_sources_pre = {str(log.source_ip).strip() for log in _env_wrapper.sim.logs if log.is_malicious}
            pre_threats = _env_wrapper.sim.state_obj.active_threats
            
            # Execute directly on simulation
            obs_obj, reward_obj, done, info_sim = _env_wrapper.sim.step(action_obj)
            post_threats = _env_wrapper.sim.state_obj.active_threats
            
            # Sync reward (using the same logic as manual steps)
            step_info = {
                "resolved_threat": post_threats < pre_threats,
                "is_correct_target": action_obj.target in malicious_sources_pre or any(l.hostname == action_obj.target and l.is_malicious for l in _env_wrapper.sim.logs),
                "is_correct_action_type": True, # Assume brain knows what it's doing
                "is_ip_mismatch": False, 
                "is_over_isolation": False,
                "is_repeated": False
            }
            reward = calculate_reward(action_obj, _env_wrapper.sim.state_obj, step_info)
            
            # Synchronize internal RL vector
            _current_obs = _env_wrapper._transform_obs(obs_obj)
            _current_pydantic_obs = obs_obj
            
            info = {
                "pydantic_obs": obs_obj,
                "pydantic_reward": {"value": reward, "feedback": info_sim.get("feedback", "")},
                "sim_info": info_sim
            }
        # 2. Preparation for Evaluation/Memory
        sim_env = _env_wrapper.sim
        
        # 3. Calling Persona Evaluator for rich feedback
        print("[STEP] Calling Persona Evaluator...")
        persona_feedback = _evaluator.evaluate_action(action_obj, sim_env.state_obj, sim_env.logs)
        
        # 4. Contextual Memory
        print("[STEP] Storing in Vector Memory...")
        try:
            get_memory().store_experience(
                state_summary=f"Threats: {sim_env.state_obj.active_threats}, Comp: {sim_env.state_obj.compromise_level}%",
                action=action_obj.model_dump(),
                reward=float(reward),
                success=reward > 0
            )
        except Exception as mem_e:
            print(f"Memory error: {mem_e}")

        # Record history for frontend
        p_scores = [p["score"] for p in persona_feedback["personas"].values() if "score" in p]
        confidence = sum(p_scores) / len(p_scores) if p_scores else 0.5
        _scheduler.record_intelligence_score(float(confidence))
        
        action_dict = action_obj.model_dump()
        action_dict.update({
            "persona_evaluations": persona_feedback["personas"],
            "step_score": float(reward),
            "step": sim_env.step_id,
            "confidence": round(float(confidence), 4)
        })
        sim_env.action_history.append(action_dict)
        
        if done:
            print("[STEP] Done. Success reporting.")
            succeeded = sim_env.state_obj.active_threats == 0
            _scheduler.record_episode(success=succeeded, final_reward=float(reward))

        pydantic_obs = info["pydantic_obs"]
        pydantic_reward = info["pydantic_reward"]
        
        # Standardize reward output (handle both dict and Pydantic model)
        reward_out = pydantic_reward
        if hasattr(pydantic_reward, "model_dump"):
            reward_out = pydantic_reward.model_dump()
            
        print(f"[STEP] Success. Reward: {reward_out.get('value', 0.0)}")
        # Finalize reward as float for strict validation compatibility
        reward_val = float(reward_out.get("value", 0.0)) if isinstance(reward_out, dict) else float(reward_out)

        # Return comprehensive response for maximum compatibility
        response_data = {
            "observation": pydantic_obs.model_dump(mode="json"),
            "reward": reward_val,  # Value for validator
            "pydantic_reward": reward_out,  # Full object for dashboard
            "done": bool(done),
            "info": {
                "difficulty": str(_scheduler.current_difficulty.value),
                "explanation": "Adaptive RL policy step complete.",
                "attack_stage": get_stage_index(detect_stage(pydantic_obs.logs)),
                "cumulative_intelligence": round(_scheduler.get_average_intelligence(), 4)
            }
        }
        # Unroll observation to root level for multi-standard compatibility
        response_data.update(pydantic_obs.model_dump(mode="json"))
        return response_data
        
    except Exception as e:
        print(f"[ERROR] Step Failure: {e}")
        import traceback
        traceback.print_exc()
        return {"error": str(e), "traceback": "Check server logs"}

@app.get("/v1/state")
async def get_state():
    global _env_wrapper
    if _env_wrapper is None:
        return {"status": "INACTIVE"}
        
    sim_env = _env_wrapper.sim
    cur_stage = "benign"
    if sim_env.last_attacker_action:
        cur_stage = sim_env.last_attacker_action["attack_type"]
        
    elapsed = int(time.time() - _episode_elapsed_start)
        
    return {
        "status": "ACTIVE",
        "task_id": sim_env.task_info.task_id if hasattr(sim_env, "task_info") else "task_hard",
        "system_state": sim_env.state(),
        "logs": [log.model_dump() for log in sim_env.logs[-10:]],
        "action_history": [a.model_dump() if hasattr(a, 'model_dump') else a for a in sim_env.action_history[-10:]],
        "cumulative_score": sim_env.cumulative_score,
        "threats_resolved": sim_env.threats_resolved,
        "difficulty": _scheduler.current_difficulty,
        "current_stage": cur_stage,
        "episode_elapsed_s": elapsed,
        "rl_telemetry": {
            "episodes": _scheduler.episode_count,
            "success_rate": sum(_scheduler.success_history) / max(1, len(_scheduler.success_history))
        }
    }

@app.get("/v1/result")
async def get_result():
    """Returns the final graded result for the current episode."""
    global _env_wrapper
    if _env_wrapper is None:
        return {"final_grader_score": 0.0, "summary": "No episode ran.", "persona_scores": {}}

    try:
        sim_env = _env_wrapper.sim
        state = sim_env.state_obj
        threats_remaining = state.active_threats
        summary = "All threats resolved." if threats_remaining == 0 else f"{threats_remaining} threat(s) remaining."

        # Use get_episode_result() - the correct grader method
        episode_result = sim_env.grader.get_episode_result(
            final_state_obj=state,
            total_steps=sim_env.step_id,
            cumulative_reward=sim_env.cumulative_score,
            threats_resolved=sim_env.threats_resolved,
            threats_total=max(1, sim_env.threats_total),
            errors=sim_env.errors,
            action_history=sim_env.action_history,
            logs=sim_env.logs
        )

        # Get persona evaluations from last action history entry
        persona_scores = {}
        if sim_env.action_history:
            last = sim_env.action_history[-1]
            if isinstance(last, dict):
                persona_scores = last.get("persona_evaluations", {})

        # Return full flattened result for maximum grader compatibility
        result_data = {
            "final_grader_score": round(float(episode_result.final_grader_score), 4),
            "summary": episode_result.summary,
            "persona_scores": episode_result.persona_scores,
            "telemetry": {
                "steps_taken": sim_env.step_id,
                "threats_total": sim_env.threats_total,
                "threats_resolved": sim_env.threats_resolved,
                "cumulative_score": sim_env.cumulative_score,
                "difficulty": str(_scheduler.current_difficulty.value),
            }
        }
        # Unroll EpisodeResult fields into the root level
        result_data.update(episode_result.model_dump(mode="json"))
        return result_data
    except Exception as e:
        import traceback
        traceback.print_exc()
        return {"final_grader_score": None, "summary": f"Grader error: {e}", "persona_scores": {}}


# Serve built dashboard if it exists
# MOVED TO BOTTOM to prevent greedy mount 404s on API routes
if os.path.exists("dashboard/dist"):
    app.mount("/", StaticFiles(directory="dashboard/dist", html=True), name="static")

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=7860)
