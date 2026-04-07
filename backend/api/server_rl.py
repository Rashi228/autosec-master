"""
server_rl.py — Enhanced API Gateway for AutoSec RL
==================================================
Extends the original FastAPI server with RL-specific telemetry,
vector memory endpoints, curriculum difficulty, and explanations.
"""

from fastapi import FastAPI, HTTPException, Body
from fastapi.middleware.cors import CORSMiddleware
from typing import Dict, Any
import os
import time

from autosec_openenv.models import Action
from backend.evaluator.personas import MultiPersonaEvaluator
from backend.rl.explainability import generate_action_explanation
from backend.curriculum.scheduler import CurriculumScheduler
from backend.memory.vector_db import VectorMemory
from backend.rl.env_wrapper import AutoSecGymEnv, STRATEGIES, TACTICS, COMMON_TARGETS

try:
    from stable_baselines3 import PPO
    _model = PPO.load("./logs/rl_training/autosec_ppo_final")
except Exception as e:
    print(f"Warning: Could not load PPO model. Fallback active. {e}")
    _model = None

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
_episode_elapsed_start = 0

# Lazy-loaded components to speed up startup
_memory = None

def get_memory():
    global _memory
    if _memory is None:
        from backend.memory.vector_db import VectorMemory
        print("Initializing Vector Memory (ChromaDB)...")
        _memory = VectorMemory()
    return _memory

@app.get("/")
async def root():
    return {"message": "AutoSec Adaptive RL API is active."}

@app.post("/v1/reset")
async def reset(payload: Dict[str, Any] = Body(default={})):
    global _env_wrapper, _current_obs, _episode_elapsed_start
    task_id = payload.get("task_id", "task_hard")
    seed    = int(os.getenv("RANDOM_SEED", "42"))
    print(f"Resetting Environment... task={task_id} seed={seed}")
    params = _scheduler.get_environment_params()
    
    _env_wrapper = AutoSecGymEnv(task_id=task_id, seed=seed)
    _current_obs, info = _env_wrapper.reset()
    _episode_elapsed_start = time.time()
    
    pydantic_obs = info["pydantic_obs"]
    print(f"Environment reset. Difficulty: {_scheduler.current_difficulty}")
    return {
        "observation": pydantic_obs.model_dump(),
        "info": {
            "status": "ACTIVE",
            "difficulty": _scheduler.current_difficulty,
            "params": params
        }
    }

@app.post("/v1/step")
async def step(payload: Dict[str, Any] = Body(default={})):
    global _env_wrapper, _current_obs
    print("\n[STEP] Request received")
    
    try:
        if _env_wrapper is None:
            return {"error": "Environment not initialized"}
        
        # 1. Action Selection: External Pilot vs internal RL
        client_action_data = payload.get("action")
        if client_action_data:
            print("[STEP] External Pilot Action Received.")
            from autosec_openenv.models import ActionType, Action
            
            # Map client dictionary to Action object
            atype_str = client_action_data.get("action_type", "NO_ACTION")
            if "." in atype_str: atype_str = atype_str.split(".")[-1]
            
            action_obj = Action(
                action_type=ActionType(atype_str),
                target=client_action_data.get("target", "none"),
                strategy=client_action_data.get("strategy", "DETECT"),
                tactic=client_action_data.get("tactic", "MONITOR"),
                reasoning=client_action_data.get("reasoning", "Client Pilot Action")
            )
            
            # Execute directly on simulation to bypass internal model prediction
            obs_obj, reward_obj, done, info_sim = _env_wrapper.sim.step(action_obj)
            reward = float(reward_obj.value if hasattr(reward_obj, 'value') else 0.0)
            
            # Synchronize the internal RL vector for future predictions
            _current_obs = _env_wrapper._transform_obs(obs_obj)
            
            # Populate info dictionary for compliance
            info = {
                "pydantic_obs": obs_obj,
                "pydantic_reward": reward_obj,
                "sim_info": info_sim
            }
        else:
            # Fall back to internal RL Autonomous Pilot
            if _model:
                print("[STEP] RL Autonomous Inference...")
                action_multi, _ = _model.predict(_current_obs, deterministic=True)
            else:
                action_multi = [0, 3, 0] # Default
                
            s_idx, t_idx, trg_idx = action_multi
            from autosec_openenv.models import ActionType, Action
            
            action_obj = Action(
                action_type=ActionType.NO_ACTION, 
                target=COMMON_TARGETS[trg_idx],
                strategy=STRATEGIES[s_idx], 
                tactic=TACTICS[t_idx],
                reasoning=f"Agent Strategy: {STRATEGIES[s_idx]}"
            )
            
            # Re-map indices to ActionType
            if action_obj.tactic == "ISOLATE_HOST": action_obj.action_type = ActionType.ISOLATE_HOST
            elif action_obj.tactic == "BLOCK_IP": action_obj.action_type = ActionType.BLOCK_IP
            elif action_obj.tactic == "INSPECT_LOGS": action_obj.action_type = ActionType.MONITOR
            
            # Execute step through the Hub wrapper to update internal RL state
            _current_obs, reward, done, _, info = _env_wrapper.step(action_multi)
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
        action_dict = action_obj.model_dump()
        action_dict.update({
            "persona_evaluations": persona_feedback["personas"],
            "step_score": float(reward)
        })
        sim_env.action_history.append(action_dict)
        
        if done:
            print("[STEP] Done. Success reporting.")
            succeeded = sim_env.state_obj.active_threats == 0
            _scheduler.record_episode(success=succeeded, final_reward=float(reward))

        pydantic_obs = info["pydantic_obs"]
        pydantic_reward = info["pydantic_reward"]
        
        print("[STEP] Success.")
        return {
            "observation": pydantic_obs.model_dump(),
            "reward": pydantic_reward.model_dump(),
            "done": bool(done),
            "info": {
                "difficulty": str(_scheduler.current_difficulty),
                "explanation": "Adaptive RL policy step complete."
            }
        }
        
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
        "system_state": sim_env.state(),
        "logs": [log.model_dump() for log in sim_env.logs[-10:]],
        "action_history": [a.model_dump() if hasattr(a, 'model_dump') else a for a in sim_env.action_history[-10:]],
        "cumulative_score": sim_env.cumulative_score,
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

        return {
            "final_grader_score": round(float(episode_result.final_grader_score), 4),
            "summary": episode_result.summary,
            "persona_scores": episode_result.persona_scores,
            "telemetry": {
                "steps_taken": sim_env.step_id,
                "threats_total": sim_env.threats_total,
                "threats_resolved": sim_env.threats_resolved,
                "cumulative_score": sim_env.cumulative_score,
                "difficulty": str(_scheduler.current_difficulty),
            }
        }
    except Exception as e:
        import traceback
        traceback.print_exc()
        return {"final_grader_score": None, "summary": f"Grader error: {e}", "persona_scores": {}}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=7860)
