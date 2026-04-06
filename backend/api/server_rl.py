"""
server_rl.py — Enhanced API Gateway for AutoSec RL
==================================================
Extends the original FastAPI server with RL-specific telemetry,
vector memory endpoints, curriculum difficulty, and explanations.
"""

from fastapi import FastAPI, HTTPException, Body
from fastapi.middleware.cors import CORSMiddleware
from typing import Dict, Any
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
async def reset():
    global _env_wrapper, _current_obs, _episode_elapsed_start
    print("Resetting Environment...")
    params = _scheduler.get_environment_params()
    
    _env_wrapper = AutoSecGymEnv(task_id="task_rl_01")
    _current_obs, _ = _env_wrapper.reset()
    _episode_elapsed_start = time.time()
    
    print(f"Environment reset. Difficulty: {_scheduler.current_difficulty}")
    return {
        "status": "ACTIVE",
        "difficulty": _scheduler.current_difficulty
    }

@app.post("/v1/step")
async def step(payload: Dict[str, Any] = Body(default={})):
    global _env_wrapper, _current_obs
    print("\n[STEP] Request received")
    
    try:
        if _env_wrapper is None:
            return {"error": "Environment not initialized"}
        
        # 1. Action Selection
        if _model:
            print("[STEP] Inference...")
            action_multi, _ = _model.predict(_current_obs, deterministic=True)
        else:
            action_multi = [0, 3, 0]
            
        s_idx, t_idx, trg_idx = action_multi
        from autosec_openenv.models import ActionType, Action
        
        tactic_str = TACTICS[t_idx]
        target = COMMON_TARGETS[trg_idx]
        
        # Map TACTICS string to ActionType enum
        a_type = ActionType.NO_ACTION
        if tactic_str == "ISOLATE_HOST": a_type = ActionType.ISOLATE_HOST
        elif tactic_str == "BLOCK_IP": a_type = ActionType.BLOCK_IP
        elif tactic_str == "INSPECT_LOGS": a_type = ActionType.MONITOR
        
        action_obj = Action(
            action_type=a_type, target=target,
            strategy=STRATEGIES[s_idx], tactic=tactic_str,
            reasoning=f"Agent Strategy: {STRATEGIES[s_idx]}"
        )
        
        sim_env = _env_wrapper.sim
        
        # 2. Evaluation
        print("[STEP] Calling Persona Evaluator...")
        persona_feedback = _evaluator.evaluate_action(action_obj, sim_env.state, sim_env.logs)
        
        print("[STEP] Generating explanation...")
        explanation = generate_action_explanation(action_obj, sim_env.logs, persona_feedback)
        
        # 3. Environment Step
        print("[STEP] Executing env.step...")
        _current_obs, reward, done, _, info = _env_wrapper.step(action_multi)
        
        # 4. Contextual Memory
        print("[STEP] Storing in Vector Memory...")
        try:
            get_memory().store_experience(
                state_summary=f"Threats: {sim_env.state.active_threats}, Comp: {sim_env.state.compromise_level}%",
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
            print("[STEP] Done. Resetting env.")
            _current_obs, _ = _env_wrapper.reset()
            
        print("[STEP] Success.")
        return {
            "reward": float(reward),
            "done": bool(done),
            "explanation": explanation
        }
        
    except Exception as e:
        print(f"[ERROR] Step Failure: {e}")
        import traceback
        traceback.print_exc()
        # Return as 200 with error info to avoid CORS/Network error on browser side
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
        "system_state": sim_env.state.model_dump(),
        "logs": [log.model_dump() for log in sim_env.logs[-10:]],
        "action_history": sim_env.action_history[-10:],
        "cumulative_score": sim_env.cumulative_score,
        "difficulty": _scheduler.current_difficulty,
        "current_stage": cur_stage,
        "episode_elapsed_s": elapsed,
        "rl_telemetry": {
            "episodes": _scheduler.episode_count,
            "success_rate": sum(_scheduler.success_history) / max(1, len(_scheduler.success_history))
        }
    }

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=7860)
