\
\
\
\
\
   

from fastapi import FastAPI, HTTPException, Body
from fastapi.middleware.cors import CORSMiddleware
from typing import Dict, Any, List
import os
import time

from autosec_openenv.models import Action, ActionType
from backend.rl.reward_engine import calculate_reward
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

@app.get("/health")
async def health():
    return {"status": "ok", "timestamp": time.time()}

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
        
                                                            
        client_action_data = payload.get("action")
        is_ip_mismatch = payload.get("is_ip_mismatch", False)
        is_over_isolation = payload.get("is_over_isolation", False)
        
        if client_action_data:
            print("[STEP] External Pilot Action Received.")
            from autosec_openenv.models import ActionType, Action
            
                                                    
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
            
                                                                                      
            malicious_sources_pre = {str(log.source_ip).strip() for log in _env_wrapper.sim.logs if log.is_malicious}
            malicious_hosts_pre = {str(log.hostname).strip() for log in _env_wrapper.sim.logs if log.is_malicious}

                                            
            pre_threats = _env_wrapper.sim.state_obj.active_threats
            obs_obj, reward_obj, done, info_sim = _env_wrapper.sim.step(action_obj)
            post_threats = _env_wrapper.sim.state_obj.active_threats
            
                                                                         
            clean_target = str(target).strip()
            is_correct_target = (clean_target in malicious_hosts_pre) or (clean_target in malicious_sources_pre)
            
                                              
            is_ip = "." in target or (target and target[0].isdigit())
            is_ip_mismatch = False
            a_type = action_obj.action_type
            if a_type == ActionType.BLOCK_IP and not is_ip:
                is_ip_mismatch = True
            elif a_type == ActionType.ISOLATE_HOST and is_ip:
                is_ip_mismatch = True
            
                                          
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
            
                                                                           
            reward = calculate_reward(action_obj, _env_wrapper.sim.state_obj, step_info)
            
                                                                       
            _current_obs = _env_wrapper._transform_obs(obs_obj)
            
                                                     
            info = {
                "pydantic_obs": obs_obj,
                "pydantic_reward": {"value": reward, "feedback": info_sim.get("feedback", "")},
                "sim_info": info_sim
            }
        else:
                                                       
            if _model:
                print("[STEP] RL Autonomous Inference...")
                action_multi, _ = _model.predict(_current_obs, deterministic=True)
            else:
                action_multi = [0, 3, 0]          
                
            s_idx, t_idx, trg_idx = action_multi
            from autosec_openenv.models import ActionType, Action
            
            action_obj = Action(
                action_type=ActionType.NO_ACTION, 
                target=COMMON_TARGETS[trg_idx],
                strategy=STRATEGIES[s_idx], 
                tactic=TACTICS[t_idx],
                reasoning=f"Agent Strategy: {STRATEGIES[s_idx]}"
            )
            
                                          
            if action_obj.tactic == "ISOLATE_HOST": action_obj.action_type = ActionType.ISOLATE_HOST
            elif action_obj.tactic == "BLOCK_IP": action_obj.action_type = ActionType.BLOCK_IP
            elif action_obj.tactic == "INSPECT_LOGS": action_obj.action_type = ActionType.MONITOR
            
                                                                              
            _current_obs, reward, done, _, info = _env_wrapper.step(action_multi)
                                              
        sim_env = _env_wrapper.sim
        
                                                        
        print("[STEP] Calling Persona Evaluator...")
        persona_feedback = _evaluator.evaluate_action(action_obj, sim_env.state_obj, sim_env.logs)
        
                              
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

                                     
        p_scores = [p["score"] for p in persona_feedback["personas"].values() if "score" in p]
        confidence = sum(p_scores) / len(p_scores) if p_scores else 0.5
        
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
        
                                                                         
        reward_out = pydantic_reward
        if hasattr(pydantic_reward, "model_dump"):
            reward_out = pydantic_reward.model_dump()
            
        print(f"[STEP] Success. Reward: {reward_out.get('value', 0.0)}")
        return {
            "observation": pydantic_obs.model_dump(),
            "reward": reward_out,
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
                                                                  
    global _env_wrapper
    if _env_wrapper is None:
        return {"final_grader_score": 0.0, "summary": "No episode ran.", "persona_scores": {}}

    try:
        sim_env = _env_wrapper.sim
        state = sim_env.state_obj
        threats_remaining = state.active_threats
        summary = "All threats resolved." if threats_remaining == 0 else f"{threats_remaining} threat(s) remaining."

                                                              
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
