"""
inference.py — Hybrid Defender Brain: Smart Policy + Selective LLM
===================================================================
Architecture:
  - Steps 1, 3, 5... → Smart Deterministic Policy (always runs, never fails)
  - Steps 2, 4, 6... → LLM Enhancement (called every LLM_CALL_INTERVAL steps)
  - LLM failure      → Seamless fallback to deterministic policy, logged
  - All episodes complete reliably, independent of API credit status

Usage:
    python inference.py                   # task_hard (default)
    python inference.py task_easy
    python inference.py task_medium
"""

import os
import sys
import json
import time
import random
import requests
import logging
import numpy as np
from typing import List, Optional, Tuple
from datetime import datetime
try:
    from stable_baselines3 import PPO
except ImportError:
    PPO = None

from openai import OpenAI
from dotenv import load_dotenv

from autosec_openenv.models import (
    Observation, Action, ActionType,
    SecurityLog, Severity, EventType
)
from autosec_openenv.memory import ExperienceMemory, Experience
from autosec_openenv.kill_chain import detect_stage

# ─────────────────────────────────────────────────────────────────────────────
# MODEL METADATA (Neural Brain Fixed Mappings)
# ─────────────────────────────────────────────────────────────────────────────
# Note: These indices are fixed for the current PPO model version. 
# Do not reorder without retraining the model.
PPO_STRATEGIES = ["DETECT", "INVESTIGATE", "CONTAIN", "REMEDIATE"]
PPO_TACTICS    = ["INSPECT_LOGS", "ISOLATE_HOST", "BLOCK_IP", "NO_ACTION"]
PPO_HOSTNAMES  = ["web-prod-01", "db-server-01", "dc-01", "hr-laptop-12", "dev-pc-04"]
PPO_TARGETS    = PPO_HOSTNAMES + ["attacker_ip"]

# ─────────────────────────────────────────────────────────────────────────────
# CONFIGURATION
# ─────────────────────────────────────────────────────────────────────────────
load_dotenv()

ENV_BASE_URL       = os.getenv("ENV_BASE_URL",       "http://localhost:7860")
MODEL_NAME         = os.getenv("MODEL_NAME",         "meta-llama/Llama-3.1-8B-Instruct")
API_BASE_URL       = os.getenv("API_BASE_URL",       "https://router.huggingface.co/v1")
MAX_STEPS          = int(os.getenv("MAX_STEPS",      "15"))
MAX_TOKENS         = int(os.getenv("MAX_TOKENS",     "256"))
TEMPERATURE        = float(os.getenv("TEMPERATURE",  "0.0"))
LLM_CALL_INTERVAL  = int(os.getenv("LLM_INTERVAL",    "3"))   # LLM called every N steps
RANDOM_SEED        = int(os.getenv("RANDOM_SEED",     "42"))
ALLOW_FALLBACK     = os.getenv("ALLOW_FALLBACK",      "true").lower() == "true"  # False = strict eval
TOP_P              = float(os.getenv("TOP_P",          "1.0"))

# Fix global seed for reproducibility
random.seed(RANDOM_SEED)

client = OpenAI(api_key=os.getenv("OPENAI_API_KEY"), base_url=API_BASE_URL)
memory = ExperienceMemory()

# ─────────────────────────────────────────────────────────────────────────────
# LOGGING
# ─────────────────────────────────────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s | %(levelname)s | %(message)s",
    datefmt="%H:%M:%S"
)
logger = logging.getLogger("autosec")

# 4. Continuous Learning Options
ONLINE_LEARNING    = os.getenv("ONLINE_LEARNING",     "false").lower() == "true"
LEARNING_THRESHOLD = float(os.getenv("LEARNING_THRESHOLD", "0.75"))
PPO_MODEL_PATH     = os.getenv("PPO_MODEL_PATH",      "./logs/rl_training/autosec_ppo_final.zip")

# 5. Load PPO Brain
ppo_model = None
if PPO is not None and os.path.exists(PPO_MODEL_PATH):
    try:
        ppo_model = PPO.load(PPO_MODEL_PATH)
        logger.info(f"PPO Brain initialized from {PPO_MODEL_PATH}")
    except Exception as e:
        logger.warning(f"Failed to load PPO brain: {e}")
else:
    logger.warning("PPO Brain (stable-baselines3) not found. Fallback to POLICY only.")

# ─────────────────────────────────────────────────────────────────────────────
# SEVERITY PRIORITY MAP (for threat prioritization)
# ─────────────────────────────────────────────────────────────────────────────
SEVERITY_SCORE = {
    "CRITICAL": 4,
    "HIGH":     3,
    "MEDIUM":   2,
    "LOW":      1,
    "INFO":     0,
}

CRITICAL_HOSTS = {"dc-01", "db-server-01", "web-prod-01"}

# ─────────────────────────────────────────────────────────────────────────────
# SMART DETERMINISTIC POLICY
# ─────────────────────────────────────────────────────────────────────────────
def _smart_policy(obs: Observation, history: List[Tuple[str, str]]) -> Action:
    """
    Priority-based deterministic policy. Always produces a valid, non-redundant action.

    Priority order:
    1. Block highest-severity external attacker IPs not yet blocked
    2. Isolate critical infrastructure hosts under attack
    3. Isolate any compromised host not yet isolated
    4. Terminate processes on compromised non-isolated hosts
    5. Monitor (if no threats)
    """
    history_set = set(history)

    sys_state = (
        obs.system_state
        if isinstance(obs.system_state, dict)
        else obs.system_state.model_dump()
    )
    already_blocked  = set(sys_state.get("blocked_ips",    []) or [])
    already_isolated = set(sys_state.get("isolated_hosts", []) or [])
    malicious_logs   = [l for l in obs.logs if l.is_malicious]

    if not malicious_logs or obs.num_active_threats == 0:
        return Action(
            action_type=ActionType.MONITOR,
            target="none",
            reasoning="Smart Policy: No active threats detected."
        )

    # Sort malicious logs by severity descending
    malicious_logs = sorted(
        malicious_logs,
        key=lambda l: SEVERITY_SCORE.get(str(l.severity).upper().split(".")[-1], 0),
        reverse=True
    )

    # 1. Block external attacker IPs (highest severity first)
    for log in malicious_logs:
        ip = log.source_ip
        if (ip and ip not in already_blocked
                and ("BLOCK_IP", ip) not in history_set):
            return Action(
                action_type=ActionType.BLOCK_IP,
                target=ip,
                reasoning=f"Smart Policy: Block attacker IP {ip} [{log.severity}]."
            )

    # 2. Isolate critical hosts first
    for log in malicious_logs:
        host = log.hostname
        if (host and host in CRITICAL_HOSTS
                and host not in already_isolated
                and ("ISOLATE_HOST", host) not in history_set):
            return Action(
                action_type=ActionType.ISOLATE_HOST,
                target=host,
                reasoning=f"Smart Policy: Isolate critical host {host} [{log.severity}]."
            )

    # 3. Isolate any compromised host
    for log in malicious_logs:
        host = log.hostname
        if (host and host not in already_isolated
                and ("ISOLATE_HOST", host) not in history_set):
            return Action(
                action_type=ActionType.ISOLATE_HOST,
                target=host,
                reasoning=f"Smart Policy: Isolate compromised host {host}."
            )

    # 4. Terminate processes (last resort before no-action)
    for log in malicious_logs:
        host = log.hostname
        if host and ("TERMINATE_PROCESS", host) not in history_set:
            return Action(
                action_type=ActionType.TERMINATE_PROCESS,
                target=host,
                reasoning=f"Smart Policy: Terminate malicious process on {host}."
            )

    # 5. No novel action available
    return Action(
        action_type=ActionType.MONITOR,
        target="none",
        reasoning="Smart Policy: All known threats already handled."
    )


# ─────────────────────────────────────────────────────────────────────────────
# LLM SYSTEM PROMPT
# ─────────────────────────────────────────────────────────────────────────────
_SYSTEM_PROMPT = """You are an autonomous SOC security engineer.

VALID action_type values (use EXACTLY one):
  BLOCK_IP | ISOLATE_HOST | TERMINATE_PROCESS | MONITOR | NO_ACTION

RULES:
- Target must be an exact IP or hostname from the logs shown.
- Never repeat a target already in HISTORY.
- MONITOR/NO_ACTION only if zero active threats.
- Prefer BLOCK_IP for external IPs, ISOLATE_HOST for internal hosts.

Respond with ONLY this JSON (no extra text):
{"action_type": "BLOCK_IP", "target": "<value>", "reasoning": "<one sentence>"}
"""


def _build_llm_prompt(obs: Observation, feedback: str, history: List[Tuple[str, str]]) -> str:
    """Minimal, token-efficient prompt for the LLM."""
    sys_state = (
        obs.system_state
        if isinstance(obs.system_state, dict)
        else obs.system_state.model_dump()
    )
    log_lines = ""
    for log in obs.logs[-8:]:  # Limit to 8 most recent logs
        flag = "MALICIOUS" if log.is_malicious else "benign"
        log_lines += f"  [{flag}] {log.event_type} | host={log.hostname} | src={log.source_ip} | sev={log.severity}\n"

    history_str = ", ".join([f"{a}:{t}" for a, t in history[-5:]]) or "none"

    return f"""Threats={obs.num_active_threats} | Step={obs.step_id}
Blocked={sys_state.get('blocked_ips',[])} | Isolated={sys_state.get('isolated_hosts',[])}
History={history_str}
Feedback={feedback or 'none'}
Logs:
{log_lines}"""


# ─────────────────────────────────────────────────────────────────────────────
# LLM CALL (Optional Enhancement — never crashes episode)
# ─────────────────────────────────────────────────────────────────────────────
def _try_llm_action(obs: Observation, feedback: str, history: List[Tuple[str, str]]) -> Optional[Action]:
    """
    Attempts an LLM-guided action. Returns None on any failure.
    Caller seamlessly falls back to smart policy on None return.
    """
    try:
        response = client.chat.completions.create(
            model=MODEL_NAME,
            messages=[
                {"role": "system", "content": _SYSTEM_PROMPT},
                {"role": "user",   "content": _build_llm_prompt(obs, feedback, history)}
            ],
            response_format={"type": "json_object"},
            temperature=TEMPERATURE,
            max_tokens=MAX_TOKENS,
            top_p=TOP_P,        # determinism: 1.0 = no nucleus sampling restriction
        )

        raw = json.loads(response.choices[0].message.content)
        atype_str = str(raw.get("action_type", "")).upper().strip()
        target    = str(raw.get("target", "none")).strip()
        reasoning = str(raw.get("reasoning", "LLM action."))

        # Validate enum
        valid_types = {e.value for e in ActionType}
        if atype_str not in valid_types:
            logger.warning(f"LLM returned invalid action_type '{atype_str}' — discarding.")
            return None

        sys_state = (
            obs.system_state
            if isinstance(obs.system_state, dict)
            else obs.system_state.model_dump()
        )
        blocked  = set(sys_state.get("blocked_ips",    []) or [])
        isolated = set(sys_state.get("isolated_hosts", []) or [])

        # Reject low-quality responses
        if obs.num_active_threats > 0:
            if atype_str in ("NO_ACTION", "MONITOR"):
                logger.warning("LLM chose passive action during active threat — discarding.")
                return None
            if target in ("none", "", "null") and atype_str in ("BLOCK_IP", "ISOLATE_HOST", "TERMINATE_PROCESS"):
                logger.warning(f"LLM gave empty target for {atype_str} — discarding.")
                return None
            # Redirect redundant actions to next-best rather than hard failing
            if atype_str == "BLOCK_IP" and target in blocked:
                logger.info(f"LLM wants to re-block {target} — redirecting to ISOLATE_HOST.")
                # Try isolating the hostname associated with this IP from logs
                for log in obs.logs:
                    if log.source_ip == target and log.hostname and log.hostname not in isolated:
                        return Action(
                            action_type=ActionType.ISOLATE_HOST,
                            target=log.hostname,
                            reasoning=f"Redirected: isolating {log.hostname} (source IP already blocked)."
                        ).model_dump()
                return None  # No valid redirect available
            if atype_str == "ISOLATE_HOST" and target in isolated:
                logger.info(f"LLM wants to re-isolate {target} — discarding.")
                return None

        return Action(action_type=ActionType(atype_str), target=target, reasoning=reasoning).model_dump()

    except Exception as e:
        logger.warning(f"LLM call failed: {type(e).__name__}: {e}")
        return None


# ─────────────────────────────────────────────────────────────────────────────
# PPO TRANSFORMS & DECISION
# ─────────────────────────────────────────────────────────────────────────────
def _transform_obs_for_ppo(obs: Observation) -> np.ndarray:
    """
    Transforms raw Observation into the 15-feature space expected by the PPO model.
    Matches the logic in backend/rl/env_wrapper.py.
    """
    sys_state = (
        obs.system_state if isinstance(obs.system_state, dict)
        else obs.system_state.model_dump()
    )
    vec = [
        float(sys_state.get("compromise_level", 0) / 100.0),
        float(obs.num_active_threats / 5.0),
        float(obs.step_id / 15.0) # Normalized to max steps
    ]
    
    malicious_hosts = {log.hostname for log in obs.logs if log.is_malicious}
    for h in PPO_HOSTNAMES:
        vec.append(1.0 if h in malicious_hosts else 0.0)
        
    malicious_ips = {log.source_ip for log in obs.logs if log.is_malicious and log.source_ip}
    vec.append(1.0 if len(malicious_ips) > 0 else 0.0)
    
    isolated = set(sys_state.get("isolated_hosts", []) or [])
    for h in PPO_HOSTNAMES:
        vec.append(1.0 if h in isolated else 0.0)
        
    last_log_malicious = obs.logs[-1].is_malicious if obs.logs else False
    vec.append(1.0 if last_log_malicious else 0.0)
    
    return np.array(vec, dtype=np.float32)

def _try_ppo_action(obs: Observation, history: List[Tuple[str, str]]) -> Optional[dict]:
    """
    Uses the learned PPO brain to predict the next reflexive action.
    Returns model_dump dict or None.
    """
    if not ppo_model:
        return None
        
    try:
        vec = _transform_obs_for_ppo(obs)
        action_multi, _states = ppo_model.predict(vec, deterministic=True)
        
        # Unpack MultiDiscrete [Strategy, Tactic, Target]
        tactic_idx = action_multi[1]
        target_idx = action_multi[2]
        
        tactic = PPO_TACTICS[tactic_idx]
        target = PPO_TARGETS[target_idx]
        
        # Diagnostic: Neural Brain is active, what does it think?
        if tactic in ("INSPECT_LOGS", "NO_ACTION"):
            # Don't log spam if it's passive and everything is fine
            if obs.num_active_threats > 0:
                logger.debug(f"🧠 [PPO] Neural brain is hesitant (predicted {tactic}) — falling back.")
            return None
            
        a_type = ActionType.MONITOR
        if tactic == "ISOLATE_HOST": a_type = ActionType.ISOLATE_HOST
        elif tactic == "BLOCK_IP":  a_type = ActionType.BLOCK_IP
        
        # Resolve 'attacker_ip' abstraction
        if target == "attacker_ip":
            mal_ips = [l.source_ip for l in obs.logs if l.is_malicious and l.source_ip]
            if mal_ips: target = mal_ips[-1]
            else: 
                logger.debug(f"🧠 [PPO] Brain predicts BLOCK_IP but can't find IP in logs — falling back.")
                return None
        
        # DYNAMIC ALIGNMENT: Auto-correct if PPO confuses BLOCK vs ISOLATE on hosts
        if a_type == ActionType.BLOCK_IP and target in PPO_HOSTNAMES:
            logger.info(f"🛡️ [PPO_ADJUST] Corrected BLOCK_IP on host {target} to ISOLATE_HOST for accuracy.")
            a_type = ActionType.ISOLATE_HOST
            tactic = "ISOLATE_HOST"
            
        return Action(
            action_type=a_type,
            target=target,
            reasoning=f"Neural Brain Strategy: Reflexive {tactic} on {target} (Pattern Match)."
        ).model_dump()
    except Exception as e:
        logger.warning(f"PPO inference error: {e}")
        return None


# ─────────────────────────────────────────────────────────────────────────────
# HYBRID DECISION (Triple Hybrid)
# ─────────────────────────────────────────────────────────────────────────────
def _decide_action(
    step: int,
    obs: Observation,
    feedback: str,
    history: List[Tuple[str, str]],
    telemetry: dict
) -> Tuple[dict, str]:
    """
    The Triple Hybrid Decision Loop:
    1. LLM Strategy (every LLM_CALL_INTERVAL)
    2. PPO Instinct (Learned Neural Reflex)
    3. Smart Policy (Deterministic Safety Net)
    """
    
    # 1. STRATEGIC LAYER: LLM
    use_llm = (step % LLM_CALL_INTERVAL == 0)
    if use_llm:
        telemetry["llm_attempts"] += 1
        llm_action = _try_llm_action(obs, feedback, history)
        if llm_action:
            act_tup = (llm_action["action_type"].upper().split(".")[-1], llm_action["target"])
            if act_tup in set(history):
                logger.info(f"🤖 [LLM] Strategic layer suggested redundant action {act_tup} — ignoring.")
                telemetry["llm_failures"] += 1
                telemetry["fallback_steps"].append(step)
            else:
                telemetry["llm_successes"] += 1
                return llm_action, "LLM"
        else:
            telemetry["llm_failures"] += 1
            telemetry["fallback_steps"].append(step)
            if not ALLOW_FALLBACK:
                return None, "ABORT"

    # 2. INSTINCT LAYER: PPO
    ppo_action = _try_ppo_action(obs, history)
    if ppo_action:
        act_tup = (ppo_action["action_type"].upper().split(".")[-1], ppo_action["target"])
        if act_tup in set(history):
            logger.info(f"🧠 [PPO] Neural reflex suggests redundant action {act_tup} — ignoring.")
        else:
            return ppo_action, "PPO"

    # 3. SAFETY LAYER: Smart Policy
    policy_action = _smart_policy(obs, history)
    return policy_action.model_dump(), "POLICY"


# ─────────────────────────────────────────────────────────────────────────────
# MAIN EPISODE LOOP
# ─────────────────────────────────────────────────────────────────────────────
def run_episode(task_id: str = "task_hard") -> Optional[dict]:
    """
    Runs a full evaluation episode. Always completes — never aborts on LLM failure.
    Returns structured result with bounded final_grader_score ∈ [0.0, 1.0].
    """
    telemetry = {
        "llm_attempts":  0,
        "llm_successes": 0,
        "llm_failures":  0,
        "fallback_steps": [],
        "ppo_steps":     [],
        "policy_steps":  [],
        "rewards":       [],
    }

    print(f"[START] Evaluation: {task_id} | Model: {MODEL_NAME} | "
          f"MaxSteps: {MAX_STEPS} | LLM every {LLM_CALL_INTERVAL} steps | "
          f"Seed: {RANDOM_SEED}")

    try:
        # ── Reset environment ─────────────────────────────────────────────
        reset_resp = requests.post(
            f"{ENV_BASE_URL}/v1/reset",
            json={"task_id": task_id}
        ).json()

        obs_data = reset_resp.get("observation")
        if not obs_data:
            raise RuntimeError(f"Reset failed — no observation returned: {reset_resp}")

        obs = Observation.model_validate(obs_data)
        done, step = False, 0
        last_feedback  = ""
        action_history: List[Tuple[str, str]] = []

        # ── Episode Loop ──────────────────────────────────────────────────
        while not done and step < MAX_STEPS:
            step += 1

            action, source = _decide_action(step, obs, last_feedback, action_history, telemetry)

            # Handle abort (ALLOW_FALLBACK=False + LLM failure)
            if source == "ABORT" or action is None:
                print(f"[ABORT] Episode terminated at step {step} (LLM failure, no fallback).")
                print(f"[END] Final Score: 0.0000 | Result: Aborted at step {step}")
                _log_telemetry(telemetry, step)
                return {"final_grader_score": 0.0, "summary": f"Aborted: LLM failure at step {step}", "aborted": True}

            if source == "POLICY":
                telemetry["policy_steps"].append(step)
            elif source == "PPO":
                telemetry["ppo_steps"].append(step)

            # Track history
            act_str = str(action["action_type"]).split(".")[-1].upper()
            action_history.append((act_str, action["target"]))

            # Execute step
            step_resp = requests.post(
                f"{ENV_BASE_URL}/v1/step",
                json={"action": action}
            ).json()

            if step_resp.get("error"):
                logger.error(f"Server error at step {step}: {step_resp['error']}")
                break

            reward_data  = step_resp.get("reward", {"value": 0.0, "feedback": ""})
            obs_data     = step_resp.get("observation")
            if not obs_data:
                logger.error(f"No observation at step {step}. Response: {step_resp}")
                break

            obs           = Observation.model_validate(obs_data)
            done          = step_resp.get("done", False)
            last_feedback = reward_data.get("feedback", "")
            reward_val    = max(0.0, min(1.0, float(reward_data.get("value", 0.0))))

            telemetry["rewards"].append(reward_val)

            # [STEP] — Show full explainability: What, Where, and WHY
            reasoning = action.get("reasoning", "No explanation.")
            print(
                f"[STEP] Step: {step:02d} | Source: {source:<6} | "
                f"Action: {act_str:<20} | Target: {action['target']:<22} | "
                f"Reward: {reward_val:.2f}"
            )
            print(f"       ↳ EXPLAIN: {reasoning}")

            # Persist to memory
            log_text = "\n".join([str(l) for l in obs.logs])
            memory.save_experience(Experience(
                state_summary=log_text[:200],
                action=act_str,
                target=action["target"],
                reward=reward_val,
                feedback=last_feedback,
                reasoning=action.get("reasoning", ""),
                success=reward_val > 0.4,
                timestamp=datetime.now().isoformat(),
                kill_chain_stage=detect_stage(obs.logs).value
            ))

        # ── Fetch Final Score ─────────────────────────────────────────────
        result = requests.get(f"{ENV_BASE_URL}/v1/result").json()
        score  = float(max(0.0, min(1.0, result.get("final_grader_score", 0.0))))
        summary = result.get("summary", "N/A")

        print("\n" + "="*80)
        print(f"🏁 EVALUATION COMPLETE: {task_id.upper()}")
        print(f"⭐ FINAL SCORE: {score*100:.1f}%")
        print(f"📋 SUMMARY: {summary}")
        print("="*80)

        _log_telemetry(telemetry, step)

        if score >= LEARNING_THRESHOLD and ONLINE_LEARNING:
            _trigger_online_learning(ppo_model, action_history, score)

        return {**result, "final_grader_score": score}

    except Exception as e:
        print(f"\n❌ [ERROR] Episode failed critically: {e}")
        import traceback
        traceback.print_exc()
        _log_telemetry(telemetry, step if 'step' in locals() else 0)
        return None


# ─────────────────────────────────────────────────────────────────────────────
# TELEMETRY REPORT
# ─────────────────────────────────────────────────────────────────────────────
def _log_telemetry(t: dict, total_steps: int):
    """Prints structured transparency telemetry after every episode."""
    llm_att  = t["llm_attempts"]
    llm_ok   = t["llm_successes"]
    ppo_s    = len(t["ppo_steps"])
    pol_s    = len(t["policy_steps"])
    
    rate     = f"{100 * llm_ok / llm_att:.1f}%" if llm_att > 0 else "N/A"
    rewards  = t["rewards"]
    avg_r    = f"{sum(rewards)/len(rewards):.3f}" if rewards else "N/A"

    print(f"\n[TELEMETRY] Steps={total_steps} | LLM_OK={llm_ok}/{llm_att} ({rate}) | "
          f"PPO_Steps={ppo_s} | Policy_Steps={pol_s} | AvgReward={avg_r}")

def _trigger_online_learning(model, history, final_score):
    """
    Lightweight online fine-tuning for PPO.
    In a real production environment, this would push to a centralized training queue.
    Here, we simulate by doing a mini-learn pass on the successful trajectories.
    """
    if model is None: return
    
    print(f"🎓 [LEARNING] High score ({final_score:.2f}) detected. Performing online policy refinement...")
    try:
        # PPO learn usually takes an env, so we perform a short fine-tune 
        # using the current experience buffer which contains the successful moves.
        # This is a 'soft' implementation of continuous learning.
        model.learn(total_timesteps=100, reset_num_timesteps=False)
        model.save(PPO_MODEL_PATH)
        print(f"💾 [SAVED] Neural Brain updated and synchronized with {PPO_MODEL_PATH}")
    except Exception as e:
        print(f"⚠️ [LEARNING_FAILED] Could not update policy: {e}")

    print(
        f"\n[TELEMETRY] "
        f"TotalSteps={total_steps} | "
        f"LLM_Calls={attempts} | LLM_OK={successes} ({rate}) | LLM_Fail={failures} | "
        f"PolicySteps={len(t['policy_steps'])} | "
        f"Fallbacks={len(t['fallback_steps'])} at steps {t['fallback_steps'] or 'none'} | "
        f"AvgReward={avg_r} | MaxReward={max_r}"
    )


# ─────────────────────────────────────────────────────────────────────────────
# ENTRY POINT
# ─────────────────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    task = "task_hard"
    for arg in sys.argv[1:]:
        if arg in ("task_easy", "task_medium", "task_hard"):
            task = arg
    run_episode(task)
