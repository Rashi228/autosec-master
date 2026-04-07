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
from typing import List, Optional, Tuple
from datetime import datetime

from openai import OpenAI
from dotenv import load_dotenv

from autosec_openenv.models import (
    Observation, Action, ActionType,
    SecurityLog, Severity, EventType
)
from autosec_openenv.memory import ExperienceMemory, Experience
from autosec_openenv.kill_chain import detect_stage

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
# HYBRID DECISION
# ─────────────────────────────────────────────────────────────────────────────
def _decide_action(
    step: int,
    obs: Observation,
    feedback: str,
    history: List[Tuple[str, str]],
    telemetry: dict
) -> Tuple[dict, str]:
    """
    Returns (action_dict, decision_source).
    Tries LLM every LLM_CALL_INTERVAL steps; smart policy otherwise.
    """
    use_llm = (step % LLM_CALL_INTERVAL == 0)

    if use_llm:
        telemetry["llm_attempts"] += 1
        llm_action = _try_llm_action(obs, feedback, history)
        if llm_action:
            telemetry["llm_successes"] += 1
            return llm_action, "LLM"  # already a dict from _try_llm_action
        else:
            telemetry["llm_failures"] += 1
            telemetry["fallback_steps"].append(step)
            if not ALLOW_FALLBACK:
                logger.warning(f"Step {step}: LLM failed and ALLOW_FALLBACK=False — aborting episode.")
                return None, "ABORT"
            logger.info(f"Step {step}: LLM failed → smart policy fallback")

    # Default: smart deterministic policy
    action = _smart_policy(obs, history)
    return action.model_dump(), "POLICY"


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

            # [STEP] — OpenEnv mandatory marker
            print(
                f"[STEP] Step: {step:02d} | Source: {source:<6} | "
                f"Action: {act_str:<20} | Target: {action['target']:<22} | "
                f"Reward: {reward_val:.2f} | Done: {done}"
            )

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
        score  = result.get("final_grader_score")
        score  = float(max(0.0, min(1.0, score))) if score is not None else 0.0
        summary = result.get("summary", "N/A")

        print(f"[END] Final Score: {score:.4f} | Result: {summary}")
        _log_telemetry(telemetry, step)

        return {**result, "final_grader_score": score}

    except Exception as e:
        import traceback
        traceback.print_exc()
        print(f"[ERROR] Episode failed: {e}")
        _log_telemetry(telemetry, step if "step" in dir() else 0)
        return None


# ─────────────────────────────────────────────────────────────────────────────
# TELEMETRY REPORT
# ─────────────────────────────────────────────────────────────────────────────
def _log_telemetry(t: dict, total_steps: int):
    """Prints structured transparency telemetry after every episode."""
    attempts  = t["llm_attempts"]
    successes = t["llm_successes"]
    failures  = t["llm_failures"]
    rate      = f"{100 * successes / attempts:.1f}%" if attempts > 0 else "N/A"

    rewards = t["rewards"]
    avg_r   = f"{sum(rewards)/len(rewards):.3f}" if rewards else "N/A"
    max_r   = f"{max(rewards):.3f}" if rewards else "N/A"

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
