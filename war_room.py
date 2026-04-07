"""
war_room.py — Interactive SOC War Room Demo
============================================
Runs a live cinematic simulation of the SOC in action.
Shows Red Team (Attacker) vs Blue Team (Defender) in real-time.

Usage:
    python war_room.py                        # task_hard (default)
    python war_room.py --task task_easy
    python war_room.py --task task_medium
    python war_room.py --task task_hard
"""

import os
import sys
import time
import requests
import argparse
from datetime import datetime
from dotenv import load_dotenv

from autosec_openenv.models import Action, ActionType, Observation
from autosec_openenv.memory import ExperienceMemory, Experience
from autosec_openenv.kill_chain import detect_stage

load_dotenv()

ENV_BASE_URL = os.getenv("ENV_BASE_URL", "http://localhost:7860")
MAX_STEPS    = int(os.getenv("MAX_STEPS", "15"))
memory       = ExperienceMemory()

SEVERITY_COLOR = {
    "CRITICAL": "🔴",
    "HIGH":     "🟠",
    "MEDIUM":   "🟡",
    "LOW":      "🟢",
    "INFO":     "⚪",
}


def run_war_room(task_id: str):
    print("\n" + "═" * 62)
    print("  🛡️  AUTOSEC OPENENV — LIVE WAR ROOM SIMULATION")
    print("      Blue Team (Defender) vs Red Team (Attacker)")
    print("═" * 62 + "\n")

    # Import the hybrid decision system from inference.py
    try:
        from inference import _smart_policy, _try_llm_action, LLM_CALL_INTERVAL
    except ImportError as e:
        print(f"❌ Could not import inference.py: {e}")
        sys.exit(1)

    # Reset environment
    print(f"[*] Initializing War Room: {task_id} | MaxSteps: {MAX_STEPS}")
    reset_resp = requests.post(
        f"{ENV_BASE_URL}/v1/reset",
        json={"task_id": task_id}
    ).json()

    obs_data = reset_resp.get("observation")
    if not obs_data:
        print(f"❌ Reset failed: {reset_resp}")
        sys.exit(1)

    obs  = Observation.model_validate(obs_data)
    done = False
    step = 0
    last_feedback  = ""
    action_history = []
    total_reward   = 0.0

    # ── Episode Loop ──────────────────────────────────────────────────────────
    while not done and step < MAX_STEPS:
        step += 1

        print(f"\n{'─' * 62}")
        print(f"  ROUND {step:02d}/{MAX_STEPS}  |  Active Threats: {obs.num_active_threats}  |  Impact: {obs.impact_score:.2f}")
        print(f"{'─' * 62}")

        # ── Red Team ─────────────────────────────────────────────────────────
        env_state      = requests.get(f"{ENV_BASE_URL}/v1/state").json()
        attacker_move  = env_state.get("last_attacker_action")

        if attacker_move:
            print(f"\n  🔴 RED TEAM MOVE")
            print(f"     Tactic  : {attacker_move.get('attack_type', 'UNKNOWN')}")
            print(f"     Target  : {attacker_move.get('target_host', '?')}")
            print(f"     Source  : {attacker_move.get('source_ip', '?')}")
        else:
            print(f"\n  🔴 RED TEAM  : Initializing reconnaissance...")

        # ── Log Stream ───────────────────────────────────────────────────────
        logs  = obs.logs
        stage = detect_stage(logs)
        print(f"\n  📊 LOG STREAM  — Kill Chain: {stage.value.upper()}")

        for log in logs[-6:]:  # Show last 6 logs
            sev    = str(log.severity).upper().split(".")[-1]
            icon   = SEVERITY_COLOR.get(sev, "⚪")
            flag   = "⚠ MALICIOUS" if log.is_malicious else "  benign "
            print(f"     {icon} {flag} | {str(log.event_type):<28} | src={log.source_ip or 'internal'}")

        # ── Blue Team Decision ────────────────────────────────────────────────
        print(f"\n  🔵 BLUE TEAM ANALYZING...")
        time.sleep(0.4)  # Dramatic pause

        use_llm = (step % LLM_CALL_INTERVAL == 0)
        source  = "POLICY"
        action_obj = None

        if use_llm:
            action_dict = _try_llm_action(obs, last_feedback, action_history)
            if action_dict:
                source     = "LLM 🧠"
                action_obj = Action.model_validate(action_dict)

        if action_obj is None:
            action_obj = _smart_policy(obs, action_history)
            source     = "POLICY ⚙️"

        action_dict = action_obj.model_dump()
        act_str     = str(action_obj.action_type).split(".")[-1].upper()
        action_history.append((act_str, action_obj.target))

        print(f"     Source    : {source}")
        print(f"     Decision  : {act_str}")
        print(f"     Target    : {action_obj.target}")
        print(f"     Reasoning : {action_obj.reasoning}")

        # ── Submit Action ─────────────────────────────────────────────────────
        step_resp = requests.post(
            f"{ENV_BASE_URL}/v1/step",
            json={"action": action_dict}
        )

        if step_resp.status_code != 200:
            print(f"\n❌ Server error {step_resp.status_code}: {step_resp.text}")
            break

        resp        = step_resp.json()
        reward_data = resp.get("reward", {})
        obs_data    = resp.get("observation")
        if not obs_data:
            print("❌ Missing observation in server response.")
            break

        obs           = Observation.model_validate(obs_data)
        done          = resp.get("done", False)
        last_feedback = reward_data.get("feedback", "")
        reward_val    = max(0.0, min(1.0, float(reward_data.get("value", 0.0))))
        total_reward += reward_val

        # ── Outcome ───────────────────────────────────────────────────────────
        bar_filled = int(reward_val * 20)
        bar        = "█" * bar_filled + "░" * (20 - bar_filled)
        print(f"\n  💰 OUTCOME")
        print(f"     Step Reward : [{bar}] {reward_val:.2f}")
        print(f"     Cumulative  : {total_reward:.2f}")
        print(f"     Feedback    : {last_feedback or 'Processed.'}")

        if done:
            print(f"\n  ✅ Environment signalled DONE at step {step}")

        # Save to memory
        log_text = "\n".join([str(l) for l in obs.logs])
        memory.save_experience(Experience(
            state_summary=log_text[:200],
            action=act_str,
            target=action_obj.target,
            reward=reward_val,
            feedback=last_feedback,
            reasoning=action_obj.reasoning,
            success=reward_val > 0.4,
            timestamp=datetime.now().isoformat(),
            kill_chain_stage=stage.value
        ))

        time.sleep(1.2)  # Pacing for readability

    # ── Final Result ──────────────────────────────────────────────────────────
    print(f"\n{'═' * 62}")
    print("  🏁  WAR ROOM CONCLUDED")
    print(f"{'═' * 62}")

    try:
        result      = requests.get(f"{ENV_BASE_URL}/v1/result").json()
        final_score = float(result.get("final_grader_score", 0.0))
        summary     = result.get("summary", "No summary.")
        total_steps = result.get("total_steps", step)

        print(f"  Final Score : {final_score:.4f}")
        print(f"  Total Steps : {total_steps}")
        print(f"  Summary     : {summary}")

        print()
        if final_score >= 0.80:
            print("  🏆  BLUE TEAM VICTORY — Network Secured!")
        elif final_score >= 0.50:
            print("  ⚠️   PARTIAL DEFENSE — Some threats neutralized.")
        else:
            print("  💀  RED TEAM BREACH — Defenses overwhelmed.")
    except Exception as e:
        print(f"  ⚠️  Could not fetch final result: {e}")

    print(f"\n  Avg Step Reward : {total_reward / max(step, 1):.3f}")
    print(f"{'═' * 62}\n")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="AutoSec War Room Demo")
    parser.add_argument(
        "--task",
        type=str,
        default="task_hard",
        choices=["task_easy", "task_medium", "task_hard"],
        help="Scenario to simulate"
    )
    args = parser.parse_args()
    run_war_room(args.task)
