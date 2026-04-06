"""
war_room.py — Interactive SOC Dashboard
========================================
Runs a live 'War Room' demo of the SOC in action.
Shows the Red Team (Attacker) movements vs. Blue Team (Defender) 
decisions in real-time.
"""

import os
import sys
import time
import requests
import argparse
from datetime import datetime
from dotenv import load_dotenv

from autosec_openenv.models import Action, ActionType, SecurityLog, Observation, SystemState
from autosec_openenv.memory import ExperienceMemory, Experience
from autosec_openenv.kill_chain import detect_stage

# Load environment variables
load_dotenv()

# Configuration
ENV_BASE_URL = os.getenv("ENV_BASE_URL", "http://localhost:7860")
memory = ExperienceMemory()

def run_war_room(task_id: str):
    print("\n" + "🔥" * 30)
    print("      AUTOSEC OPENENV — LIVE WAR ROOM")
    print("      Defender (Blue) vs. Adaptive Attacker (Red)")
    print("🔥" * 30 + "\n")

    # 1. Reset Environment in 'war_room' mode
    print(f"[*] Initializing War Room for {task_id}...")
    try:
        from inference import _llm_action
    except ImportError:
        print("❌ CRITICAL: Could not find 'inference.py'. Make sure it is in the root directory.")
        sys.exit(1)

    reset_resp = requests.post(f"{ENV_BASE_URL}/v1/reset", json={"task_id": task_id, "mode": "war_room"}).json()
    obs = reset_resp["observation"]
    done = obs.get("done", False)
    
    step = 0
    last_feedback = ""

    while not done:
        step += 1
        print(f"\n{'='*60}")
        print(f" ROUND {step}")
        print(f"{'='*60}")

        # --- Attacker's Turn (Happened in previous env.step or reset) ---
        env_state = requests.get(f"{ENV_BASE_URL}/v1/state").json()
        attacker_move = env_state.get("last_attacker_action")
        
        if attacker_move:
            print(f"\n🔴 [RED TEAM MOVE]")
            print(f"   Action: {attacker_move.get('attack_type'):20s} | Target: {attacker_move.get('target_host')}")
            print(f"   Source: {attacker_move.get('source_ip')}")
            print(f"   Reasoning: {attacker_move.get('reasoning')}")
        else:
            print(f"\n🔴 [RED TEAM] Initializing reconnaissance...")

        # --- Logs Created by Attacker ---
        logs = obs.get("logs", [])
        stage = detect_stage(logs)
        
        print(f"\n📊 [LOG STREAM] — Stage: {stage.value.upper()}")
        for log in logs:
            severity = f"[{log.get('severity')}]"
            print(f"   {severity:10s} {log.get('event_type'):30s} src={log.get('source_ip') or 'internal'}")

        print(f"\n🔵 [BLUE TEAM ANALYZING...]")
        action = _llm_action(obs, last_feedback)
        
        icon = "🧠 [MEMORY HIT]" if "Memory" in action.get("reasoning", "") else "🤖 [LLM REASONING]"
        # Add to history (standardized as strings) for subsequent rounds
        act_type_str = str(action["action_type"]).split('.')[-1].upper()
        action_history.append((act_type_str, action["target"]))
        print(f"   {icon}")
        print(f"   Action: {action['action_type']:20s} | Target: {action['target']}")
        print(f"   Reasoning: {action['reasoning']}")

        # --- Submit Action ---
        step_resp_raw = requests.post(f"{ENV_BASE_URL}/v1/step", json={"action": action})
        if step_resp_raw.status_code != 200:
            print(f"\n❌ SERVER ERROR DURING STEP: {step_resp_raw.status_code}")
            try:
                print(f"   Detail: {step_resp_raw.json().get('detail')}")
            except:
                print(f"   Response: {step_resp_raw.text}")
            sys.exit(1)
            
        step_resp = step_resp_raw.json()
        reward = step_resp["reward"]
        obs = step_resp["observation"]
        done = reward.get("done", False)
        last_feedback = reward.get("feedback", "")
        
        # 💾 SAVE TO MEMORY (New!)
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

        print(f"\n💰 [OUTCOME]")
        score = reward.get('score') or 0.0
        cum_score = reward.get('cumulative_score') or 0.0
        print(f"   Score: {score:.3f} | Total: {cum_score:.3f}")
        print(f"   Feedback: {reward.get('feedback') or 'Processed.'}")
        
        time.sleep(2) # Slow down for demo impact

    # --- Final Result ---
    result = requests.get(f"{ENV_BASE_URL}/v1/result").json()
    print("\n" + "🏁" * 30)
    print("      WAR ROOM CONCLUDED")
    print("🏁" * 30)
    print(f"   Final Result: {result.get('summary')}")
    print(f"   Total Steps:  {result.get('total_steps')}")
    print(f"   Safety Score: {result.get('final_grader_score'):.4f}")
    
    if result.get('final_grader_score') > 0.7:
        print("\n🏆 BLUE TEAM (DEFENDER) VICTORIOUS")
    else:
        print("\n💀 RED TEAM (ATTACKER) BREACHED DEFENSES")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="AutoSec War Room Demo")
    parser.add_argument("--task", type=str, default="task_02", help="The task ID to run (task_01, task_02, task_03)")
    args = parser.parse_args()
    
    run_war_room(args.task)
