"""
war_room_rl.py — High-Fidelity RL Simulation CLI
================================================
A detailed CLI view of the RL agent's defensive actions, 
showing attacker moves, logs, and agent reasoning.
"""

import time
import os
import sys
from stable_baselines3 import PPO
from backend.rl.env_wrapper import AutoSecGymEnv, STRATEGIES, TACTICS, COMMON_TARGETS

def run_rl_war_room():
    print("\n" + "🛡️ " * 30)
    print("      AUTOSEC RL — AUTONOMOUS WAR ROOM")
    print("      RL Defender (PPO) vs. Adaptive Attacker")
    print("🛡️ " * 30 + "\n")

    print("[*] Initializing Environment...")
    env = AutoSecGymEnv(task_id="war_room_rl_01")
    
    try:
        model = PPO.load("./logs/rl_training/autosec_ppo_final")
        print("✅ RL Brain loaded. Ready for combat.")
    except Exception as e:
        print(f"❌ Error loading RL model: {e}")
        return

    obs, info = env.reset()
    done = False
    step = 0
    total_reward = 0.0

    while not done and step < 20:
        step += 1
        print(f"\n{'-'*60}")
        print(f" ROUND {step}")
        print(f"{'-'*60}")

        # --- Show Attacker Move (from the simulator state) ---
        sim = env.sim
        attacker_action = sim.last_attacker_action
        if attacker_action:
            print(f"\n🔴 [RED TEAM MOVE]")
            print(f"   Action: {attacker_action.get('attack_type'):20s} | Target: {attacker_action.get('target_host')}")
            print(f"   Reasoning: {attacker_action.get('reasoning')}")
        
        # --- Show Recent Logs ---
        print(f"\n📊 [LOG STREAM]")
        logs = sim.logs[-3:]
        for log in logs:
            mark = "🚨" if log.is_malicious else "🔍"
            print(f"   {mark} [{log.severity}] {log.event_type:25s} src={log.source_ip or 'internal'}")

        # --- RL Agent Decision ---
        print(f"\n🔵 [BLUE TEAM (RL) THINKING...]")
        action_multi, _ = model.predict(obs, deterministic=True)
        s_idx, t_idx, trg_idx = action_multi
        
        print(f"   Strategy: {STRATEGIES[s_idx]}")
        print(f"   Tactic:   {TACTICS[t_idx]}")
        print(f"   Target:   {COMMON_TARGETS[trg_idx]}")

        # --- Execute Step ---
        obs, reward, done, truncated, info = env.step(action_multi)
        total_reward += reward

        print(f"\n💰 [OUTCOME]")
        print(f"   Step Reward: {reward:+.2f} | Cumulative: {total_reward:+.2f}")
        print(f"   Current Threats: {sim.state.active_threats} | Compromise: {sim.state.compromise_level:.1f}%")
        
        time.sleep(1.5)

    print("\n" + "🏁" * 30)
    print("      WAR ROOM CONCLUDED")
    print("🏁" * 30)
    if env.sim.state.active_threats == 0:
        print("🏆 VICTORIOUS: RL Agent protected the assets and cleared all threats.")
    else:
        print("💀 DEFEATED: Attacker survived. The environment requires more training.")

if __name__ == "__main__":
    run_rl_war_room()
