\
\
\
\
   

import time
from stable_baselines3 import PPO
from backend.rl.env_wrapper import AutoSecGymEnv

def run_inference():
    print("Loading RL Environment...")
    env = AutoSecGymEnv(task_id="inference_01")
    
    try:
        model = PPO.load("./logs/rl_training/autosec_ppo_final")
        print("✅ RL Model loaded successfully.")
    except Exception as e:
        print("⚠️ Could not load trained model. Ensure train_rl.py has completed.")
        print(f"Error: {e}")
        return

    obs, info = env.reset()
    done = False
    step = 0
    
    print("\n--- Starting Adaptive RL Simulation ---")
    
    while not done and step < 20:
        action, _states = model.predict(obs, deterministic=True)
        obs, reward, done, truncated, info = env.step(action)
        step += 1
        
                                       
        state = env.sim.state
        print(f"[{step}] Reward: {reward:+.2f} | Threats: {state.active_threats} | Compromise: {state.compromise_level:.1f}%")
        time.sleep(0.5)

    print("\n--- Simulation Complete ---")
    if env.sim.state.active_threats == 0:
        print("🟢 SUCCESS: RL Agent resolved all threats!")
    else:
        print("🔴 FAILURE: RL Agent could not resolve all threats in time.")

if __name__ == "__main__":
    run_inference()
