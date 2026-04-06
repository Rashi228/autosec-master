"""
train_rl.py — Train PPO Agent for AutoSec
=========================================
Training script using Stable-Baselines3 to train an RL SOC agent.
"""

import os
import time
from stable_baselines3 import PPO
from stable_baselines3.common.env_util import make_vec_env
from stable_baselines3.common.callbacks import EvalCallback
from backend.rl.env_wrapper import AutoSecGymEnv

def main():
    print("Initializing AutoSec RL Training Environment...")
    env_id = lambda: AutoSecGymEnv(task_id="train_01")
    
    # Vectorized environment for faster execution (using 4 parallel envs)
    vec_env = make_vec_env(env_id, n_envs=4)
    
    # Eval environment
    eval_env = AutoSecGymEnv(task_id="eval_01")
    
    # Setup Checkpointing & Logs
    log_dir = "./logs/rl_training/"
    os.makedirs(log_dir, exist_ok=True)
    
    eval_callback = EvalCallback(
        eval_env, 
        best_model_save_path=log_dir,
        log_path=log_dir, 
        eval_freq=500,
        deterministic=True, 
        render=False
    )
    
    # Initialize PPO Agent
    model = PPO("MlpPolicy", vec_env, verbose=1, tensorboard_log=log_dir)
    
    print("Starting PPO Training for 5,000 steps...")
    start_time = time.time()
    
    model.learn(total_timesteps=5000, callback=eval_callback)
    
    end_time = time.time()
    print(f"Training completed in {end_time - start_time:.2f} seconds.")
    
    # Save the final model
    model.save(f"{log_dir}/autosec_ppo_final")

if __name__ == "__main__":
    main()
