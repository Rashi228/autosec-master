"""
train_soc.py — Reinforcement Learning Training Suite
=====================================================
Trains a PPO policy to act as a 'No-Brainer' tactical 
response layer for the AutoSec SOC.
"""

import os
import argparse
from typing import Optional

# Conditional import as Stable Baselines is optional for LLM-only mode
try:
    from stable_baselines3 import PPO
    from stable_baselines3.common.env_util import make_vec_env
    HAS_RL = True
except ImportError:
    HAS_RL = False

from autosec_openenv.gym_wrapper import make_env

def train_agent(task_id: str = "task_01", total_timesteps: int = 20000):
    """
    Trains a PPO agent on the specified SOC task.
    """
    if not HAS_RL:
        print("❌ Error: 'stable-baselines3' not found. Please install it to run RL training.")
        return

    print(f"[*] Training PPO SOC Agent on {task_id} for {total_timesteps} steps...")
    
    # 1. Create Vectorized Environment
    env = make_vec_env(lambda: make_env(task_id), n_envs=4)
    
    # 2. Initialize PPO Model
    model = PPO(
        "MlpPolicy", 
        env, 
        verbose=1, 
        learning_rate=3e-4, 
        n_steps=512,
        batch_size=64,
        tensorboard_log="./soc_training_logs/"
    )
    
    # 3. Train
    model.learn(total_timesteps=total_timesteps)
    
    # 4. Save Model
    model_path = f"models/soc_agent_{task_id}.zip"
    os.makedirs("models", exist_ok=True)
    model.save(model_path)
    
    print(f"✅ Training Complete. Model saved to {model_path}.")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="AutoSec RL Training Script")
    parser.add_argument("--task", type=str, default="task_01", help="The task ID for training.")
    parser.add_argument("--steps", type=int, default=10000, help="Total training timesteps.")
    args = parser.parse_args()
    
    train_agent(task_id=args.task, total_timesteps=args.steps)
