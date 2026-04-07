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

from backend.rl.env_wrapper import AutoSecGymEnv

def train_agent(task_id: str = "task_easy", total_timesteps: int = 30000):
    """
    Trains a PPO agent on a mixture of SOC tasks for robust generalization.
    """
    if not HAS_RL:
        print("❌ Error: 'stable-baselines3' not found. Please install it to run RL training.")
        return

    print(f"[*] Starting Multi-Task Tactical Training for {total_timesteps} steps...")
    print(f"[*] Diversifying data: [1x Easy, 1x Medium, 2x Hard] parallel streams.")
    
    # 1. Create Vectorized Environment with Scenario Diversification
    from stable_baselines3.common.vec_env import DummyVecEnv

    def make_env_fn(t_id):
        return lambda: AutoSecGymEnv(task_id=t_id)

    # Strategic Mix: 1x Easy, 1x Medium, 2x Hard parallel streams
    tasks = ["task_easy", "task_medium", "task_hard", "task_hard"]
    env_fns = [make_env_fn(t) for t in tasks]
    env = DummyVecEnv(env_fns)
    
    # 2. Initialize PPO Model
    model = PPO(
        "MlpPolicy", 
        env, 
        verbose=1, 
        learning_rate=2e-4, 
        n_steps=1024,
        batch_size=128,
        gamma=0.99
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
