
import os
import time
from stable_baselines3 import PPO
from stable_baselines3.common.env_util import make_vec_env
from backend.rl.env_wrapper import AutoSecGymEnv

def debug_train():
    print("Debug Training Started...")
    env_id = lambda: AutoSecGymEnv(task_id="debug_01")
    vec_env = make_vec_env(env_id, n_envs=1)
    
    log_dir = "./logs/debug_rl/"
    os.makedirs(log_dir, exist_ok=True)
    
    model = PPO("MlpPolicy", vec_env, verbose=1)
    
    print("Testing set_threat_capacity method...")
    vec_env.env_method("set_threat_capacity", 1)
    
    print("Learning for 500 steps...")
    model.learn(total_timesteps=500)
    print("Debug Training Finished Successfully.")

if __name__ == "__main__":
    debug_train()
