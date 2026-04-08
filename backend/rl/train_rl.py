\
\
\
\
   

import os
import time
from stable_baselines3 import PPO
from stable_baselines3.common.env_util import make_vec_env
from stable_baselines3.common.callbacks import EvalCallback
from backend.rl.env_wrapper import AutoSecGymEnv

def main():
    print("Initializing AutoSec RL Training Environment...")
    env_id = lambda: AutoSecGymEnv(task_id="train_01")
    
                                                                         
    vec_env = make_vec_env(env_id, n_envs=4)
    
                      
    eval_env = AutoSecGymEnv(task_id="eval_01")
    
                                
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
    
                                                                                   
    model = PPO("MlpPolicy", vec_env, verbose=1, 
                learning_rate=0.00005, ent_coef=0.1, gamma=0.99,
                tensorboard_log=log_dir)
    
    print("Starting PPO Training for 200,000 steps (Curriculum Enabled)...")
    start_time = time.time()
    
                                                                            
    print("[CURRICULUM] Phase 1: Target Discovery (Threats limited to 1)")
    vec_env.env_method("set_threat_capacity", 1)
    model.learn(total_timesteps=40000, callback=eval_callback)
    
                                    
    print("[CURRICULUM] Phase 2: Multi-Threat Defense (Full Capacity)")
    vec_env.env_method("set_threat_capacity", 3)
    model.learn(total_timesteps=160000, callback=eval_callback)
    
    end_time = time.time()
    print(f"Training completed in {end_time - start_time:.2f} seconds.")
    
                          
    model.save(f"{log_dir}/autosec_ppo_final")

if __name__ == "__main__":
    main()
