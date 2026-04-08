
import numpy as np
from backend.rl.env_wrapper import AutoSecGymEnv

def test_obs():
    print("Testing AutoSecGymEnv Observation Vector...")
    env = AutoSecGymEnv(task_id="test_obs")
    obs, _ = env.reset()
    
    print(f"Observation Shape: {obs.shape}")
    print(f"Observation Vector: {obs}")
    
    assert obs.shape == (15,), f"Expected shape (15,), got {obs.shape}"
                             
                          
                       
                          
                              
                               
                                 
    
                                                         
    obs, reward, done, _, _ = env.step([0, 0, 0])            
    print(f"Post-Step Obs: {obs}")
    print(f"Post-Step Reward: {reward}")

if __name__ == "__main__":
    try:
        test_obs()
        print("✅ Observation Verification Passed.")
    except Exception as e:
        print(f"❌ Observation Verification Failed: {e}")
