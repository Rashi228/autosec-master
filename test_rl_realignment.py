
import numpy as np
from backend.rl.env_wrapper import AutoSecGymEnv

def test_obs():
    print("Testing AutoSecGymEnv Observation Vector...")
    env = AutoSecGymEnv(task_id="test_obs")
    obs, _ = env.reset()
    
    print(f"Observation Shape: {obs.shape}")
    print(f"Observation Vector: {obs}")
    
    assert obs.shape == (15,), f"Expected shape (15,), got {obs.shape}"
    # Index 0: Compromise (0)
    # Index 1: Threats (0)
    # Index 2: Step (0)
    # Index 3-7: Hosts (0)
    # Index 8: Attacker IP (0)
    # Index 9-13: Isolation (0)
    # Index 14: Log Malicious (0)
    
    # Simulate a step with an action to see if it changes
    obs, reward, done, _, _ = env.step([0, 0, 0]) # NO_ACTION
    print(f"Post-Step Obs: {obs}")
    print(f"Post-Step Reward: {reward}")

if __name__ == "__main__":
    try:
        test_obs()
        print("✅ Observation Verification Passed.")
    except Exception as e:
        print(f"❌ Observation Verification Failed: {e}")
