\
\
\
\
\
   

from fastapi import FastAPI, HTTPException, Body
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import Dict, Any, Optional

from autosec_openenv.env import SimulationEnvironment
from autosec_openenv.models import Action

app = FastAPI(title="AutoSec OpenEnv API")

                            
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],                            
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

                                
_env: Optional[SimulationEnvironment] = None

class ResetRequest(BaseModel):
    task_id: str = "task_01"
    mode: str = "eval"

@app.get("/")
async def root():
    return {"message": "AutoSec OpenEnv Simulation API is active."}

@app.post("/v1/reset")
async def reset(req: ResetRequest = Body(...)):
                                           
    global _env
    _env = SimulationEnvironment(task_id=req.task_id)
    obs, info = _env.reset()
    return {
        "observation": obs.model_dump(),
        "info": info
    }

@app.post("/v1/step")
async def step(payload: Dict[str, Any] = Body(...)):
                                                       
    global _env
    if _env is None:
        raise HTTPException(status_code=400, detail="Environment not initialized. Call /v1/reset first.")
    
    try:
        action_data = payload.get("action")
        if not action_data:
            raise HTTPException(status_code=400, detail="Missing 'action' in payload.")
            
        action = Action(**action_data)
        obs, reward_obj, done, info = _env.step(action)
        
        return {
            "observation": obs.model_dump(),
            "reward": reward_obj.model_dump(),
            "done": done,
            "info": info
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Step failed: {str(e)}")

@app.get("/v1/state")
async def get_state():
                                                                
    global _env
    if _env is None:
        return {"status": "INACTIVE"}
    
                                                                   
    return {
        "system_state": _env.state(),
        "logs": [log.model_dump() for log in _env.logs[-10:]],                 
        "last_attacker_action": _env.last_attacker_action,
        "step_id": _env.step_id
    }

@app.get("/v1/result")
async def get_result():
                                  
    global _env
    if _env is None:
        raise HTTPException(status_code=400, detail="No result available. Call /v1/reset first.")
    
    result = _env.get_result()
    return result.model_dump()

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=7860)
