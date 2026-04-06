# 🛡️ AutoSec RL Agent: Self-Improving Autonomous SOC

AutoSec RL is a next-generation, **self-teaching cybersecurity defense agent** powered by Reinforcement Learning (PPO). It transforms traditional rule-based SOC automation into a proactive, adaptive defensive brain that learns from experience and evaluates its own actions through multi-persona reasoning.

---

## 🚀 Key Features

### 🧠 RL-Powered Defensive Brain
- **Gymnasium Core**: Wraps the security simulation into a standard RL environment for modular training.
- **PPO Strategy**: Uses Proximal Policy Optimization to discover optimal containment strategies for complex multi-stage attacks.
- **Curriculum Learning**: Automatically scales environment difficulty (noise, attacker speed) based on the agent's real-time success rate.

### 💾 Semantic Experience Memory (Vector DB)
- **ChromaDB Integration**: Replaces static history with a high-performance vector store.
- **Embedding-Based Retrieval**: Uses `sentence-transformers` for semantic similarity searches, allowing the agent to correlate current snapshots with successful past mitigations.

### 🎭 Multi-Persona Explainability
- Actions are independently evaluated by three distinct SOC personas:
  1. **SOC Analyst**: Focuses on triage speed and active threat resolution.
  2. **Threat Hunter**: Evaluates log correlation and precision.
  3. **Incident Responder**: Focuses on containment correctness and blast-radius reduction.

### 📉 Adaptive Adversarial Attacker
- A learner-aware attacker that tracks agent failure points and dynamically shifts its attack vectors (Recon -> Brute Force -> Lateral Movement) to exploit vulnerabilities.

---

## 🛠️ Technology Stack
- **RL Framework**: Gymnasium, Stable-Baselines3
- **Intelligence**: PyTorch (PPO), ChromaDB (Vector DB)
- **Backend**: FastAPI (Python 3.12+)
- **Frontend**: React + Vite (Telemetry Dashboard)
- **Personas**: Rule-based & LLM-augmented explainability Traces

---

## ⚙️ Running the System

### 1. Pre-requisites
```powershell
python -m venv venv
.\venv\Scripts\activate
pip install -r requirements.txt
```

### 2. Autonomous RL Server
Start the RL-integrated backend to handle autonomous defender steps:
```powershell
$env:PYTHONPATH="."
.\venv\Scripts\python.exe backend\api\server_rl.py
```

### 3. Dashboard UI
Launch the telemetry dashboard to visualize the agent's reasoning traces:
```powershell
cd dashboard
npm install
npm run dev
```

---

## 📝 Training the Agent
To run a fresh reinforcement learning training cycle:
```powershell
$env:PYTHONPATH="."
.\venv\Scripts\python.exe backend\rl\train_rl.py
```
Training logs and model checkpoints are stored in `./logs/rl_training/`.

---

## ✅ Recent RL Upgrades
- **Pydantic Enum Alignment**: Synchronized the environment's internal strings with API schemas to resolve dashboard stalls.
- **Autonomous Step Polling**: Integrated the dashboard with the `/v1/step` autonomous endpoint.
- **Hierarchical Actions**: Refactored the action space to support [Strategy, Tactic, Target] decision layers.
