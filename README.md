# 🛡️ AutoSec Defender: Autonomous SOC Defense Engine

AutoSec is a cutting-edge, autonomous Security Operations Center (SOC) designed to protect enterprise infrastructure from adaptive human and AI adversaries. It leverages a hierarchical decision-making framework combining **Deterministic Rules**, **Few-Shot Experience Memory**, and **LLM-based Tactical Reasoning**.

---

## 🚀 Key Features

### 🧠 The Defender Brain (Hybrid Tactical Engine)
The SOC doesn't just guess; it follows a high-performance decision tree:
1.  **Layer 1: Rule Engine**: Resolves "no-brainer" cases (e.g., immediate blocking of critical malicious IPs) to bypass latency.
2.  **Layer 2: Experience Memory**: Retrieval of past successful containment actions using a session-aware history filter (to prevent redundancy).
3.  **Layer 3: LLM Intelligence**: Powered by **Llama-3.3 (Groq)**, this layer handles complex lateral movement and multi-stage threats using asset-aware prioritization (e.g., protecting DC and Database servers first).

### 📦 Adversarial Simulation Environment
*   **Multi-Stage Attacker**: Simulates a realistic kill chain:
    *   **Reconnaissance**: Port scanning and service discovery.
    *   **Brute Force**: Authentication attacks on edge laptops and dev PCs.
    *   **Lateral Movement**: Targeted pivoting from compromised endpoints to high-value internal nodes.
*   **High-Fidelity Log Generator**: Produces realistic JSON security logs mapped to industry-standard severity levels.

### 📊 Live Monitoring Dashboard
*   **Real-Time Telemetry**: Visualization of `active_threats`, `compromise_levels`, and `isolated_hosts`.
*   **Session Tracking**: A running history of all defensive moves with a cumulative scoring engine.

---

## 🛠️ Technology Stack
*   **Core Logic**: Python 3.12+
*   **Web Framework**: FastAPI (Uvicorn)
*   **AI Integration**: OpenAI SDK (Groq-compatible)
*   **Frontend**: React (Vite)
*   **Environment**: Gymnasium-compatible RL wrapper
*   **Database/Memory**: JSON-based persistent experience memory

---

## ⚙️ Project Architecture

### 🛡️ Defensive Workflow
1.  **Ingestion**: Security logs pull in via the `/v1/state` or `real_world_bridge.py`.
2.  **Mapping**: Logs are mapped to kill chain stages (`detect_stage`).
3.  **Decision**: 
    *   **Redundancy Check**: Current session history is checked for existing blocks/isolations.
    *   **Heuristic Selection**: Actions targeting internal assets (DC, DB) get a **+10.0 score boost**.
4.  **Action**: The best action is executed via the environment's `step` function.

---

## 🔌 API Endpoints (v1)

| Endpoint | Method | Description |
| :--- | :--- | :--- |
| `/v1/reset` | `POST` | Resets the simulation to a clean state for a specific task. |
| `/v1/step` | `POST` | Executes a defender action (Block IP, Isolate Host, etc.) and returns the reward. |
| `/v1/state` | `GET` | Returns the current environmental state, including `system_state` and `logs`. |
| `/v1/result` | `GET` | Returns the final episode grade and summary. |

---

## 🎌 Installation & Setup

### 1. Requirements
Ensure you have Python 3.12 installed.
```powershell
python -m venv venv
.\venv\Scripts\activate
pip install -r requirements.txt
```

### 2. Configuration
Create a `.env` file in the root directory:
```bash
API_BASE_URL=https://api.groq.com/openai/v1
MODEL_NAME=llama-3.3-70b-versatile
OPENAI_API_KEY=your_groq_key_here
MAX_STEPS=20
```

### 3. Running the Simulation
**Terminal 1 (The API Server):**
```powershell
.\venv\Scripts\python.exe -m uvicorn api.server:app --host 0.0.0.0 --port 7860
```

**Terminal 2 (The War Room):**
```powershell
.\venv\Scripts\python.exe war_room.py --task task_02
```

---

## 📝 Recent Fixes (Stability Patch)
*   **CORS Fix**: Added CORSMiddleware to allow cross-origin requests from the React dashboard.
*   **JSON Extraction**: Implemented robust regex-based JSON parsing in `inference.py` to handle LLM conversational filler.
*   **History Synchronization**: Applied string-safe action history tracking to resolve the redundancy loop issue.
*   **Scoring Sync**: Restored `cumulative_score` tracking in the environment core.
