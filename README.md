# 🛡️ AutoSec RL Agent: Autonomous SOC Intelligence

> A production-ready, OpenEnv-compliant autonomous Security Operations Center agent combining **Reinforcement Learning**, **Hybrid LLM reasoning**, and **multi-persona evaluation**. Built for reproducible, credit-efficient, crash-free evaluation.

---

## 🎯 What Is AutoSec?

AutoSec is a **self-teaching SOC agent** that simulates realistic enterprise network attacks and autonomously learns to defend against them using a two-layer hybrid intelligence system:

- **Smart Deterministic Policy** — always runs, never fails, severity-prioritized
- **LLM Enhancement** — selectively called every N steps for novel threat reasoning
- **Multi-Persona Grading** — Analyst, Hunter, Responder perspectives
- **Semantic Vector Memory** — episode experience retrieval via ChromaDB
- **Curriculum Learning** — auto-scales difficulty based on performance
- **Dense Reward Shaping** — 8 signals driving intelligent, non-redundant behavior

---

## 🏗️ Architecture Overview

```
┌──────────────────────────────────────────────────────────────────┐
│                        inference.py                              │
│        Hybrid Defender Brain                                     │
│   ┌─────────────────────┐   ┌──────────────────────────────┐    │
│   │  Smart Policy        │   │  LLM (every N steps)         │    │
│   │  Severity-ordered   │   │  Llama 3.1 8B via HF         │    │
│   │  Always succeeds    │   │  Fails gracefully → POLICY   │    │
│   └─────────────────────┘   └──────────────────────────────┘    │
│              │                          │                        │
│              └──────────┬───────────────┘                        │
│                         ▼                                        │
│              [TELEMETRY] block logged at episode end             │
└────────────────────────┬─────────────────────────────────────────┘
                         │ REST API (OpenEnv Spec)
                         ▼
┌──────────────────────────────────────────────────────────────────┐
│              backend/api/server_rl.py (FastAPI)                  │
│   POST /v1/reset   POST /v1/step   GET /v1/state   GET /v1/result│
│                                                                  │
│   ┌───────────────────┐   ┌────────────────────────────┐        │
│   │ CurriculumScheduler│   │ MultiPersonaEvaluator       │        │
│   │ BASIC→ADVANCED    │   │ Analyst / Hunter / Responder│        │
│   └───────────────────┘   └────────────────────────────┘        │
│                                                                  │
│   ┌──────────────────────────────────────────────────────┐      │
│   │  AutoSecGymEnv (Gymnasium)                            │      │
│   │  Pilot Mode (LLM action) ↔ Autonomous Mode (PPO)     │      │
│   │  _seen_action_targets: novelty tracker per episode    │      │
│   └──────────────────────────────┬───────────────────────┘      │
│                                  │                               │
│   ┌──────────────────────────────▼───────────────────────┐      │
│   │  SimulationEnvironment (env.py)                       │      │
│   │  Attacker Engine → LogGenerator → SystemState         │      │
│   │  SOCGrader → EpisodeResult (bounded [0.0, 1.0])       │      │
│   └───────────────────────────────────────────────────────┘     │
│                                                                  │
│   ┌──────────────────────────────────────┐                      │
│   │   ExperienceMemory (500-cap JSON)     │                      │
│   │   VectorMemory (ChromaDB)             │                      │
│   └──────────────────────────────────────┘                      │
└──────────────────────────────────────────────────────────────────┘
                         │
                         ▼
┌──────────────────────────────────────────────────────────────────┐
│              dashboard/ (React 18 + Vite)                        │
│   Live telemetry · persona traces · action history               │
│   [NEW] Auto-Pilot Toggle · Task Selector · Result Modal         │
└──────────────────────────────────────────────────────────────────┘
```

---

## 🚀 Feature Deep-Dive

### 1. 🧠 Hybrid Intelligence System (inference.py)

The core decision engine uses a **two-layer hybrid architecture** that guarantees every episode completes regardless of LLM availability:

#### Layer 1 — Smart Deterministic Policy (every step)
A priority-ordered, state-aware policy that runs on all steps:

| Priority | Action | Condition |
|---|---|---|
| 1 | `BLOCK_IP` | Novel external attacker IP, sorted by severity (CRITICAL first) |
| 2 | `ISOLATE_HOST` | Critical infrastructure hosts (`dc-01`, `db-server-01`, `web-prod-01`) |
| 3 | `ISOLATE_HOST` | Any remaining compromised host not yet isolated |
| 4 | `TERMINATE_PROCESS` | Hosts already isolated or all others exhausted |
| 5 | `MONITOR` | No active threats, or all known threats handled |

- Maintains a **session history set** — never repeats the same `(action, target)` pair
- Reads live `blocked_ips` and `isolated_hosts` from current observation state
- Severity sorted using `CRITICAL(4) > HIGH(3) > MEDIUM(2) > LOW(1)`

#### Layer 2 — LLM Enhancement (every `LLM_INTERVAL` steps)
- Called every N steps (default: 3) to reason about novel or complex scenarios
- **Token-efficient prompt** (256 tokens max) to conserve API credits
- **Intelligent redirect**: if LLM suggests re-blocking an already-blocked IP, automatically redirects to `ISOLATE_HOST` of the associated hostname instead of discarding
- **Graceful degradation**: on any LLM failure (credits exhausted, network, invalid JSON), seamlessly falls back to smart policy — episode never crashes

#### Evaluation Modes
| Mode | `ALLOW_FALLBACK` | Behavior on LLM failure |
|---|---|---|
| **Dev** (default) | `true` | Smart policy takes over silently |
| **Strict Eval** | `false` | Episode terminates cleanly, score = 0.0, marked `aborted: true` |

---

### 2. 🌐 OpenEnv Compliant API (server_rl.py)

All endpoints strictly follow the OpenEnv specification:

| Endpoint | Method | Description |
|---|---|---|
| `/v1/reset` | POST | Resets simulation with `task_id` + `seed`; returns `Observation` |
| `/v1/step` | POST | Executes action (Pilot Mode OR PPO autonomous); returns step result |
| `/v1/state` | GET | Live system state + RL telemetry |
| `/v1/result` | GET | Persona-weighted `EpisodeResult` with bounded score |

**Pilot Mode** — if the POST `/v1/step` payload contains an `action`, it executes that action directly in the simulation (LLM/external control). Otherwise, the loaded PPO model infers the action autonomously.

---

### 3. 🎭 Three Structurally Distinct Scenarios

| Task | Scenario | Unique Structural Feature |
|---|---|---|
| `task_easy` | Single brute-force attacker | Clean signal, 1 attacker |
| `task_medium` | Lateral movement chain | **Delayed logs** — indicators appear 1 step after event |
| `task_hard` | Multi-stage APT | **50% stealth moves** (no log) + noisy benign traffic |

---

### 4. 📊 Dense Reward Engine (reward_engine.py)

8 layered reward signals, all clipped to `[0.0, 1.0]` per OpenEnv spec:

| Signal | Amount | Condition |
|---|---|---|
| Correct Target | `+0.20` | Action targets confirmed malicious host/IP |
| Strategic Alignment | `+0.10` | Action matches declared strategy |
| Threat Resolution | `+0.30` | Active threat count decreased |
| Terminal Success | `+0.40` | All threats cleared at episode end |
| Novel Action Bonus | `+0.05` | First time this `(action, target)` used this episode |
| Efficiency Penalty | `-0.05` | Applied every step (drives speed) |
| Redundancy Penalty | `-0.15` | Same action repeated on same target consecutively |
| Invalid Target | `-0.20` | `BLOCK_IP` with empty/`none` target |

---

### 5. ⚖️ Hardened Scoring (graders.py)

The `SOCGrader` provides a crash-proof, bounded scoring pipeline:

```
base_score   = (threats_resolved / threats_total) - (errors × 0.02)
final_score  = (base_score × 0.70) + (persona_score × 0.30)
output       = max(0.0, min(1.0, final_score))
```

Key hardening:
- `threats_total` always `≥ 1` (safe division, no `ZeroDivisionError`)
- `threats_resolved` clamped to `≤ threats_total` (no overflow)
- **Error penalty is `0.02` per error** (was `0.05`) — prevents minor errors from collapsing an otherwise correct episode
- **Only genuine wrong-target actions count as errors** — redundant actions (re-block) are penalized by reward engine only, not the grader
- `TERMINATE_PROCESS` on a malicious hostname now correctly counts as a resolution
- Persona evaluation wrapped in `try/except` — failure never breaks grading
- All inputs validated defensively (`int(...) or 0`, `float(...) or 0.0`)

---

### 6. 🎭 Three-Persona Evaluation (personas.py)

Every action is evaluated by three independent SOC expert perspectives:

| Persona | Weight | Focus |
|---|---|---|
| **SOC Analyst** | 30% | Alert triage speed, active threat resolution rate |
| **Threat Hunter** | 30% | Log correlation, attacker IP precision |
| **Incident Responder** | 40% | Containment correctness, blast-radius minimization |

---

### 7. 💾 Smart Experience Memory

**JSON Buffer** (`experience_memory.json`):
- 500-experience capacity (expanded from 100)
- Smart eviction: keeps top-300 by reward + 100 most recent
- Deduplication by `(action, target, kill_chain_stage)`
- Used by inference for fast-path pattern matching

**ChromaDB Vector Memory**:
- Semantic experience retrieval during server-side inference
- Lazy-loaded at first use (fast startup)

---

### 8. 📈 Curriculum Learning (scheduler.py)

| Level | Hosts | Noise | Max Active Threats | Promotion Threshold |
|---|---|---|---|---|
| BASIC | 3 | 10% | 1 | 85% success / 20 episodes |
| INTERMEDIATE | 10 | 50% | 3 | 85% success / 20 episodes |
| ADVANCED | 50 | 90% | 5 | — |

---

---

### 9. 🖥️ Professional SOC Dashboard (dashboard/)

The React-based dashboard has been transformed into a robust, multi-mode evaluation center:

#### 🎮 Dual-Control Modes
| Mode | Toggle | Description |
|---|---|---|
| **Auto-Pilot** | **ON** | **Active Driver**: The dashboard automatically triggers `step()` every 1.5s using the RL/LLM brain. |
| **Manual Mode** | **OFF** | **Passive Observer**: Dashboard only polls for state. Use this when running `inference.py` in a terminal to watch live telemetry without control conflicts. |

#### 🛠️ Dynamic Scenario Selection
- **Task Selector**: Choose between **L1 (Easy)**, **L2 (Medium)**, or **L3 (Hard)** directly from the UI dropdown.
- **Auto-Sync**: The dashboard automatically detects if the environment was reset via CLI or API and updates its scenario label to match.

#### 📊 Advanced Telemetry & Feedback
- **Step Counter**: Real-time progress tracking (e.g., `Step 5 / 15`).
- **Resolved vs. Total**: Displays specific threat neutralization counts.
- **Expanded SIEM**: History window increased to the last **20 logs** for better incident investigation.
- **Episode Conclusion Modal**: A premium overlay appearing at `done: true` that displays:
    - Final Grader Score (%)
    - Categorized Threat Resolution counts
    - Three-Persona score breakdown (Analyst, Hunter, Responder)

---

### 10. 📋 Reproducibility Design

Every component is deterministically seeded:

| Parameter | Value | Effect |
|---|---|---|
| `RANDOM_SEED=42` | `random.seed(42)` | Attacker IP/host selection identical across runs |
| `TEMPERATURE=0.0` | LLM param | Deterministic LLM token selection |
| `TOP_P=1.0` | LLM param | No nucleus sampling variation |
| `MAX_STEPS=15` | Loop cap | Episode always terminates in exactly ≤15 steps |
| `MAX_TOKENS=256` | LLM param | Consistent, credit-efficient responses |
| Fixed `task_id` from client | Reset param | Same scenario every run |

---

### 11. 📡 Evaluation Telemetry

Every episode ends with a structured `[TELEMETRY]` block (in CLI) and a **Result Modal** (in Dashboard):

```
[TELEMETRY] TotalSteps=15 | LLM_Calls=5 | LLM_OK=4 (80.0%) | LLM_Fail=1 |
            PolicySteps=12 | Fallbacks=1 at steps [9] | AvgReward=0.334 | MaxReward=0.450
```

This enables **evaluation transparency** — every run is auditable:
- How often LLM was used vs policy
- Exactly which steps triggered LLM failure/fallback
- Average and peak reward distribution
- Persona-based performance trends

---

## 🛠️ Technology Stack

| Layer | Technology | Purpose |
|---|---|---|
| **Hybrid AI** | Smart Policy + LLM (Llama 3.1 8B) | Two-layer decision making |
| **LLM Router** | Hugging Face Inference Router | Credit-efficient LLM hosting |
| **RL Framework** | Gymnasium + Stable-Baselines3 PPO | Policy training + env interface |
| **Backend API** | FastAPI + Uvicorn | OpenEnv compliant REST server |
| **Semantic Memory** | ChromaDB + sentence-transformers | Experience retrieval |
| **JSON Memory** | Python JSON | Lightweight inference-time replay |
| **Data Models** | Pydantic v2 | Type-safe contracts, safe deserialization |
| **Frontend** | React 18 + Vite | Live telemetry dashboard |
| **Containerization** | Docker + docker-compose | Reproducible deployment |

---

## ⚙️ Setup & Configuration

### Prerequisites

```powershell
python -m venv venv
.\venv\Scripts\activate
pip install -r requirements.txt
```

### `.env` Configuration

Create `.env` in the project root:

```env
# LLM Provider (Hugging Face — lightweight, cost-efficient)
OPENAI_API_KEY=hf_YOUR_TOKEN_HERE
MODEL_NAME=meta-llama/Llama-3.1-8B-Instruct
API_BASE_URL=https://router.huggingface.co/v1

# Simulation Server
ENV_BASE_URL=http://localhost:7860

# Episode Constraints (deterministic & credit-safe)
MAX_STEPS=15
MAX_TOKENS=256
TEMPERATURE=0.0
TOP_P=1.0

# Hybrid Policy: LLM called every N steps (rest = smart policy)
LLM_INTERVAL=3

# Reproducibility
RANDOM_SEED=42

# Evaluation mode: true=dev (fallback allowed), false=strict (abort on LLM fail)
ALLOW_FALLBACK=true
```

---

## 🚦 Running the System

### Step 1 — Start the Adaptive RL Server

```powershell
$env:PYTHONPATH="."; .\venv\Scripts\python.exe backend\api\server_rl.py
```

Server starts at `http://localhost:7860`. Expected output:
```
INFO: Application startup complete.
INFO: Uvicorn running on http://0.0.0.0:7860
```

### Step 2 — Run the Hybrid Inference Agent

```powershell
$env:PYTHONPATH="."; .\venv\Scripts\python.exe inference.py
```

Expected output:
```
[START] Evaluation: task_hard | Model: meta-llama/Llama-3.1-8B-Instruct | MaxSteps: 15 | LLM every 3 steps | Seed: 42
[STEP] Step: 01 | Source: POLICY | Action: MONITOR        | Target: none          | Reward: 0.00 | Done: False
[STEP] Step: 02 | Source: POLICY | Action: BLOCK_IP       | Target: 194.165.x.x   | Reward: 0.45 | Done: False
[STEP] Step: 03 | Source: LLM    | Action: ISOLATE_HOST   | Target: db-server-01  | Reward: 0.45 | Done: False
...
[END] Final Score: 0.8500 | Result: Task 'task_hard' concluded. Score: 0.85 (Resolved: 8/9, Errors: 1, Penalty: 0.02)

[TELEMETRY] TotalSteps=12 | LLM_Calls=4 | LLM_OK=3 (75.0%) | LLM_Fail=1 | PolicySteps=9 | Fallbacks=1 at steps [6] | AvgReward=0.371 | MaxReward=0.450
```

### Step 3 — Launch the Dashboard

```powershell
cd dashboard
npm install
npm run dev
```

Dashboard at `http://localhost:5173`.

### Strict Evaluation Mode (no heuristic fallback)

```env
ALLOW_FALLBACK=false
```

In this mode, any LLM failure immediately terminates the episode with `score=0.0` and `aborted=true`. Use for reproducible benchmark runs.

### Other Run Modes

```powershell
# Specific task
$env:PYTHONPATH="."; .\venv\Scripts\python.exe inference.py task_easy
$env:PYTHONPATH="."; .\venv\Scripts\python.exe inference.py task_medium

# PPO Training
$env:PYTHONPATH="."; .\venv\Scripts\python.exe train_soc.py

# Docker
docker-compose up --build
```

---

## 📂 Project Structure

```
autosec-master/
├── inference.py                  # Hybrid Brain (Smart Policy + LLM)
├── train_soc.py                  # PPO training loop
├── war_room.py                   # CLI headless simulation
├── openenv.yaml                  # OpenEnv manifest
├── .env                          # All configuration
├── requirements.txt
├── Dockerfile                    # Fixed paths: backend/ not api/
├── docker-compose.yml
│
├── autosec_openenv/              # Core OpenEnv Package
│   ├── env.py                    # SimulationEnvironment (seeded, 10-log window)
│   ├── models.py                 # Pydantic v2 models
│   ├── graders.py                # SOCGrader (hardened, crash-proof, bounded)
│   ├── task_manager.py           # Scenario definitions
│   ├── log_generator.py          # Realistic attack log simulation
│   ├── memory.py                 # ExperienceMemory (500-cap, smart eviction)
│   └── kill_chain.py             # Attack stage detection
│
├── backend/
│   ├── api/
│   │   └── server_rl.py          # FastAPI server (Pilot + RL modes, seeded reset)
│   ├── rl/
│   │   ├── env_wrapper.py        # Gymnasium wrapper (seed + novelty tracking)
│   │   ├── reward_engine.py      # Dense reward (8 signals, novelty bonus)
│   │   └── explainability.py     # Action explanation generator
│   ├── evaluator/
│   │   └── personas.py           # MultiPersonaEvaluator (3 personas)
│   ├── curriculum/
│   │   └── scheduler.py          # CurriculumScheduler (BASIC→ADVANCED)
│   └── memory/
│       └── vector_db.py          # ChromaDB vector memory (lazy-loaded)
│
└── dashboard/                    # React 18 + Vite telemetry dashboard
    ├── src/
    └── package.json
```

---

## ✅ OpenEnv Compliance

| Requirement | Status |
|---|---|
| `step(action) → observation, reward, done, info` | ✅ |
| `reset() → observation, info` | ✅ |
| `/v1/state` endpoint | ✅ |
| Pydantic `Observation`, `Action`, `Reward` models | ✅ |
| Reward normalized to `[0.0, 1.0]` | ✅ |
| `openenv.yaml` manifest | ✅ |
| `[START]`, `[STEP]`, `[END]` log markers | ✅ |
| Deterministic scoring with partial credit | ✅ |
| Multi-task evaluation (easy / medium / hard) | ✅ |
| Episode terminates within step limit | ✅ |
| No runtime crashes on LLM failure | ✅ |
| Score always in `[0.0, 1.0]` | ✅ |

---

## 🏆 Key Design Decisions

1. **Hybrid over Pure LLM**: Deterministic policy guarantees completion regardless of API credit status, while LLM provides strategic intelligence every few steps.

2. **Redirect over Reject**: When the LLM suggests a redundant action (re-blocking an already-blocked IP), the system redirects to `ISOLATE_HOST` of the associated host rather than discarding the step as a failure.

3. **Grader Errors ≠ Reward Redundancy**: Redundant actions (re-block/re-isolate) are penalized only in the reward engine (`-0.15`). The grader only records errors for genuinely wrong-target actions, preventing inflated error counts from destroying valid scores.

4. **Seed Propagation**: The same `RANDOM_SEED=42` flows from `.env` → `inference.py` → `server_rl.py` → `SimulationEnvironment` → `AutoSecGymEnv`, ensuring identical attacker behavior across all runs.

5. **Credit-Efficient LLM Use**: By calling the LLM only every 3 steps with a 256-token cap and `temperature=0`, an entire 15-step episode consumes ~5 API calls × ~512 tokens = ~2,500 tokens — well within free tier limits.
