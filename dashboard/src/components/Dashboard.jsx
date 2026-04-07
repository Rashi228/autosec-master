import React, { useState, useEffect } from 'react';
import {
  Shield, AlertTriangle, Activity,
  Terminal, Zap, History, Target, Cpu, XCircle, CheckCircle2, FlaskConical
} from 'lucide-react';
import { getSystemState, resetEnvironment, stepEnvironment, getEpisodeResult } from '../api/client';
import { AreaChart, Area, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer } from 'recharts';

/* ─────────────────────────────────────────
   HELPER FUNCTIONS
───────────────────────────────────────── */

const getSeverityColor = (sev) => {
  if (sev === 'CRITICAL') return 'text-red-700 bg-red-50 border border-red-100';
  if (sev === 'HIGH')     return 'text-amber-700 bg-amber-50 border border-amber-100';
  if (sev === 'MEDIUM')   return 'text-emerald-700 bg-emerald-50 border border-emerald-100';
  return 'text-slate-600 bg-slate-50 border border-slate-100';
};

const getStageDesc = (stage) => ({
  reconnaissance:       'Gathering info on the network.',
  initial_access:       'Gaining a foothold via login.',
  privilege_escalation: 'Becoming root/admin on a host.',
  lateral_movement:     'Moving to targets like dc-01.',
  exfiltration:         'Stealing sensitive corporate data.',
  discovery:            'Enumerating active services.',
  lateral:              'Spreading to internal systems.',
}[stage.toLowerCase()] || '');

/* ─────────────────────────────────────────
   STAT CARD — clean, no left-border accent
───────────────────────────────────────── */
const getDifficultyLabel = (taskId, stateDiff) => {
  if (taskId === 'task_easy') return 'L1 — BASIC';
  if (taskId === 'task_medium') return 'L2 — INTERMEDIATE';
  if (taskId === 'task_hard') return 'L3 — ADVANCED';
  return stateDiff || 'L1 — BASIC';
};

const StatCard = ({ label, value, icon, sub }) => (
  <div className="bg-white border border-soc-border p-5 rounded-md shadow-sm hover:shadow-md transition-shadow">
    <div className="flex items-start justify-between mb-4">
      <span className="text-[10px] font-semibold uppercase tracking-widest text-slate-400">{label}</span>
      <span className="text-slate-400">{icon}</span>
    </div>
    <div className="text-2xl font-bold text-slate-900 tabular-nums">{value}</div>
    {sub && <div className="text-[10px] text-slate-400 mt-1.5 font-medium">{sub}</div>}
  </div>
);

/* ─────────────────────────────────────────
   ATTACK PIPELINE
───────────────────────────────────────── */
const AttackPipeline = ({ currentStage }) => {
  const STAGES = ['reconnaissance', 'initial_access', 'privilege_escalation', 'lateral_movement', 'exfiltration'];
  const normalizedStage = (currentStage || 'benign').toLowerCase().replace(/\s+/g, '_');
  const isBenign   = normalizedStage === 'benign';
  
  // Try to find index by exact match or substring for robustness
  let currentIdx = STAGES.indexOf(normalizedStage);
  if (currentIdx === -1) {
    currentIdx = STAGES.findIndex(s => normalizedStage.includes(s) || s.includes(normalizedStage));
  }

  return (
    <div className="relative flex items-center justify-between px-1 py-2">
      {/* Base track */}
      <div className="absolute left-0 right-0 top-[22px] h-px bg-slate-200" />
      {/* Filled track */}
      {!isBenign && currentIdx >= 0 && (
        <div
          className="absolute top-[22px] left-0 h-px bg-brand transition-all duration-700"
          style={{ width: `${(currentIdx / (STAGES.length - 1)) * 100}%` }}
        />
      )}

      {STAGES.map((stage, idx) => {
        const isActive  = !isBenign && idx <= currentIdx;
        const isCurrent = !isBenign && idx === currentIdx;
        return (
          <div key={stage} className="relative z-10 flex flex-col items-center gap-2.5 group">
            {/* Node */}
            <div className={`w-11 h-11 flex items-center justify-center rounded-sm border text-[10px] font-bold
              transition-all duration-300
              ${isCurrent ? 'bg-brand border-brand text-white shadow-md' :
                isActive  ? 'bg-blue-50 border-brand text-brand' :
                            'bg-white border-slate-200 text-slate-400'}`}
            >
              {String(idx + 1).padStart(2, '0')}
            </div>
            {/* Label */}
            <span className={`text-[9px] font-semibold uppercase tracking-wider text-center leading-tight
              ${isCurrent ? 'text-brand' : isActive ? 'text-slate-600' : 'text-slate-400'}`}
              style={{ maxWidth: 70 }}>
              {stage.replace(/_/g, '\u00A0')}
            </span>
            {/* Tooltip */}
            <div className="absolute bottom-full mb-2 left-1/2 -translate-x-1/2 w-44 bg-white border border-slate-200
              shadow-lg rounded-md p-3 text-[10px] opacity-0 group-hover:opacity-100 pointer-events-none
              transition-opacity z-50">
              <p className="font-bold text-brand uppercase tracking-wide mb-1">{stage.replace(/_/g, ' ')}</p>
              <p className="text-slate-500 leading-relaxed">{getStageDesc(stage)}</p>
            </div>
          </div>
        );
      })}
    </div>
  );
};

/* ─────────────────────────────────────────
   CHART TOOLTIP
───────────────────────────────────────── */
const SOCTooltip = ({ active, payload }) => {
  if (!active || !payload?.length) return null;
  return (
    <div className="bg-white border border-slate-200 shadow-md rounded-md p-3 text-[11px]">
      <p className="text-slate-400 mb-1">{payload[0].payload.time}</p>
      <p className="font-bold text-slate-800">
        {payload[0].value} <span className="font-normal text-slate-500">active threats</span>
      </p>
    </div>
  );
};

/* ─────────────────────────────────────────
   LOADING SPINNER — clean minimal
───────────────────────────────────────── */
const Spinner = () => (
  <div className="w-8 h-8 border-2 border-slate-200 border-t-brand rounded-full animate-spin" />
);

/* ─────────────────────────────────────────
   MAIN DASHBOARD
───────────────────────────────────────── */
const Dashboard = () => {
  const [state, setState]               = useState(null);
  const [history, setHistory]           = useState([]);
  const [loading, setLoading]           = useState(true);
  const [error, setError]               = useState(null);
  const [isAutoPilot, setIsAutoPilot]   = useState(false);
  const [selectedTask, setSelectedTask] = useState('task_hard');
  const [showResultModal, setShowResultModal] = useState(false);
  const [resultData, setResultData]     = useState(null);
  const [isResetting, setIsResetting]   = useState(false);

  useEffect(() => {
    const fetchData = async () => {
      try {
        const data = await getSystemState();
        setState(data);
        setError(null);
        if (data.status === 'ACTIVE' && data.task_id) setSelectedTask(data.task_id);
        if (data.status !== 'INACTIVE' && data.system_state) {
          setHistory(prev => [...prev.slice(-19), {
            time: new Date().toLocaleTimeString(),
            threats: data.system_state.active_threats || 0,
          }]);
        }
        setLoading(false);
      } catch (err) {
        console.error('Fetch error:', err);
        setError('Connection to SOC API failed. Retrying...');
      }
    };
    fetchData();
    const id = setInterval(fetchData, 1500);
    return () => clearInterval(id);
  }, []);

  useEffect(() => {
    if (state?.done && !showResultModal && !resultData) {
      (async () => {
        try {
          const res = await getEpisodeResult();
          setResultData(res);
          setShowResultModal(true);
          setIsAutoPilot(false);
        } catch (e) { console.error('Result fetch failed', e); }
      })();
    } else if (!state?.done) {
      setResultData(null);
    }
  }, [state?.done]);

  useEffect(() => {
    let alive = true;
    const id = setInterval(async () => {
      if (state?.status === 'ACTIVE' && isAutoPilot && !state?.done && alive) {
        try { await stepEnvironment({}); } catch (e) { console.error('Step failed', e); }
      }
    }, 1500);
    return () => { alive = false; clearInterval(id); };
  }, [state?.status, isAutoPilot, state?.done]);

  const handleReset = async (taskId) => {
    setIsResetting(true);
    try {
      await resetEnvironment(taskId || selectedTask);
      setShowResultModal(false);
      setResultData(null);
    } catch (e) { console.error('Reset failed', e); }
    finally { setIsResetting(false); }
  };

  if (error && !state) return (
    <div className="flex flex-col items-center justify-center h-screen bg-soc-bg text-critical gap-3">
      <AlertTriangle className="w-8 h-8" />
      <p className="text-sm font-semibold">{error}</p>
      <p className="text-xs text-slate-400">Ensure backend is running on 127.0.0.1:7860</p>
    </div>
  );

  if (loading) return (
    <div className="flex flex-col items-center justify-center h-screen bg-soc-bg gap-4">
      <Spinner />
      <p className="text-xs text-slate-400 uppercase tracking-widest font-semibold">Initializing...</p>
    </div>
  );

  const isInactive    = state?.status === 'INACTIVE';
  const actionHistory = state?.action_history || [];
  const lastAction    = actionHistory.length > 0 ? actionHistory[actionHistory.length - 1] : null;
  const maxSteps      = state?.max_steps || state?.system_state?.max_steps || 15;

  return (
    <div className="min-h-screen bg-soc-bg text-slate-800 font-sans antialiased">

      {/* ── HEADER ── */}
      <header className="sticky top-0 z-50 bg-white border-b border-soc-border flex items-center justify-between px-6 py-3.5">
        <div className="flex items-center gap-3">
          <div className="p-2 bg-brand rounded-md">
            <Shield className="w-4 h-4 text-white" />
          </div>
          <div>
            <h1 className="text-sm font-bold text-slate-900 tracking-tight">AutoSec RL Agent</h1>
            <p className="text-[10px] text-slate-400 font-medium uppercase tracking-widest">Autonomous SOC · Defense Layer</p>
          </div>
        </div>

        <div className="flex items-center gap-5">
          {/* Status Pill */}
          <div className="flex items-center gap-2 px-3 py-1.5 bg-slate-50 border border-soc-border rounded-md">
            <span className={`w-2 h-2 rounded-full ${state?.status === 'ACTIVE' ? 'bg-green-500' : 'bg-slate-300'}`} />
            <span className="text-[10px] font-semibold uppercase tracking-widest text-slate-500">
              {state?.status || 'UNKNOWN'}
            </span>
          </div>

          {/* Auto-pilot toggle */}
          <div className="flex items-center gap-3">
            <span className="text-[10px] font-semibold text-slate-500 uppercase tracking-widest">
              {isAutoPilot ? 'Autonomous' : 'Manual'}
            </span>
            <button
              onClick={() => setIsAutoPilot(p => !p)}
              className={`w-10 h-5 rounded-full relative transition-colors border ${isAutoPilot ? 'bg-brand border-brand' : 'bg-slate-200 border-slate-300'}`}
            >
              <span className={`absolute top-0.5 w-4 h-4 bg-white rounded-full shadow-sm transition-all ${isAutoPilot ? 'left-5' : 'left-0.5'}`} />
            </button>
          </div>

          {/* Task selector */}
          <select
            value={selectedTask}
            onChange={e => setSelectedTask(e.target.value)}
            className="text-[10px] font-semibold uppercase border border-soc-border bg-white text-slate-700
              rounded-md px-3 py-2 outline-none focus:border-brand cursor-pointer"
          >
            <option value="task_easy">L1 — Perimeter</option>
            <option value="task_medium">L2 — Lateral</option>
            <option value="task_hard">L3 — Stealth APT</option>
          </select>

          {/* Reset button */}
          <button
            onClick={() => handleReset()}
            disabled={isResetting}
            className="flex items-center gap-2 px-4 py-2 bg-brand text-white text-[10px] font-semibold
              uppercase tracking-widest rounded-md hover:bg-blue-700 active:scale-95 transition-all
              disabled:opacity-50"
          >
            <FlaskConical className="w-3 h-3" />
            {isResetting ? 'Resetting...' : 'Reset War Room'}
          </button>
        </div>
      </header>

      {/* ── MAIN ── */}
      <main className="grid grid-cols-12 gap-4 p-5 max-w-[1900px] mx-auto">

        {/* ── LEFT COLUMN ── */}
        <div className="col-span-12 lg:col-span-7 flex flex-col gap-4">

          {/* Stat cards */}
          <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
            <StatCard
              label="Active Threats"
              value={state?.system_state?.active_threats || 0}
              icon={<AlertTriangle className="w-4 h-4" />}
            />
            <StatCard
              label="Policy Reward"
              value={state?.cumulative_score?.toFixed(2) || '0.00'}
              icon={<Zap className="w-4 h-4" />}
            />
            <StatCard
              label="Difficulty"
              value={getDifficultyLabel(selectedTask, state?.difficulty)}
              icon={<Shield className="w-4 h-4" />}
            />
            <StatCard
              label="RL Episodes"
              value={state?.rl_telemetry?.episodes || 0}
              icon={<History className="w-4 h-4" />}
              sub={`Success: ${((state?.rl_telemetry?.success_rate || 0) * 100).toFixed(1)}%`}
            />
          </div>

          {/* Attack Pipeline */}
          <div className="bg-white border border-soc-border rounded-md shadow-sm p-6">
            <div className="flex items-center justify-between mb-5 pb-4 border-b border-soc-border">
              <div className="flex items-center gap-2">
                <Target className="w-4 h-4 text-slate-400" />
                <h2 className="text-[10px] font-bold uppercase tracking-widest text-slate-500">Tactical Attack Stage</h2>
              </div>
              <span className="text-[10px] font-mono font-semibold text-slate-400 bg-slate-50 border border-slate-200 px-2.5 py-1 rounded-md">
                {state?.current_stage?.toUpperCase() || 'BENIGN'}
              </span>
            </div>
            <AttackPipeline currentStage={state?.current_stage || 'benign'} />
          </div>

          {/* Network Graph */}
          <div className="bg-white border border-soc-border rounded-md shadow-sm p-6 h-[290px] flex flex-col">
            <div className="flex items-center justify-between mb-5 pb-4 border-b border-soc-border">
              <div className="flex items-center gap-2">
                <Activity className="w-4 h-4 text-slate-400" />
                <h2 className="text-[10px] font-bold uppercase tracking-widest text-slate-500">Network Threat Density</h2>
              </div>
              <div className="flex items-center gap-2">
                <span className="w-2 h-2 rounded-full bg-brand animate-pulse" />
                <span className="text-[9px] font-semibold text-slate-400 uppercase tracking-widest">Live</span>
              </div>
            </div>
            <div className="flex-1">
              <ResponsiveContainer width="100%" height="100%">
                <AreaChart data={history}>
                  <defs>
                    <linearGradient id="threatFill" x1="0" y1="0" x2="0" y2="1">
                      <stop offset="5%"  stopColor="#1d4ed8" stopOpacity={0.12} />
                      <stop offset="95%" stopColor="#1d4ed8" stopOpacity={0} />
                    </linearGradient>
                  </defs>
                  <CartesianGrid strokeDasharray="4 4" stroke="#f1f5f9" vertical={false} />
                  <XAxis dataKey="time" hide stroke="#94a3b8" fontSize={9} />
                  <YAxis stroke="#cbd5e1" fontSize={9} domain={[0, 'auto']} tickFormatter={v => `${v}`} />
                  <Tooltip content={<SOCTooltip />} />
                  <Area type="monotone" dataKey="threats" stroke="#1d4ed8" strokeWidth={2}
                    fillOpacity={1} fill="url(#threatFill)" isAnimationActive={false} />
                </AreaChart>
              </ResponsiveContainer>
            </div>
          </div>
        </div>

        {/* ── RIGHT COLUMN: AI ENGINE ── */}
        <div className="col-span-12 lg:col-span-5 flex flex-col gap-4">
          <div className="bg-white border border-soc-border rounded-md shadow-sm p-7 flex flex-col h-full min-h-[560px]">

            {/* Panel header */}
            <div className="flex items-center gap-3 mb-7 pb-5 border-b border-soc-border">
              <div className="p-2 bg-blue-50 border border-blue-100 rounded-md">
                <Cpu className="w-4 h-4 text-brand" />
              </div>
              <div>
                <h2 className="text-sm font-bold text-slate-800 tracking-tight">AI Decision Engine</h2>
                <p className="text-[10px] text-slate-400 font-medium mt-0.5">Real-time Policy Inference</p>
              </div>
            </div>

            {lastAction ? (
              <div className="flex flex-col gap-6 flex-1">
                {/* Action block */}
                <div className="bg-slate-50 border border-soc-border rounded-md p-5">
                  <div className="flex items-center justify-between mb-4 pb-4 border-b border-soc-border">
                    <div>
                      <p className="text-[9px] text-slate-400 font-semibold uppercase tracking-widest mb-1">Defensive Action</p>
                      <p className="text-2xl font-bold font-mono text-slate-900 tracking-tight uppercase">
                        {lastAction.action_type}
                      </p>
                    </div>
                    <div className="text-right">
                      <p className="text-[9px] text-slate-400 font-semibold uppercase tracking-widest mb-1">Confidence</p>
                      <div className="flex items-center gap-2">
                        <span className="text-lg font-bold text-slate-800">
                          {((lastAction.confidence || 0) * 100).toFixed(0)}%
                        </span>
                        <div className="w-16 h-1.5 bg-slate-200 rounded-full overflow-hidden">
                          <div className="h-full bg-brand transition-all duration-700" 
                               style={{ width: `${(lastAction.confidence || 0) * 100}%` }} />
                        </div>
                      </div>
                    </div>
                  </div>
                  
                  <div className="flex items-center gap-4">
                    <div className="flex items-center gap-2 text-slate-500">
                      <Target className="w-3.5 h-3.5 text-high" />
                      <span className="text-xs font-mono font-semibold">{lastAction.target}</span>
                    </div>
                    <div className="ml-auto text-[10px] font-semibold text-slate-400 bg-white border border-soc-border px-3 py-1 rounded-md">
                      Step {(lastAction.step || 0)} / {maxSteps}
                    </div>
                  </div>
                </div>

                {/* Reasoning */}
                <div>
                  <div className="flex items-center gap-2 mb-3">
                    <Terminal className="w-3.5 h-3.5 text-slate-400" />
                    <span className="text-[9px] font-bold uppercase tracking-widest text-slate-400">
                      Multi-Persona Reasoning
                    </span>
                  </div>
                  <div className="bg-slate-50 border border-soc-border rounded-md p-5 text-xs text-slate-600 space-y-4">
                    <div className="flex items-center gap-4 pb-3 border-b border-soc-border">
                      <div>
                        <span className="text-[9px] font-bold text-brand uppercase block mb-0.5">Strategy</span>
                        <span className="font-semibold text-slate-700 uppercase text-[10px]">{lastAction.strategy || 'N/A'}</span>
                      </div>
                      <div className="w-px h-6 bg-soc-border" />
                      <div>
                        <span className="text-[9px] font-bold text-brand uppercase block mb-0.5">Tactic</span>
                        <span className="font-semibold text-slate-700 uppercase text-[10px]">{lastAction.tactic || 'N/A'}</span>
                      </div>
                    </div>
                    <p className="text-slate-500 leading-relaxed italic text-[11px]">
                      "{lastAction.reasoning}"
                    </p>
                    {lastAction.persona_evaluations && (
                      <div className="pt-3 border-t border-soc-border space-y-3">
                        {['analyst', 'hunter', 'responder'].map(p => (
                          <div key={p} className="flex items-center gap-3">
                            <span className="w-20 text-[9px] font-semibold text-slate-400 uppercase tracking-wide">{p}</span>
                            <div className="flex-1 h-1.5 bg-slate-100 rounded-sm overflow-hidden">
                              <div className="h-full bg-brand transition-all duration-700"
                                style={{ width: `${(lastAction.persona_evaluations[p]?.score || 0) * 100}%` }} />
                            </div>
                            <span className="w-8 text-right text-[9px] font-mono font-semibold text-slate-500">
                              {(lastAction.persona_evaluations[p]?.score || 0).toFixed(1)}
                            </span>
                          </div>
                        ))}
                      </div>
                    )}
                  </div>
                </div>

                {/* Reward footer */}
                <div className="mt-auto pt-5 border-t border-soc-border flex items-center gap-3">
                  <Zap className="w-4 h-4 text-slate-300" />
                  <span className="text-xl font-bold font-mono text-slate-800">
                    {lastAction.step_score?.toFixed(3) || '0.000'}
                  </span>
                  <span className="text-[10px] font-semibold uppercase tracking-widest text-slate-400 ml-1">
                    Cumulative Reward
                  </span>
                </div>
              </div>

            ) : (
              /* Idle state */
              <div className="flex-1 flex flex-col items-center justify-center gap-6">
                <div className="p-5 bg-slate-50 border border-soc-border rounded-md text-center">
                  <div className="flex justify-center mb-4">
                    <Spinner />
                  </div>
                  <p className="text-xs font-semibold text-slate-500 uppercase tracking-widest mb-1">
                    {isInactive ? 'System Idle' : 'Awaiting Inference'}
                  </p>
                  <p className="text-[10px] text-slate-400 max-w-[220px] mx-auto leading-relaxed">
                    {isInactive
                      ? 'Initialize the environment to begin monitoring.'
                      : 'Waiting for next policy reasoning trace.'}
                  </p>
                </div>
                {isInactive && (
                  <button
                    onClick={() => handleReset('task_easy')}
                    className="flex items-center gap-2 px-6 py-2.5 bg-brand text-white text-[10px] font-semibold
                      uppercase tracking-widest rounded-md hover:bg-blue-700 transition-all"
                  >
                    <Shield className="w-3 h-3" />
                    Initialize Defense
                  </button>
                )}
              </div>
            )}
          </div>
        </div>

        {/* ── BOTTOM ROW ── */}
        <div className="col-span-12 grid grid-cols-12 gap-4">

          {/* SIEM Feed */}
          <div className="col-span-12 lg:col-span-8 h-[480px] bg-white border border-soc-border rounded-md shadow-sm p-6 flex flex-col overflow-hidden">
            <div className="flex items-center justify-between mb-5 pb-4 border-b border-soc-border">
              <div className="flex items-center gap-2">
                <History className="w-4 h-4 text-slate-400" />
                <h2 className="text-[10px] font-bold uppercase tracking-widest text-slate-500">Security Intelligence Feed</h2>
              </div>
              <div className="flex items-center gap-2">
                <span className="w-1.5 h-1.5 bg-green-500 rounded-full animate-pulse" />
                <span className="text-[9px] font-semibold text-slate-400 uppercase tracking-widest">Recording</span>
              </div>
            </div>
            <div className="flex-1 overflow-auto custom-scroll">
              <table className="w-full text-left text-[10px] font-mono">
                <thead className="sticky top-0 bg-white border-b border-soc-border">
                  <tr className="text-[9px] font-bold uppercase tracking-widest text-slate-400">
                    <th className="py-2.5 pr-4">Timestamp</th>
                    <th className="py-2.5 pr-4">Event Type</th>
                    <th className="py-2.5 pr-4">Source</th>
                    <th className="py-2.5 pr-4 text-center">Severity</th>
                    <th className="py-2.5 text-right">Host</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-50">
                  {state?.logs?.slice(-20).reverse().map((log, i) => (
                    <tr key={i} className="hover:bg-slate-50 transition-colors">
                      <td className="py-2.5 pr-4 text-slate-400">{log.timestamp?.split('T')[1]?.split('.')[0] || '--:--:--'}</td>
                      <td className="py-2.5 pr-4 text-slate-800 font-semibold">{log.event_type}</td>
                      <td className="py-2.5 pr-4 text-slate-500">{log.source_ip || '---'}</td>
                      <td className="py-2.5 pr-4 text-center">
                        <span className={`px-2 py-0.5 rounded-sm text-[9px] font-bold ${getSeverityColor(log.severity)}`}>
                          {log.severity?.substring(0, 4)}
                        </span>
                      </td>
                      <td className="py-2.5 text-slate-400 text-right">{log.hostname}</td>
                    </tr>
                  ))}
                  {(!state?.logs || state.logs.length === 0) && (
                    <tr>
                      <td colSpan="5" className="py-16 text-center text-slate-300 text-[10px] font-semibold uppercase tracking-widest">
                        Monitoring — No events recorded
                      </td>
                    </tr>
                  )}
                </tbody>
              </table>
            </div>
          </div>

          {/* Defensive Enforcement Log */}
          <div className="col-span-12 lg:col-span-4 h-[480px] bg-slate-50 border border-soc-border rounded-md p-6
            font-mono text-[11px] flex flex-col shadow-sm overflow-hidden">
            <div className="flex items-center justify-between mb-5 pb-4 border-b border-slate-200">
              <div className="flex items-center gap-2 text-slate-400">
                <Terminal className="w-3.5 h-3.5" />
                <span className="text-[9px] font-bold uppercase tracking-widest text-slate-500">Defensive Enforcement Log</span>
              </div>
              <span className="w-1.5 h-1.5 bg-brand rounded-full" />
            </div>
            <div className="flex-1 overflow-y-auto custom-scroll space-y-4 pr-1">
              {actionHistory.slice().reverse().map((act, i) => (
                <div key={i} className="border-l-2 border-slate-200 pl-4 py-1">
                  <div className="flex items-center gap-3 mb-1.5 text-[9px]">
                    <span className="text-slate-400 font-medium uppercase tracking-wider">
                      +{String(state?.episode_elapsed_s || 0).padStart(3, '0')}s
                    </span>
                    <span className="text-brand font-bold uppercase">Executed</span>
                  </div>
                  <div className="text-slate-900 font-bold text-xs uppercase mb-2 tracking-wide">
                    {act.action_type}
                  </div>
                  <div className="text-slate-500 text-[10px] bg-white px-3 py-2 rounded-sm border border-slate-200 leading-relaxed font-mono">
                    <span className="text-brand select-none">$</span> auth --enforce {act.action_type} --target {act.target}
                  </div>
                </div>
              ))}
              {actionHistory.length === 0 && (
                <div className="flex flex-col items-center justify-center h-full text-slate-300 gap-2">
                  <History className="w-8 h-8 opacity-50" />
                  <p className="text-[9px] font-semibold uppercase tracking-widest text-slate-300/40">Link Standby</p>
                </div>
              )}
              <div className="w-1.5 h-4 bg-slate-200 animate-pulse mt-1" />
            </div>
          </div>
        </div>
      </main>

      {/* ── RESULT MODAL ── */}
      {showResultModal && resultData && (
        <div className="fixed inset-0 z-[100] flex items-center justify-center bg-slate-900/50 backdrop-blur-sm p-6">
          <div className="w-full max-w-xl bg-white border border-soc-border rounded-md shadow-2xl overflow-hidden">

            {/* Modal header */}
            <div className="flex items-center justify-between px-8 py-6 border-b border-soc-border bg-slate-50">
              <div className="flex items-center gap-4">
                <div className="p-2 bg-green-100 border border-green-200 rounded-md">
                  <CheckCircle2 className="w-5 h-5 text-medium" />
                </div>
                <div>
                  <h2 className="text-base font-bold text-slate-900">Episode Concluded</h2>
                  <p className="text-[10px] text-slate-400 font-medium uppercase tracking-widest mt-0.5">{selectedTask}</p>
                </div>
              </div>
              <button
                onClick={() => setShowResultModal(false)}
                className="text-slate-400 hover:text-slate-600 p-1.5 hover:bg-slate-100 rounded-md transition-colors"
              >
                <XCircle className="w-5 h-5" />
              </button>
            </div>

            <div className="px-8 py-7">
              {/* Metrics */}
              <div className="grid grid-cols-3 gap-6 mb-7 pb-7 border-b border-soc-border">
                <div>
                  <p className="text-[9px] font-bold uppercase tracking-widest text-slate-400 mb-2">Final Score</p>
                  <p className="text-4xl font-bold text-slate-900 tabular-nums">
                    {(resultData.final_grader_score * 100).toFixed(0)}
                    <span className="text-brand text-xl">%</span>
                  </p>
                </div>
                <div>
                  <p className="text-[9px] font-bold uppercase tracking-widest text-slate-400 mb-2">Neutralized</p>
                  <p className="text-4xl font-bold text-slate-900 tabular-nums">
                    {resultData.telemetry?.threats_resolved || 0}
                    <span className="text-slate-300 text-xl"> / {resultData.telemetry?.threats_total || 0}</span>
                  </p>
                </div>
                <div>
                  <p className="text-[9px] font-bold uppercase tracking-widest text-slate-400 mb-2">Clearance</p>
                  <p className="text-sm font-bold text-brand uppercase tracking-wider mt-3">
                    {resultData.telemetry?.difficulty || 'BASIC'}
                  </p>
                </div>
              </div>

              {/* Persona scores */}
              <div className="bg-slate-50 border border-soc-border rounded-md p-5 mb-6">
                <p className="text-[9px] font-bold text-slate-400 uppercase tracking-widest mb-4">
                  Multi-Persona Evaluation
                </p>
                <div className="space-y-3.5">
                  {Object.entries(resultData.persona_scores || {}).map(([name, data]) => (
                    <div key={name} className="flex items-center gap-4">
                      <span className="w-20 text-[9px] font-semibold text-slate-500 uppercase tracking-wide">{name}</span>
                      <div className="flex-1 h-1.5 bg-slate-200 rounded-sm overflow-hidden">
                        <div className="h-full bg-brand transition-all duration-700"
                          style={{ width: `${(data.score || 0) * 100}%` }} />
                      </div>
                      <span className="w-10 text-right text-[9px] font-mono font-semibold text-slate-500">
                        {(data.score || 0).toFixed(2)}
                      </span>
                    </div>
                  ))}
                </div>
              </div>

              {/* Actions */}
              <div className="flex gap-3">
                <button
                  onClick={() => handleReset()}
                  className="flex-1 py-3 bg-brand text-white text-[10px] font-semibold uppercase tracking-widest
                    rounded-md hover:bg-blue-700 transition-all"
                >
                  New Session
                </button>
                <button
                  onClick={() => setShowResultModal(false)}
                  className="flex-1 py-3 bg-slate-50 border border-soc-border text-slate-600 text-[10px] font-semibold
                    uppercase tracking-widest rounded-md hover:bg-slate-100 transition-all"
                >
                  Review Simulation
                </button>
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};

export default Dashboard;
