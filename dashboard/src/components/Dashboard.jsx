import React, { useState, useEffect } from 'react';
import { 
  Shield, AlertTriangle, Activity, Database, 
  Terminal, Zap, History, Target, Cpu 
} from 'lucide-react';
import { getSystemState, resetEnvironment, stepEnvironment } from '../api/client';
import { LineChart, Line, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer, AreaChart, Area } from 'recharts';

const Dashboard = () => {
  const [state, setState] = useState(null);
  const [history, setHistory] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);

  // Poll for state every 2 seconds
  useEffect(() => {
    const fetchData = async () => {
      try {
        const data = await getSystemState();
        console.log("DASHBOARD_SYNC_DATA:", data);
        setState(data);
        setError(null);
        if (data.status !== 'INACTIVE' && data.system_state) {
          setHistory(prev => [...prev.slice(-19), { time: new Date().toLocaleTimeString(), threats: data.system_state.active_threats || 0 }]);
        }
        setLoading(false);
      } catch (err) {
        console.error("Fetch error:", err);
        setError("Connection to SOC API failed. Retrying...");
      }
    };

    fetchData();
    const interval = setInterval(fetchData, 1500);
    return () => clearInterval(interval);
  }, []);

  // Autonomous RL stepping interval
  useEffect(() => {
    let active = true;
    const processStep = async () => {
      if (state?.status === 'ACTIVE' && active) {
        try {
          // Trigger the RL model to infer and execute a step
          await stepEnvironment({});
        } catch (e) {
          console.error("Step failed", e);
        }
      }
    };
    
    // The backend executes the model predict logic. 
    // We tick it every 1.5 seconds.
    const stepInterval = setInterval(processStep, 1500);
    return () => {
       active = false;
       clearInterval(stepInterval);
    };
  }, [state?.status]);

  if (error && !state) return (
    <div className="flex flex-col items-center justify-center h-screen bg-soc-bg text-critical gap-4">
      <AlertTriangle className="w-12 h-12 animate-bounce" />
      <h1 className="text-xl font-black uppercase tracking-widest">{error}</h1>
      <p className="text-xs text-slate-500">Ensure backend is running on 127.0.0.1:7860</p>
    </div>
  );

  if (loading) return <div className="flex items-center justify-center h-screen text-brand bg-soc-bg">Initializing SOC...</div>;

  const isInactive = state?.status === 'INACTIVE';
  const statusColor = state?.system_state?.status === 'COMPROMISED' ? 'text-critical' : 'text-success';
  const actionHistory = state?.action_history || [];
  const lastAction = actionHistory.length > 0 ? actionHistory[actionHistory.length - 1] : null;

  return (
    <div className="min-h-screen bg-soc-bg text-slate-100 font-sans selection:bg-brand/30">
      {/* Header - Fixed or Sticky */}
      <header className="sticky top-0 z-50 flex items-center justify-between p-4 border-b border-soc-border bg-soc-bg/80 backdrop-blur-md">
        <div className="flex items-center gap-3">
          <div className="p-2 border border-brand/50 bg-brand/10 rounded-lg shadow-[0_0_15px_rgba(14,165,233,0.1)]">
            <Shield className="w-5 h-5 text-brand" />
          </div>
          <div>
            <h1 className="text-lg font-black tracking-tight text-white">AutoSec <span className="text-brand">RL Agent</span> Dashboard</h1>
            <p className="text-[10px] text-slate-500 font-mono uppercase tracking-[0.3em]">Autonomous Neural Defensive Layer</p>
          </div>
        </div>
        
        <div className="flex items-center gap-8">
          <div className="flex items-center gap-4 border-l border-white/5 pl-6">
            <div className="text-right">
              <p className="text-[9px] uppercase font-bold text-slate-500 tracking-widest">Global Status</p>
              <p className={`text-sm font-black flex items-center gap-2 ${statusColor}`}>
                <Activity className="w-3 h-3 animate-pulse" />
                {isInactive ? 'INACTIVE' : (state?.system_state?.status || 'IDLE')}
              </p>
            </div>
          </div>
          <button 
            onClick={() => resetEnvironment('task_02')}
            className="px-5 py-2 bg-brand text-white font-bold rounded-lg text-xs hover:bg-brand/80 transition-all shadow-lg shadow-brand/20 active:scale-95"
          >
            RESET WAR ROOM
          </button>
        </div>
      </header>

      {/* Main Grid - Now Scrolling Naturally */}
      <main className="grid grid-cols-12 gap-6 p-6 max-w-[1800px] mx-auto">
        
        {/* Left Column: Stats, Kill Chain & Graph */}
        <div className="col-span-12 lg:col-span-7 flex flex-col gap-6">
          <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
            <StatCard label="Threats" value={state?.system_state?.active_threats || 0} icon={<AlertTriangle className="text-medium w-4 h-4" />} />
            <StatCard label="Reward" value={state?.cumulative_score?.toFixed(2) || 0} icon={<Zap className="text-brand w-4 h-4" />} />
            <StatCard label="Difficulty" value={state?.difficulty || 'BASIC'} icon={<Shield className="text-high w-4 h-4" />} />
            <StatCard label="RL Episodes" value={state?.rl_telemetry?.episodes || 0} icon={<History className="text-slate-400 w-4 h-4" />} sub={`Success: ${((state?.rl_telemetry?.success_rate || 0) * 100).toFixed(1)}%`} />
          </div>

          <div className="p-6 bg-soc-card border border-soc-border rounded-2xl shadow-xl">
             <div className="flex items-center gap-3 mb-6 border-b border-white/5 pb-4">
               <Target className="w-4 h-4 text-high" />
               <h2 className="text-[11px] font-black uppercase tracking-[0.3em] text-slate-400">Tactical Attack Stage</h2>
             </div>
             <KillChainTracker currentStage={state?.current_stage || 'benign'} />
          </div>

          <div className="h-[300px] bg-soc-card border border-soc-border rounded-2xl p-6 shadow-xl flex flex-col">
            <div className="flex items-center gap-3 mb-6">
               <Activity className="w-4 h-4 text-brand" />
               <h2 className="text-[11px] font-black uppercase tracking-[0.3em] text-slate-400">Network Threat Density</h2>
            </div>
            <div className="flex-1">
              <ResponsiveContainer width="100%" height="100%">
                <AreaChart data={history}>
                  <defs>
                    <linearGradient id="colorThreat" x1="0" y1="0" x2="0" y2="1">
                      <stop offset="5%" stopColor="#0ea5e9" stopOpacity={0.4}/>
                      <stop offset="95%" stopColor="#0ea5e9" stopOpacity={0}/>
                    </linearGradient>
                  </defs>
                  <CartesianGrid strokeDasharray="3 3" stroke="#334155" vertical={false} />
                  <XAxis dataKey="time" stroke="#64748b" fontSize={10} hide />
                  <YAxis stroke="#475569" fontSize={10} domain={[0, 'auto']} />
                  <Tooltip contentStyle={{ backgroundColor: '#0f172a', border: '1px solid #334155', borderRadius: '12px' }} />
                  <Area type="monotone" dataKey="threats" stroke="#0ea5e9" strokeWidth={4} fillOpacity={1} fill="url(#colorThreat)" isAnimationActive={false} />
                </AreaChart>
              </ResponsiveContainer>
            </div>
          </div>
        </div>

        {/* Right Column: AI Reasoning Panel */}
        <div className="col-span-12 lg:col-span-5 flex flex-col gap-6">
           <div className="bg-soc-card border-l-4 border-l-brand border border-soc-border rounded-2xl p-8 flex flex-col shadow-2xl relative overflow-hidden group h-full min-h-[480px]">
             <div className="absolute top-0 right-0 p-8 opacity-[0.03] group-hover:opacity-[0.07] transition-opacity">
               <Cpu className="w-48 h-48 text-white" />
             </div>
             <div className="flex items-center gap-3 mb-8 relative z-10 border-b border-white/10 pb-4">
               <div className="p-2 bg-brand/10 rounded-lg"><Cpu className="w-6 h-6 text-brand" /></div>
               <div>
                <h2 className="text-sm font-black uppercase tracking-widest text-white">AI Decision Engine</h2>
                <p className="text-[10px] text-slate-500 font-bold uppercase mt-0.5 tracking-tighter">Real-time Policy Inference Explainer</p>
               </div>
             </div>
              {lastAction ? (
               <div className="flex flex-col gap-8 relative z-10 h-full">
                  <div className="p-6 bg-slate-950 border border-brand/30 rounded-2xl shadow-inner">
                    <p className="text-[10px] text-brand/70 font-black uppercase tracking-widest mb-2">Primary Defense Action</p>
                    <p className="text-4xl font-black font-mono text-white tracking-tighter uppercase">{lastAction.action_type}</p>
                    <div className="flex items-center gap-4 mt-6 pt-4 border-t border-white/5">
                      <div className="flex items-center gap-2"><Target className="w-4 h-4 text-high" /><span className="text-xs font-mono text-slate-300">{lastAction.target}</span></div>
                      <div className="ml-auto px-3 py-1 bg-brand/20 rounded-full border border-brand/30"><span className="text-[10px] font-black text-brand uppercase tracking-widest">Step {(lastAction.step || 0) + 1}</span></div>
                    </div>
                  </div>
                  <div className="space-y-4">
                    <div className="flex items-center justify-between">
                      <p className="text-[11px] text-slate-400 font-black uppercase tracking-widest">Multi-Persona Reasoning Trace</p>
                    </div>
                    <div className="p-4 bg-white/[0.04] rounded-2xl border border-white/10 leading-relaxed text-xs space-y-3">
                        <div>
                          <span className="text-[10px] font-bold text-brand uppercase tracking-widest">Strategy:</span> {lastAction.strategy || 'N/A'} <span className="text-[10px] font-bold text-brand uppercase tracking-widest ml-4">Tactic:</span> {lastAction.tactic || 'N/A'}
                        </div>
                        <div className="italic text-slate-300">"{lastAction.reasoning}"</div>
                        {lastAction.persona_evaluations && (
                          <div className="mt-4 pt-4 border-t border-white/10 grid grid-cols-1 gap-2">
                             <div className="flex justify-between items-center"><span className="text-[9px] text-slate-400 uppercase">Analyst</span><span className="text-brand font-mono">{lastAction.persona_evaluations.analyst?.score || 0}</span></div>
                             <div className="flex justify-between items-center"><span className="text-[9px] text-slate-400 uppercase">Hunter</span><span className="text-brand font-mono">{lastAction.persona_evaluations.hunter?.score || 0}</span></div>
                             <div className="flex justify-between items-center"><span className="text-[9px] text-slate-400 uppercase">Responder</span><span className="text-brand font-mono">{lastAction.persona_evaluations.responder?.score || 0}</span></div>
                          </div>
                        )}
                    </div>
                  </div>
                  <div className="mt-auto pt-6 border-t border-white/5 flex items-center gap-2">
                       <Zap className="w-4 h-4 text-brand" /><span className="text-2xl font-black text-white">{lastAction.step_score?.toFixed(3) || 0}</span><span className="text-[10px] text-slate-500 font-bold uppercase ml-2 tracking-widest">Cumulative Policy Reward</span>
                  </div>
               </div>
              ) : isInactive ? (
                <div className="flex-1 flex flex-col items-center justify-center text-slate-600 gap-6">
                  <div className="p-4 bg-brand/5 border border-brand/20 rounded-xl text-center">
                    <p className="text-brand text-xs font-bold uppercase mb-2">SOC System Disengaged</p>
                    <p className="text-[10px] text-slate-500 max-w-[200px]">The neural defensive layer is waiting for an initial reset to begin monitoring the environment.</p>
                  </div>
                  <button 
                    onClick={() => resetEnvironment('task_02')}
                    className="px-8 py-3 bg-brand text-white font-black rounded-xl text-xs hover:bg-brand/80 transition-all shadow-xl shadow-brand/20 flex items-center gap-2"
                  >
                    <Zap className="w-4 h-4" />
                    INITIALIZE DEFENSE
                  </button>
                </div>
              ) : (
                <div className="flex-1 flex flex-col items-center justify-center text-slate-600 gap-6">
                  <div className="w-20 h-20 border-8 border-slate-900 border-t-brand rounded-full animate-spin"></div>
                  <p className="tracking-[0.4em] uppercase text-[10px] font-black text-slate-500 animate-pulse">Waiting for AI Inference...</p>
                </div>
              )}
           </div>
        </div>

        {/* Bottom Battle Row: SIEM & TERMINAL (Perfect Symmetry) */}
        <div className="col-span-12 grid grid-cols-12 gap-6">
           {/* Security Intelligence Feed */}
           <div className="col-span-12 lg:col-span-7 h-[500px] bg-soc-card border border-soc-border rounded-2xl p-6 shadow-xl flex flex-col overflow-hidden">
             <div className="flex items-center justify-between mb-6 border-b border-white/5 pb-4">
               <div className="flex items-center gap-3">
                 <History className="w-5 h-5 text-slate-500" />
                 <h2 className="text-[10px] font-black uppercase tracking-[0.3em] text-slate-400">Security Intelligence Feed</h2>
               </div>
             </div>
             <div className="flex-1 overflow-auto custom-scroll pr-2">
               <table className="w-full text-left text-[10px] font-mono border-separate border-spacing-y-2">
                 <thead className="sticky top-0 bg-soc-card text-slate-500 z-20">
                  <tr><th className="p-2 w-24">TIMESTAMP</th><th className="p-2 w-32">EVENT TYPE</th><th className="p-2 w-28">SOURCE</th><th className="p-2 w-20">SEV</th><th className="p-2">HOSTNAME</th></tr>
                </thead>
                <tbody>
                  {state?.logs?.slice().reverse().map((log, i) => (
                    <tr key={i} className="bg-slate-800/10 hover:bg-slate-800/40 transition-colors">
                      <td className="p-2 text-slate-500 border-l border-white/5">{log.timestamp?.split('T')[1]?.split('.')[0] || '---'}</td>
                      <td className="p-2 text-slate-200 font-bold">{log.event_type}</td>
                      <td className="p-2 text-slate-400">{log.source_ip || '---'}</td>
                      <td className={`p-2 font-bold ${getSeverityColor(log.severity)}`}>{log.severity?.substring(0,4)}</td>
                      <td className="p-2 text-slate-400 border-r border-white/5">{log.hostname}</td>
                    </tr>
                  ))}
                  {(!state?.logs || state.logs.length === 0) && (
                    <tr><td colSpan="5" className="p-10 text-center text-slate-600 italic">Listening for live intrusion events...</td></tr>
                  )}
                </tbody>
              </table>
             </div>
           </div>

           {/* Secure Kernel Log */}
           <div className="col-span-12 lg:col-span-5 h-[500px] bg-black border border-soc-border rounded-2xl p-6 font-mono text-[11px] flex flex-col shadow-2xl relative overflow-hidden">
             <div className="flex items-center justify-between mb-6 pb-4 border-b border-white/10">
               <div className="flex items-center gap-3"><Terminal className="w-4 h-4 text-slate-500" /><span className="text-white font-black uppercase tracking-widest text-[10px]">Secure Kernel Log v4.0</span></div>
             </div>
             <div className="flex-1 overflow-y-auto custom-scroll pr-2 space-y-6">
                {actionHistory.slice().reverse().map((act, i) => (
                  <div key={i} className="border-l-2 border-brand/20 pl-4 py-1 animate-in fade-in slide-in-from-left-2 transition-all">
                    <div className="flex items-center gap-4 text-slate-600 mb-2">
                      <span className="text-[9px] bg-slate-900 px-2 py-1 rounded border border-white/5">T+{state?.episode_elapsed_s || 0}s</span>
                      <span className="font-bold text-green-500 uppercase tracking-tighter">EXEC::ENFORCED</span>
                    </div>
                    <div className="text-slate-100 uppercase font-black text-xs">DISPATCHED: {act.action_type} &rarr; {act.target}</div>
                    <div className="text-slate-500 font-light mt-3 bg-white/[0.03] p-3 rounded-lg border border-white/5">$ sudo iptables -A INPUT -s {act.target} -j DROP --comment "AutoSec_Policy"</div>
                  </div>
                ))}
                {actionHistory.length === 0 && <div className="text-slate-700 italic py-10 text-center">{isInactive ? "System awaiting kernel initialization." : "No kernel events recorded in this session."}</div>}
                <div className="w-2 h-4 bg-brand/50 animate-pulse mt-4 shadow-[0_0_8px_#0ea5e9]"></div>
             </div>
           </div>
        </div>
      </main>
    </div>
  );
};

const StatCard = ({ label, value, icon, sub }) => (
  <div className="p-4 bg-soc-card border border-soc-border rounded-xl">
    <div className="flex items-center justify-between mb-2">
      <span className="text-[10px] text-slate-500 uppercase font-bold tracking-wider">{label}</span>
      {icon}
    </div>
    <div className="text-2xl font-bold text-slate-100">{value}</div>
    <div className="text-[10px] text-slate-400 mt-1">{sub}</div>
  </div>
);

const KillChainTracker = ({ currentStage }) => {
  const STAGES = ['reconnaissance', 'initial_access', 'privilege_escalation', 'lateral_movement', 'exfiltration'];
  const isBenign = currentStage?.toLowerCase() === 'benign';
  
  // Find the index of the current stage
  const currentStageIdx = STAGES.indexOf(currentStage?.toLowerCase());

  return (
    <div className="relative flex justify-between">
       <div className="absolute top-1/2 left-0 right-0 h-0.5 bg-soc-border -translate-y-1/2 -z-0"></div>
       
       {/* Normal/Monitoring State indicator */}
       {isBenign && (
         <div className="absolute -left-2 -top-8 flex items-center gap-2 animate-pulse">
            <Shield className="w-3 h-3 text-success" />
            <span className="text-[9px] font-black text-success uppercase tracking-widest">System Monitoring: Normal</span>
         </div>
       )}

       {STAGES.map((stage, idx) => {
         const isActive = !isBenign && idx <= currentStageIdx;
         const isCurrent = !isBenign && idx === currentStageIdx;
         return (
           <div key={stage} className="relative z-10 flex flex-col items-center gap-2 group cursor-help">
             <div className={`w-8 h-8 rounded-full flex items-center justify-center border-2 transition-all ${
               isCurrent ? 'bg-brand border-brand shadow-[0_0_15px_rgba(14,165,233,0.5)] scale-110' : 
               isActive ? 'bg-success border-success' : 'bg-soc-card border-soc-border'
             }`}>
                {isActive && <div className="w-2 h-2 bg-white rounded-full"></div>}
                {isBenign && idx === 0 && <div className="w-full h-full rounded-full border border-success/30 animate-ping absolute"></div>}
             </div>
             <span className={`text-[9px] uppercase font-bold tracking-tighter ${isActive ? 'text-slate-200' : 'text-slate-500'}`}>
               {stage.replace('_', ' ')}
             </span>

             {/* Tooltip */}
             <div className="absolute bottom-full left-1/2 -translate-x-1/2 mb-2 p-2 bg-slate-800 border border-slate-700 rounded text-[10px] w-32 opacity-0 group-hover:opacity-100 transition-opacity hidden sm:block pointer-events-none">
                Goal of {stage}: {getStageDesc(stage)}
             </div>
           </div>
         );
       })}
    </div>
  );
}

const getSeverityColor = (sev) => {
  if (sev === 'CRITICAL') return 'text-critical';
  if (sev === 'HIGH') return 'text-high';
  if (sev === 'MEDIUM') return 'text-medium';
  return 'text-low';
}

const getStageDesc = (stage) => {
  const descs = {
    reconnaissance: "Gathering info on the network.",
    initial_access: "Gaining a foothold via login.",
    privilege_escalation: "Becoming root/admin on a host.",
    lateral_movement: "Moving to targets like dc-01.",
    exfiltration: "Stealing sensitive corporate data."
  };
  return descs[stage] || "";
}

export default Dashboard;
