"""
personas.py — Multi-Persona Evaluation Engine
=============================================
Evaluates agent actions from the perspective of three distinct SOC personas:
1. SOC Analyst (Triage & Alerts)
2. Threat Hunter (Correlation & Pattern)
3. Incident Responder (Containment Correctness)
"""

from typing import Dict, Any, List
from autosec_openenv.models import Action, ActionType, SystemState, SecurityLog

class MultiPersonaEvaluator:
    def __init__(self):
        pass

    def evaluate_action(self, action: Action, state: SystemState, logs: List[SecurityLog]) -> Dict[str, Any]:
        """
        Calculates scores (0.0 to 1.0) and generates explanations for each persona.
        """
        
        # 1. SOC Analyst: Focuses on quick triage and active threats
        analyst_score = 0.5
        analyst_reasoning = "Neutral triage assessment."
        if action.action_type in [ActionType.BLOCK_IP, ActionType.ISOLATE_HOST, ActionType.TERMINATE_PROCESS]:
            if state.active_threats > 0:
                analyst_score = 0.95
                analyst_reasoning = "Decisive and correct intervention during an active threat episode."
            else:
                analyst_score = 0.15
                analyst_reasoning = "Pointless intervention; no active threats were detected in the environment."
        elif action.action_type == ActionType.MONITOR:
            if state.active_threats == 0:
                analyst_score = 0.90
                analyst_reasoning = "Vigilant monitoring of a secure environment. No intervention needed."
            else:
                analyst_score = 0.25
                analyst_reasoning = "Passive monitoring while malicious indicators are present. Possible triage failure."

        # 2. Threat Hunter: Focuses on correlation and logs
        hunter_score = 0.5
        hunter_reasoning = "Standard log alignment."
        malicious_logs = [log for log in logs if log.is_malicious]
        if action.action_type in [ActionType.NO_ACTION, ActionType.MONITOR] and malicious_logs:
            hunter_score = 0.2
            hunter_reasoning = "Significant oversight: Indicators of compromise detected in SIEM logs were ignored."
        elif action.target and any(action.target in l.raw_log for l in malicious_logs):
            hunter_score = 1.0
            hunter_reasoning = "High precision: The defensive target directly correlates with malicious telemetry."
        elif action.action_type == ActionType.MONITOR and not malicious_logs:
            hunter_score = 0.95
            hunter_reasoning = "Correct deduction: No malicious patterns detected in the current window."
            
        # 3. Incident Responder: Focuses on containment effectiveness & blast radius
        responder_score = 0.5
        responder_reasoning = "Standard containment posture."
        if action.action_type == ActionType.ISOLATE_HOST and action.target == "dc-01":
            responder_score = 0.05
            responder_reasoning = "CRITICAL RISK: Indiscriminate isolation of the Domain Controller. High business impact."
        elif action.action_type in [ActionType.BLOCK_IP, ActionType.TERMINATE_PROCESS, ActionType.ISOLATE_HOST]:
            if state.active_threats > 0:
                responder_score = 0.95
                responder_reasoning = "Surgical containment successfully minimized the incident blast radius."
            else:
                responder_score = 0.4
                responder_reasoning = "Unnecessary containment action in a stable system."
        elif action.action_type == ActionType.MONITOR and state.active_threats == 0:
            responder_score = 0.95
            responder_reasoning = "Optimal posture: maintaining system availability in the absence of verified threats."

        # Compute Weights
        final_score = (analyst_score * 0.3) + (hunter_score * 0.3) + (responder_score * 0.4)

        return {
            "final_persona_score": final_score,
            "personas": {
                "analyst": {"score": analyst_score, "explanation": analyst_reasoning},
                "hunter": {"score": hunter_score, "explanation": hunter_reasoning},
                "responder": {"score": responder_score, "explanation": responder_reasoning}
            }
        }
