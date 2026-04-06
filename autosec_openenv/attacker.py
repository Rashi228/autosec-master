"""
attacker.py — Adversarial Attacker Engine
========================================
Simulates a human or AI attacker targeting internal assets.
Moves through the Cyber Kill Chain based on host visibility.
"""

import random
from typing import List, Dict, Any, Optional
from autosec_openenv.models import AttackAction, AttackType, SystemState

class AdversarialAttacker:
    """
    Simulates a goal-oriented attacker attempting to compromise the network.
    """

    def __init__(self, hosts: List[str]):
        self.hosts = hosts
        self.compromised_hosts = set()
        self.source_ip = f"194.165.{random.randint(1,254)}.{random.randint(1,254)}"
        self.current_stage = AttackType.BRUTE_FORCE

    def decide_move(self, state: SystemState) -> Optional[AttackAction]:
        """
        Determines the next move based on current containment state.
        """
        # If attacker is blocked, no move possible
        if self.source_ip in state.blocked_ips:
            return None

        # 1. Target Discovery
        available_targets = [h for h in self.hosts if h not in state.isolated_hosts]
        if not available_targets:
            return None

        # 2. Logic: Move through Kill Chain
        if not self.compromised_hosts:
            # Stage: Initial Access
            target = random.choice(available_targets)
            action = AttackAction(
                attack_type=AttackType.BRUTE_FORCE,
                target_host=target,
                source_ip=self.source_ip,
                reasoning=f"Attempting initial brute-force on {target}."
            )
            self.compromised_hosts.add(target)
            return action

        elif len(self.compromised_hosts) < 3:
            # Stage: Lateral Movement
            pivot = random.choice(list(self.compromised_hosts))
            next_target = random.choice(available_targets)
            if next_target not in self.compromised_hosts:
                action = AttackAction(
                    attack_type=AttackType.LATERAL_MOVEMENT,
                    target_host=next_target,
                    source_ip=self.source_ip,
                    reasoning=f"Pivoting from {pivot} to {next_target}."
                )
                self.compromised_hosts.add(next_target)
                return action

        # Stage: Data Exfiltration
        target = random.choice(list(self.compromised_hosts))
        return AttackAction(
            attack_type=AttackType.DATA_EXFILTRATION,
            target_host=target,
            source_ip=self.source_ip,
            reasoning=f"Exfiltrating data from compromised host {target}."
        )

def get_attacker_move(state: SystemState, hosts: List[str]) -> Optional[AttackAction]:
    """Helper for the environment engine."""
    attacker = AdversarialAttacker(hosts)
    return attacker.decide_move(state)
