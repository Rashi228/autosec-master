"""
adaptive_attacker.py — Dynamic Adversarial Engine
=================================================
Attacker that modifies its strategy based on the agent's failure patterns.
"""

import random
from typing import List, Optional
from autosec_openenv.models import AttackAction, AttackType, SystemState

class AdaptiveAttacker:
    def __init__(self, hosts: List[str]):
        self.hosts = hosts
        self.compromised_hosts = set()
        self.source_ip = f"194.165.{random.randint(1,254)}.{random.randint(1,254)}"
        
        # Adaptive tracking
        self.agent_failures = {
            "missed_brute_force": 0,
            "missed_lateral": 0,
            "missed_exfil": 0
        }

    def register_agent_failure(self, failure_type: str):
        """Called when the agent fails to block an attack."""
        if failure_type in self.agent_failures:
            self.agent_failures[failure_type] += 1

    def decide_move(self, state: SystemState) -> Optional[AttackAction]:
        if self.source_ip in state.blocked_ips:
            return None

        available_targets = [h for h in self.hosts if h not in state.isolated_hosts]
        if not available_targets:
            return None

        # Probabilistic attack selection based on agent weaknesses
        weights = [
            1.0 + self.agent_failures["missed_brute_force"],
            1.0 + self.agent_failures["missed_lateral"],
            1.0 + self.agent_failures["missed_exfil"]
        ]
        
        if not self.compromised_hosts:
            target = random.choice(available_targets)
            self.compromised_hosts.add(target)
            return AttackAction(
                attack_type=AttackType.BRUTE_FORCE,
                target_host=target,
                source_ip=self.source_ip,
                reasoning="Agent is weak at initial access detection. Proceeding."
            )

        if len(self.compromised_hosts) < 3:
            # Decide whether to lateral move or exfil early based on weights
            if random.random() < (weights[1] / sum(weights)):
                pivot = random.choice(list(self.compromised_hosts))
                next_target = random.choice(available_targets)
                if next_target not in self.compromised_hosts:
                    self.compromised_hosts.add(next_target)
                    return AttackAction(
                        attack_type=AttackType.LATERAL_MOVEMENT,
                        target_host=next_target,
                        source_ip=self.source_ip,
                        reasoning="Exploiting lateral movement weakness."
                    )

        target = random.choice(list(self.compromised_hosts))
        return AttackAction(
            attack_type=AttackType.DATA_EXFILTRATION,
            target_host=target,
            source_ip=self.source_ip,
            reasoning="Extracting data from compromised machine."
        )
