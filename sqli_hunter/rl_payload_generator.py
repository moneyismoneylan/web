# -*- coding: utf-8 -*-
"""Reinforcement learning inspired payload generator.

This module implements a tiny Q-learning like mechanism to prioritise
payloads that previously yielded positive results.
"""
from __future__ import annotations
import random
from typing import List, Dict


class RLPayloadGenerator:
    def __init__(self, epsilon: float = 0.2, learning_rate: float = 0.1):
        self.epsilon = epsilon
        self.learning_rate = learning_rate
        self.q_table: Dict[str, float] = {}

    def choose(self, techniques: List[dict]) -> List[dict]:
        """Returns techniques ordered based on learnt rewards."""
        for tech in techniques:
            self.q_table.setdefault(tech["name"], 0.0)
        if random.random() < self.epsilon:
            random.shuffle(techniques)
            return techniques
        return sorted(techniques, key=lambda t: self.q_table[t["name"]], reverse=True)

    def update(self, technique: str, reward: float) -> None:
        """Updates the Q-value for a technique based on observed reward."""
        current = self.q_table.get(technique, 0.0)
        self.q_table[technique] = current + self.learning_rate * (reward - current)
