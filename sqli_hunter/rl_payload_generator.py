# -*- coding: utf-8 -*-
"""Reinforcement learning inspired payload generator.

This module implements a tiny Q-learning like mechanism to prioritise
payloads that previously yielded positive results.
"""
from __future__ import annotations
import random
from typing import List, Dict


class RLPayloadGenerator:
    """Tiny reinforcement learning helper for payload selection.

    The class prefers successful techniques by assigning rewards.  When the
    optional :mod:`stable_baselines3` library is available, a small DQN model is
    instantiated to illustrate how a deep RL agent could be integrated.  The
    heavyweight dependency is entirely optional; the tests run using the light
    weight Q-learning fallback implemented here.
    """

    def __init__(self, epsilon: float = 0.2, learning_rate: float = 0.1):
        self.epsilon = epsilon
        self.learning_rate = learning_rate
        self.q_table: Dict[str, float] = {}
        try:  # pragma: no cover - optional heavy dependency
            from stable_baselines3 import DQN
            import gymnasium as gym

            class _DummyEnv(gym.Env):
                def __init__(self):
                    super().__init__()
                    self.observation_space = gym.spaces.Discrete(1)
                    self.action_space = gym.spaces.Discrete(1)

                def reset(self, *, seed=None, options=None):
                    return 0, {}

                def step(self, action):
                    return 0, 0.0, True, False, {}

            self._dqn = DQN("MlpPolicy", _DummyEnv(), verbose=0)
        except Exception:  # library missing
            self._dqn = None

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
        if self._dqn:  # pragma: no cover - optional path
            # A real implementation would use the reward to train the agent.
            pass
