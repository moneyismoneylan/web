# -*- coding: utf-8 -*-
"""Lightweight LSTM-based anomaly classifier stub.

The classifier loads a JSON model definition that contains weighted keywords.
During scoring the AST is stringified and matched against the weighted
keywords to compute an anomaly score between 0 and 1.
"""
from __future__ import annotations
import json
from pathlib import Path
from typing import Any


class LSTMAnomalyClassifier:
    def __init__(self, model_path: Path | None = None):
        self.model_path = model_path or Path(__file__).with_name("lstm_model.json")
        self.model = self._load_model()

    def _load_model(self) -> dict:
        try:
            with open(self.model_path, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            # Fallback to a tiny built‑in model
            return {"keywords": {"union": 0.5, "sleep": 0.7}}

    def score(self, ast: Any) -> float:
        """Scores a SQL AST by looking for weighted keywords."""
        tokens = str(ast).lower()
        score = 0.0
        for kw, weight in self.model.get("keywords", {}).items():
            if kw in tokens:
                score += weight
        return min(score, 1.0)
