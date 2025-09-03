# -*- coding: utf-8 -*-
"""
Polymorphic Payload Engine.

This module is responsible for generating variations of a base payload
to evade signature-based WAFs.
"""
import random
from typing import Dict, List
from sqli_hunter.tamper import TAMPER_FUNCTIONS

try:  # Optional heavy dependency
    from transformers import AutoTokenizer, AutoModelForCausalLM  # type: ignore
except Exception:  # pragma: no cover
    AutoTokenizer = None  # type: ignore
    AutoModelForCausalLM = None  # type: ignore


import torch
import numpy as np


class DenoisingModel:
    """
    A mock denoising model that simulates a Transformer-based model.
    It uses heuristics to predict the original token from a corrupted input.
    """
    def __init__(self, vocab: List[str]):
        self.vocab = vocab
        self.sql_keywords = {"select", "union", "from", "where", "and", "or", "order", "by"}

    def predict(self, corrupted_payload: List[str], timestep: int) -> List[str]:
        """Predicts the original tokens. More 'confident' at lower timesteps."""
        denoised = []
        # The model is more likely to change tokens at higher timesteps (more noise)
        denoising_strength = 1.0 - (timestep / 10.0) # Simple linear scale

        for token in corrupted_payload:
            if token == "[MASK]" and random.random() < denoising_strength:
                # Heuristic: guess a plausible keyword
                denoised.append(random.choice(list(self.sql_keywords)))
            else:
                # Keep the original token
                denoised.append(token)
        return denoised

class DiffusionPayloadGenerator:
    """
    A discrete diffusion model for generating SQLi payloads.
    It works by corrupting a payload with [MASK] tokens (forward process)
    and then learning a model to reverse the process (denoising).
    """
    def __init__(self, timesteps: int = 10):
        self.timesteps = timesteps
        self.vocab = [
            'select', 'from', 'where', 'and', 'or', 'union', 'order', 'by', '1=1', "'",
            ' ', '(', ')', ',', '*', '`', '"', '`', '=', '<', '>',
            '[MASK]'
        ]
        self.denoising_model = DenoisingModel(self.vocab)
        self.taint_feedback = None

    def train(self, feedback: str):
        """Stores taint feedback to influence generation."""
        # In a real model, this would be used to fine-tune the denoising network.
        # Here, we'll just store it to guide the initial payload.
        self.taint_feedback = feedback.lower().split()

    def _corrupt(self, payload: List[str], t: int) -> List[str]:
        """Applies corruption (masking) based on the timestep t."""
        if t == 0: return payload

        corruption_rate = t / self.timesteps
        corrupted = []
        for token in payload:
            if random.random() < corruption_rate:
                corrupted.append("[MASK]")
            else:
                corrupted.append(token)
        return corrupted

    def generate(self, base_payload: str, n: int = 1) -> List[str]:
        """Generates payload variations using the reverse diffusion process."""
        variations = []

        initial_tokens = base_payload.lower().split()
        if self.taint_feedback:
            # Use taint feedback to enrich the initial payload
            initial_tokens += self.taint_feedback

        for _ in range(n):
            # Start with a corrupted version of the payload at a high timestep
            x_t = self._corrupt(initial_tokens, t=self.timesteps - 1)

            # Iteratively denoise
            for t in reversed(range(self.timesteps)):
                x_t = self.denoising_model.predict(x_t, t)

            variations.append(" ".join(x_t))

        return variations


class LLMPromptedMutator:
    """Applies prompt-driven mutations using a tiny language model when available."""

    def __init__(self) -> None:
        self.tokenizer = None
        self.model = None
        if AutoTokenizer and AutoModelForCausalLM:  # pragma: no cover - optional
            try:
                self.tokenizer = AutoTokenizer.from_pretrained(
                    "distilgpt2", local_files_only=True
                )
                self.model = AutoModelForCausalLM.from_pretrained(
                    "distilgpt2", local_files_only=True
                )
            except Exception:
                self.tokenizer = None
                self.model = None

    def mutate(self, prompt: str, payload: str) -> str:
        if self.tokenizer and self.model:
            try:  # pragma: no cover - heavy dependency path
                import torch

                inputs = self.tokenizer(prompt + payload, return_tensors="pt")
                out = self.model.generate(
                    **inputs, max_length=inputs["input_ids"].shape[1] + 8, do_sample=True
                )
                text = self.tokenizer.decode(out[0], skip_special_tokens=True)
                return text[len(prompt):]
            except Exception:
                pass
        return payload[::-1]


try:
    from qiskit.algorithms.optimizers import COBYLA
    IS_QISKIT_AVAILABLE = True
except ImportError:
    IS_QISKIT_AVAILABLE = False


class QAOAOptimizer:
    """
    Selects the optimal payload from a list using a mock QAOA implementation.
    The "quantum" part is simulated with a classical objective function that
    rewards payloads estimated to be highly evasive.
    """
    def __init__(self, payloads: List[str]):
        if not IS_QISKIT_AVAILABLE:
            self.optimizer = None
        else:
            self.optimizer = COBYLA(maxiter=50)
        self.payloads = payloads
        if not self.payloads:
            self.payload_scores = np.array([])
        else:
            self.payload_scores = self._score_payloads()

    def _score_payloads(self) -> np.ndarray:
        """Calculates a heuristic 'evasiveness' score for each payload."""
        scores = []
        for p in self.payloads:
            score = len(p) + len(set(p))
            if 'union' in p.lower() or 'select' in p.lower():
                score *= 1.2
            scores.append(score)
        return np.array(scores)

    def _objective_function(self, params) -> float:
        """
        A mock objective function that simulates running a QAOA circuit.
        It uses the classical scores as a proxy for the cost.
        """
        num_payloads = len(self.payloads)
        param_sum = np.sum(params)
        index = int(np.floor(np.abs(np.sin(param_sum) * (num_payloads - 1))))
        cost = 1.0 / (self.payload_scores[index] + 1e-6)
        return cost

    def select(self) -> str:
        """Selects the best payload using the classical optimization part of QAOA."""
        if not self.payloads:
            return ""
        if not self.optimizer:
            return max(self.payloads, key=len)

        initial_params = np.random.rand(2)

        result = self.optimizer.minimize(
            fun=self._objective_function,
            x0=initial_params,
        )

        optimal_params = result.x
        final_param_sum = np.sum(optimal_params)
        best_index = int(np.floor(np.abs(np.sin(final_param_sum) * (len(self.payloads) - 1))))

        return self.payloads[best_index]


class PolymorphicEngine:
    """Generates polymorphic variations of a given payload."""

    def __init__(self, max_transformations: int = 3):
        self.max_transformations = max_transformations
        self.tamper_functions = list(TAMPER_FUNCTIONS.values())

    def _apply_grammar(
        self,
        payload: str,
        grammar: Dict[str, List[str]],
        taint_map: Dict[str, str] | None,
    ) -> str:
        """Replaces grammar tokens using grammar rules and optional taint map."""
        if not grammar:
            return payload
        for token, expansions in grammar.items():
            while token in payload:
                replacement = (
                    taint_map.get(token) if taint_map and token in taint_map else random.choice(expansions)
                )
                payload = payload.replace(token, replacement, 1)
        return payload

    def generate(
        self,
        base_payload: str,
        num_variations: int = 10,
        grammar: Dict[str, List[str]] | None = None,
        taint_map: Dict[str, str] | None = None,
        use_diffusion: bool = False,
        prompt: str | None = None,
        use_llm: bool = False,
    ) -> list[str]:
        """Generates polymorphic variations for a given base payload.

        :param base_payload: The base payload to transform. It may contain grammar
            tokens such as <expr> that will be expanded using the grammar rules.
        :param num_variations: Number of variations to generate.
        :param grammar: Optional grammar rules for fuzzing.
        :param taint_map: Optional taint analysis results overriding grammar choices.
        :param use_diffusion: Whether to use the diffusion model for generation.
        :return: A list of transformed payloads.
        """
        variations = set()
        diffusion_gen = DiffusionPayloadGenerator() if use_diffusion else None
        llm = LLMPromptedMutator() if use_llm else None
        if diffusion_gen and taint_map:
            diffusion_gen.train(str(taint_map))

        from sqli_hunter.tamper import TAMPER_FUNCTIONS, MUTUALLY_EXCLUSIVE_TAMPERS

        variations = set()
        tamper_names = list(TAMPER_FUNCTIONS.keys())
        if use_llm:
            llm = LLMPromptedMutator()
        if use_diffusion:
            diffusion_gen = DiffusionPayloadGenerator()
            if taint_map:
                diffusion_gen.train(str(taint_map))

        for _ in range(num_variations):
            num_transformations = random.randint(1, self.max_transformations)
            selected_tamper_names = []
            available_tampers = tamper_names[:]

            # Ensure the number of transformations does not exceed available tampers
            num_transformations = min(num_transformations, len(available_tampers))

            for _ in range(num_transformations):
                if not available_tampers:
                    break

                chosen_tamper = random.choice(available_tampers)
                selected_tamper_names.append(chosen_tamper)
                available_tampers.remove(chosen_tamper)

                for group in MUTUALLY_EXCLUSIVE_TAMPERS:
                    if chosen_tamper in group:
                        for t in group:
                            if t != chosen_tamper and t in available_tampers:
                                available_tampers.remove(t)
                        break

            selected_funcs = [TAMPER_FUNCTIONS[name] for name in selected_tamper_names]

            transformed_payload = self._apply_grammar(base_payload, grammar or {}, taint_map)
            for tamper_func in selected_funcs:
                transformed_payload = tamper_func(transformed_payload)

            if use_llm and llm and prompt:
                transformed_payload = llm.mutate(prompt, transformed_payload)

            variations.add(transformed_payload)
            if use_diffusion and diffusion_gen:
                variations.update(diffusion_gen.generate(transformed_payload, 1))

        return list(variations)

    def select_optimal(self, payloads: List[str]) -> str:
        """Return the payload deemed optimal via the QAOA optimiser."""
        optimizer = QAOAOptimizer(payloads)
        return optimizer.select()
