# -*- coding: utf-8 -*-
"""
Polymorphic Payload Engine.

This module is responsible for generating variations of a base payload
to evade signature-based WAFs.
"""
import random
from typing import Dict, List
from sqli_hunter.tamper import TAMPER_FUNCTIONS


class Seq2SeqGANPayloadGenerator:
    """Toy seq2seq GAN used to diversify grammar-based fuzzing.

    The generator accepts feedback strings (e.g. from taint analysis) and
    simply mixes them into the payload before shuffling characters.  The goal
    is to emulate how a seq2seq GAN might learn from data flow information
    without pulling in heavyweight ML dependencies in the training
    environment.
    """

    def __init__(self) -> None:
        self.feedback: str = ""

    def train(self, feedback: str) -> None:
        self.feedback = feedback

    def generate(self, payload: str, n: int = 1) -> List[str]:
        variations = []
        base = payload + self.feedback
        for _ in range(n):
            chars = list(base)
            random.shuffle(chars)
            variations.append("".join(chars))
        return variations

class PolymorphicEngine:
    """
    Generates polymorphic variations of a given payload.
    """
    def __init__(self, max_transformations: int = 3):
        self.max_transformations = max_transformations
        self.tamper_functions = list(TAMPER_FUNCTIONS.values())

    def _apply_grammar(self, payload: str, grammar: Dict[str, List[str]], taint_map: Dict[str, str] | None) -> str:
        """Replaces grammar tokens in the payload using provided grammar rules and
        optional taint analysis results."""
        if not grammar:
            return payload
        for token, expansions in grammar.items():
            while token in payload:
                replacement = taint_map.get(token) if taint_map and token in taint_map else random.choice(expansions)
                payload = payload.replace(token, replacement, 1)
        return payload

    def generate(
        self,
        base_payload: str,
        num_variations: int = 10,
        grammar: Dict[str, List[str]] | None = None,
        taint_map: Dict[str, str] | None = None,
        use_gan: bool = False,
    ) -> list[str]:
        """Generates polymorphic variations for a given base payload.

        :param base_payload: The base payload to transform. It may contain grammar
            tokens such as <expr> that will be expanded using the grammar rules.
        :param num_variations: Number of variations to generate.
        :param grammar: Optional grammar rules for fuzzing.
        :param taint_map: Optional taint analysis results overriding grammar choices.
        :return: A list of transformed payloads.
        """
        variations = set()
        gan = Seq2SeqGANPayloadGenerator() if use_gan else None
        if gan and taint_map:
            gan.train(str(taint_map))
        for _ in range(num_variations):
            num_transformations = random.randint(1, self.max_transformations)
            selected_tampers = random.sample(self.tamper_functions, num_transformations)

            transformed_payload = self._apply_grammar(base_payload, grammar or {}, taint_map)
            for tamper in selected_tampers:
                transformed_payload = tamper(transformed_payload)

            variations.add(transformed_payload)
            if gan:
                variations.update(gan.generate(transformed_payload, 1))

        return list(variations)
