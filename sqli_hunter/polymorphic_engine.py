# -*- coding: utf-8 -*-
"""
Polymorphic Payload Engine.

This module is responsible for generating variations of a base payload
to evade signature-based WAFs.
"""
import random
from sqli_hunter.tamper import TAMPER_FUNCTIONS

class PolymorphicEngine:
    """
    Generates polymorphic variations of a given payload.
    """
    def __init__(self, max_transformations: int = 3):
        self.max_transformations = max_transformations
        self.tamper_functions = list(TAMPER_FUNCTIONS.values())

    def generate(self, base_payload: str, num_variations: int = 10) -> list[str]:
        """
        Generates a list of polymorphic variations for a given base payload.

        :param base_payload: The base payload to transform.
        :param num_variations: The number of variations to generate.
        :return: A list of transformed payloads.
        """
        variations = set()
        for _ in range(num_variations):
            num_transformations = random.randint(1, self.max_transformations)
            selected_tampers = random.sample(self.tamper_functions, num_transformations)

            transformed_payload = base_payload
            for tamper in selected_tampers:
                transformed_payload = tamper(transformed_payload)

            variations.add(transformed_payload)

        return list(variations)
