import os
import sys
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from sqli_hunter.polymorphic_engine import PolymorphicEngine


def test_grammar_and_taint():
    engine = PolymorphicEngine(max_transformations=1)
    grammar = {"<field>": ["username", "password"], "<id>": ["1", "2"]}
    taint = {"<field>": "email"}
    payloads = engine.generate("SELECT <field> FROM users WHERE id=<id>", num_variations=5, grammar=grammar, taint_map=taint)
    assert any("email" in p.lower() for p in payloads)


def test_gan_generation():
    engine = PolymorphicEngine(max_transformations=1)
    payloads = engine.generate("UNION SELECT 1", num_variations=1, use_gan=True)
    assert len(payloads) >= 1


def test_llm_prompted_mutation_fallback():
    engine = PolymorphicEngine(max_transformations=1)
    payloads = engine.generate(
        "UNION SELECT 1", num_variations=1, use_llm=True, prompt="mutate"
    )
    assert len(payloads) >= 1
