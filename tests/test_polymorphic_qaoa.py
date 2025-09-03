import os
import sys
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from sqli_hunter.polymorphic_engine import PolymorphicEngine


def test_qaoa_optimizer():
    engine = PolymorphicEngine(max_transformations=1)
    payloads = ["a", "aaaa", "aa"]
    best = engine.select_optimal(payloads)
    assert best == "aaaa"
