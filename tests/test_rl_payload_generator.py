import os
import sys
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from sqli_hunter.rl_payload_generator import RLPayloadGenerator


def test_rl_payload_ordering():
    gen = RLPayloadGenerator(epsilon=0.0)
    techniques = [{"name": "A"}, {"name": "B"}]
    gen.update("B", 1.0)
    ordered = [t["name"] for t in gen.choose(techniques)]
    assert ordered[0] == "B"
