import os
import sys
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from sqli_hunter.polymorphic_engine import PolymorphicEngine


def test_gan_taint_feedback():
    engine = PolymorphicEngine(max_transformations=1)
    grammar = {'<col>': ['a', 'b']}
    taint = {'<col>': 'secret'}
    payloads = engine.generate('SELECT <col>', num_variations=2, grammar=grammar, taint_map=taint, use_gan=True)
    assert any('secret' in p for p in payloads)
