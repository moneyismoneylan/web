import os
import sys
import types
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
import sqlglot
from sqli_hunter.scanner import Scanner


def test_graph_transformer_score():
    scanner = Scanner(None, types.SimpleNamespace(), {}, None, debug=False)
    ast = sqlglot.parse_one("SELECT 1 UNION SELECT 2")
    score = scanner.graph_scorer.score(ast)
    assert 0.0 <= score <= 1.0
