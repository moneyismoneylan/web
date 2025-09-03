import types
import os
import sys
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from sqli_hunter.scanner import Scanner
from simhash import Simhash


def test_ml_scoring():
    scanner = Scanner(None, types.SimpleNamespace(), {}, None, debug=False)
    response = "SELECT 1 UNION SELECT SLEEP(1)"
    baseline_hash = Simhash(response)
    score, _ = scanner._analyze_response_for_anomalies(200, baseline_hash, 200, response, 0.1, 0.2)
    assert score > 0.3
