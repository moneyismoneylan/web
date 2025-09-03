import os
import sys
from unittest.mock import MagicMock, patch

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from sqli_hunter.waf_detector import WafDetector

MOCK_SIGNATURES = {
    "TestJA3": {
        "ja3": "abcd1234",
        "min_matches": 1
    }
}

@patch("sqli_hunter.waf_detector.WAF_SIGNATURES", MOCK_SIGNATURES)
def test_ja3_fingerprint_detection():
    detector = WafDetector(MagicMock(), MagicMock())
    features = {
        "body": "ok",
        "headers": {},
        "cookies": set(),
        "ja3": "abcd1234"
    }
    assert detector._predict_waf(features) == "TestJA3"
