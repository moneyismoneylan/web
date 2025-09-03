import os
import sys
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from sqli_hunter.waf_detector import WafDetector


class DummyResponse:
    def __init__(self, headers=None, text=""):
        self.headers = headers or {}
        self.text = text


class DummyCookie:
    def __init__(self, name):
        self.name = name


def test_ja3_fingerprint_detection():
    detector = WafDetector(None, None)
    resp = DummyResponse()
    cookies = []
    assert detector._check_signatures_headless(resp, cookies, ja3_hash="abcd1234") == "TestJA3"
