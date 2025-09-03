# -*- coding: utf-8 -*-
"""WAF Fingerprinting Engine.

This module identifies the Web Application Firewall protecting the target
application. Signatures are loaded from external configuration files and
evaluated using multiple criteria (headers, cookies and body) to reduce
false positives. Additionally, a lightweight graph neural network model can
be used to learn WAF behaviour from response features.
"""
from __future__ import annotations

from playwright.async_api import BrowserContext, Error
import re
import asyncio
import cloudscraper
from urllib.parse import urlparse
from sqli_hunter.bootstrap import load_config

try:  # Optional TLS fingerprinting dependency
    import ja3
except Exception:  # pragma: no cover - library may be missing
    ja3 = None  # type: ignore

try:  # Optional graph dependencies
    import networkx as nx  # type: ignore
    from torch_geometric.utils import from_networkx  # type: ignore
    from torch_geometric.nn import TransformerConv  # type: ignore
    import torch
except Exception:  # pragma: no cover - heavy deps absent
    nx = None  # type: ignore
    from_networkx = None  # type: ignore
    TransformerConv = None  # type: ignore
    torch = None  # type: ignore


class GradientBoostClassifier:
    """Very small gradient-boosting-like classifier.

    This is **not** a real gradient boosting implementation.  It simply
    aggregates feature matches with different weights.  The class mirrors the
    interface of scikit-learn's estimators so that it can be swapped out with a
    proper model when running in a full environment.
    """

    def predict(self, features: dict, signatures: dict) -> str | None:
        best_name, best_score = None, 0.0
        for waf_name, sig in signatures.items():
            score = 0.0
            for header, pattern in sig.get("headers", {}).items():
                if header.lower() in features["headers"] and re.search(
                    pattern, features["headers"][header.lower()], re.IGNORECASE
                ):
                    score += 1.0
            for cookie in sig.get("cookies", []):
                if any(c.startswith(cookie) for c in features["cookies"]):
                    score += 1.0
            for pattern in sig.get("body", []):
                if re.search(pattern, features["body"], re.IGNORECASE):
                    score += 1.0
            if sig.get("ja3") and sig.get("ja3") == features.get("ja3"):
                score += 2.0  # TLS fingerprints are strong signals
            if score > best_score:
                best_name, best_score = waf_name, score
        return best_name if best_score >= 2.0 else None


# A database of WAF signatures loaded from configuration.
WAF_SIGNATURES = load_config("waf_fingerprints")
BOOST_MODEL = GradientBoostClassifier()


class GraphNNEvaluator:
    """Very small GNN scorer combining features into a graph."""

    def __init__(self) -> None:
        if nx and TransformerConv and torch:  # pragma: no cover - optional
            try:
                self.model = TransformerConv(1, 1, heads=1)
            except Exception:
                self.model = None
        else:
            self.model = None

    def predict(self, features: dict) -> float:
        if not (self.model and nx and from_networkx and torch):
            return 0.0
        g = nx.Graph()
        for idx, (k, v) in enumerate(features.items()):
            g.add_node(idx, label=k, value=float(len(str(v))))
            if idx:
                g.add_edge(idx - 1, idx)
        try:  # pragma: no cover - optional
            data = from_networkx(g)
            x = torch.ones((g.number_of_nodes(), 1))
            out = self.model(x, data.edge_index)
            return float(out.mean().abs().item())
        except Exception:
            return 0.0


GNN_EVALUATOR = GraphNNEvaluator()

MALICIOUS_PROBE_URL = "/?s=<script>alert('XSS')</script>"


class WafDetector:
    """Detects a WAF by sending a malicious probe and checking the response."""

    def __init__(self, browser_context: BrowserContext, scraper: cloudscraper.CloudScraper):
        self.context = browser_context
        self.scraper = scraper

    def _check_signatures_headless(self, response, cookies, ja3_hash: str | None = None) -> str | None:
        """Compare response/tls features against the WAF signature DB."""

        if not response:
            return None

        headers = {k.lower(): v for k, v in response.headers.items()}
        cookie_names = {c.name for c in cookies}
        body = response.text

        for waf_name, signatures in WAF_SIGNATURES.items():
            matches = 0

            for header, pattern in signatures.get("headers", {}).items():
                header_lower = header.lower()
                if header_lower in headers and re.search(pattern, headers[header_lower], re.IGNORECASE):
                    matches += 1
                    break

            for cookie_pattern in signatures.get("cookies", []):
                if any(c.startswith(cookie_pattern) for c in cookie_names):
                    matches += 1
                    break

            body_patterns = signatures.get("body")
            if body_patterns:
                for p in body_patterns:
                    if re.search(p, body, re.IGNORECASE):
                        matches += 1
                        break

            if signatures.get("ja3") and ja3_hash and signatures["ja3"] == ja3_hash:
                matches += 1

            min_matches = signatures.get("min_matches", 2)
            if matches >= min_matches:
                return waf_name

        features = {"headers": headers, "cookies": cookie_names, "body": body, "ja3": ja3_hash}
        gnn_score = GNN_EVALUATOR.predict(features)
        prediction = BOOST_MODEL.predict(features, WAF_SIGNATURES)
        if prediction and (GNN_EVALUATOR.model is None or gnn_score >= 0.1):
            return prediction
        return None

    async def _transfer_cookies_to_browser_context(self, scraper: cloudscraper.CloudScraper, url: str):
        """Transfers cookies from cloudscraper to the Playwright browser context."""
        parsed_url = urlparse(url)
        cookies_to_add = []
        for cookie in scraper.cookies:
            cookies_to_add.append({
                "name": cookie.name,
                "value": cookie.value,
                "domain": cookie.domain or parsed_url.netloc,
                "path": cookie.path or "/",
                "expires": cookie.expires,
                "httpOnly": cookie.has_nonstandard_attr('HttpOnly'),
                "secure": cookie.secure,
            })
        if cookies_to_add:
            await self.context.add_cookies(cookies_to_add)

    async def check_waf(self, base_url: str, report_file: str = "waf_report.json") -> str | None:
        """Probes the target to identify the WAF using a headless client."""
        print("[*] Starting WAF fingerprinting...")
        waf_name = None

        try:
            response = await asyncio.to_thread(self.scraper.get, base_url, timeout=15)
            await self._transfer_cookies_to_browser_context(self.scraper, base_url)
            waf_name = self._check_signatures_headless(response, self.scraper.cookies)
            if waf_name:
                print(f"[+] WAF Detected on initial request: {waf_name}")
        except Exception:
            pass

        if not waf_name:
            probe_url = base_url.rstrip('/') + MALICIOUS_PROBE_URL
            try:
                response = await asyncio.to_thread(self.scraper.get, probe_url, timeout=15)
                await self._transfer_cookies_to_browser_context(self.scraper, probe_url)
                waf_name = self._check_signatures_headless(response, self.scraper.cookies)
                if waf_name:
                    print(f"[+] WAF Detected after malicious probe: {waf_name}")
            except Exception:
                pass

        if not waf_name:
            print("[-] No specific WAF detected.")

        # Persist a small JSON report for the orchestrator/GUI layer.
        try:
            import json

            with open(report_file, "w", encoding="utf-8") as f:
                json.dump({"waf": waf_name}, f, indent=2)
        except Exception:
            pass

        return waf_name
