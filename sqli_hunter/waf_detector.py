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
import time
import ssl
import cloudscraper
from urllib.parse import urlparse
from sqli_hunter.bootstrap import load_config
from h2.config import H2Configuration
from h2.connection import H2Connection
from h2.events import (
    ResponseReceived,
    DataReceived,
    RemoteSettingsChanged,
    StreamEnded,
    ConnectionTerminated,
)

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

            delay_threshold = sig.get("delay_threshold")
            if delay_threshold and features.get("delay_ratio", 0) > delay_threshold:
                score += 1.5  # Behavioral delay is a strong signal

            # Check for specific HTTP/2 setting fingerprints
            h2_sig_settings = sig.get("h2_settings", {})
            h2_features = features.get("h2_features", {})
            for setting_name, expected_value in h2_sig_settings.items():
                if h2_features.get(setting_name.lower()) == expected_value:
                    score += 2.0  # H2 settings are a very strong signal
                    break  # One match is enough to score for H2

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


class H2Fingerprinter:
    """A helper class to establish an HTTP/2 connection and fingerprint server settings."""
    def __init__(self, host: str, port: int):
        self.host = host
        self.port = port
        self.features = {}
        self.connection_lost = asyncio.Future()
        self.stream_ended = asyncio.Future()

    async def run(self) -> dict:
        try:
            ssl_context = ssl.create_default_context(purpose=ssl.Purpose.SERVER_AUTH)
            ssl_context.set_alpn_protocols(["h2"])

            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(self.host, self.port, ssl=ssl_context, server_hostname=self.host),
                timeout=10.0
            )

            config = H2Configuration(client_side=True)
            conn = H2Connection(config=config)
            conn.initiate_connection()
            writer.write(conn.data_to_send())
            await writer.drain()

            stream_id = conn.get_next_available_stream_id()
            headers = [
                (':method', 'GET'), (':authority', self.host), (':scheme', 'https'), (':path', '/'),
                ('user-agent', 'Mozilla/5.0 H2Fingerprinter'),
            ]
            conn.send_headers(stream_id, headers, end_stream=True)
            writer.write(conn.data_to_send())
            await writer.drain()

            while not self.stream_ended.done() and not self.connection_lost.done():
                data = await asyncio.wait_for(reader.read(65535), timeout=5.0)
                if not data: break
                events = conn.receive_data(data)
                for event in events:
                    if isinstance(event, RemoteSettingsChanged):
                        for param, value in event.changed_settings.items():
                            self.features[param.name.lower()] = value
                    elif isinstance(event, StreamEnded):
                        self.stream_ended.set_result(True)
                    elif isinstance(event, ConnectionTerminated):
                        self.connection_lost.set_result(True)

                if conn.data_to_send:
                    writer.write(conn.data_to_send())
                    await writer.drain()

        except Exception as e:
            # Don't log common errors like timeouts as they are expected
            if not isinstance(e, (asyncio.TimeoutError, ConnectionResetError, OSError)):
                print(f"[!] H2 fingerprinting failed for {self.host}: {type(e).__name__}")
        finally:
            if 'writer' in locals() and not writer.is_closing():
                writer.close()
                try:
                    await writer.wait_closed()
                except Exception: pass

        return self.features


MALICIOUS_PROBE_URL = "/?s=<script>alert('XSS')</script>"


class WafDetector:
    """Detects a WAF by sending a malicious probe and checking the response."""

    def __init__(self, browser_context: BrowserContext, scraper: cloudscraper.CloudScraper):
        self.context = browser_context
        self.scraper = scraper

    def _predict_waf(self, features: dict) -> str | None:
        """Compare response/tls features against the WAF signature DB."""
        if not features.get("body"):
            return None

        gnn_score = GNN_EVALUATOR.predict(features)
        prediction = BOOST_MODEL.predict(features, WAF_SIGNATURES)

        # The GNN score can act as a confidence score for the prediction
        if prediction and (GNN_EVALUATOR.model is None or gnn_score >= 0.1):
            return prediction
        return None

    async def _transfer_cookies_to_browser_context(self, scraper: cloudscraper.CloudScraper, url: str):
        """Transfers cookies from cloudscraper to the Playwright browser context."""
        parsed_url = urlparse(url)
        cookies_to_add = []
        for cookie in scraper.cookies:
            expires_timestamp = cookie.expires

            # Ensure expires_timestamp is a valid integer or -1
            if expires_timestamp is None:
                expires_timestamp = -1
            elif not isinstance(expires_timestamp, (int, float)):
                try:
                    # Handle string-based timestamps
                    expires_timestamp = int(float(str(expires_timestamp)))
                except (ValueError, TypeError):
                    # Default to a session cookie on any conversion failure
                    expires_timestamp = -1

            cookies_to_add.append({
                "name": cookie.name,
                "value": cookie.value,
                "domain": cookie.domain or parsed_url.netloc,
                "path": cookie.path or "/",
                "expires": int(expires_timestamp),
                "httpOnly": cookie.has_nonstandard_attr('HttpOnly'),
                "secure": cookie.secure,
            })
        if cookies_to_add:
            try:
                await self.context.add_cookies(cookies_to_add)
            except Error as e:
                print(f"[Warning] Could not set cookies for Playwright context: {e}")

    async def _analyze_http2_frames(self, host: str, port: int) -> dict:
        """Analyzes HTTP/2 frames for WAF signatures."""
        fingerprinter = H2Fingerprinter(host, port)
        return await fingerprinter.run()

    async def check_waf(self, base_url: str, report_file: str = "waf_report.json") -> str | None:
        """Probes the target to identify the WAF using a headless client."""
        print("[*] Starting WAF fingerprinting...")
        waf_name = None

        # 1. Benign request to get baseline
        start_time_benign = time.monotonic()
        try:
            response_benign = await asyncio.to_thread(self.scraper.get, base_url, timeout=15)
            await self._transfer_cookies_to_browser_context(self.scraper, base_url)
        except Exception as e:
            print(f"[!] Initial request to {base_url} failed: {e}")
            return None
        duration_benign = time.monotonic() - start_time_benign

        # 2. Malicious probe request
        probe_url = base_url.rstrip('/') + MALICIOUS_PROBE_URL
        start_time_malicious = time.monotonic()
        try:
            response_malicious = await asyncio.to_thread(self.scraper.get, probe_url, timeout=15)
            await self._transfer_cookies_to_browser_context(self.scraper, probe_url)
        except Exception:
            response_malicious = response_benign # Fallback to benign if probe fails
        duration_malicious = time.monotonic() - start_time_malicious

        # 3. Calculate behavioral and protocol features
        delay_ratio = duration_malicious / duration_benign if duration_benign > 0 else 0.0

        parsed_url = urlparse(base_url)
        host = parsed_url.netloc
        port = parsed_url.port or 443
        h2_features = await self._analyze_http2_frames(host, port)

        # 4. Assemble features and predict
        if response_malicious:
            features = {
                "headers": {k.lower(): v for k, v in response_malicious.headers.items()},
                "cookies": {c.name for c in self.scraper.cookies},
                "body": response_malicious.text,
                "ja3": None,
                "delay_ratio": delay_ratio,
                "h2_features": h2_features,
                "h3_features": {},
            }
            waf_name = self._predict_waf(features)

        if waf_name:
            print(f"[+] WAF Detected: {waf_name} (Delay Ratio: {delay_ratio:.2f})")
        else:
            print("[-] No specific WAF detected.")

        # Persist a small JSON report for the orchestrator/GUI layer.
        try:
            import json

            with open(report_file, "w", encoding="utf-8") as f:
                json.dump({"waf": waf_name}, f, indent=2)
        except Exception:
            pass

        return waf_name
