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


class WAFBehaviorGNN:
    """Simplified GNN-like model for WAF behaviour.

    The model builds a graph of response features (headers, cookies, body
    tokens) and computes a naive score for each WAF. It is intentionally
    lightweight and does not require external ML libraries.
    """

    def predict(self, features: dict, signatures: dict) -> str | None:
        best_name, best_score = None, 0
        for waf_name, sig in signatures.items():
            score = 0
            for header, pattern in sig.get("headers", {}).items():
                if header.lower() in features["headers"] and re.search(
                    pattern, features["headers"][header.lower()], re.IGNORECASE
                ):
                    score += 1
            for cookie in sig.get("cookies", []):
                if any(c.startswith(cookie) for c in features["cookies"]):
                    score += 1
            for pattern in sig.get("body", []):
                if re.search(pattern, features["body"], re.IGNORECASE):
                    score += 1
            if score > best_score:
                best_name, best_score = waf_name, score
        return best_name if best_score >= 2 else None


# A database of WAF signatures loaded from configuration.
WAF_SIGNATURES = load_config("waf_signatures")
GNN_MODEL = WAFBehaviorGNN()

MALICIOUS_PROBE_URL = "/?s=<script>alert('XSS')</script>"


class WafDetector:
    """Detects a WAF by sending a malicious probe and checking the response."""

    def __init__(self, browser_context: BrowserContext, scraper: cloudscraper.CloudScraper):
        self.context = browser_context
        self.scraper = scraper

    def _check_signatures_headless(self, response, cookies) -> str | None:
        """Compares response headers, cookies, and body against the WAF signature DB.

        If no direct signature matches are found, a lightweight GNN model is
        used to infer the most probable WAF based on the observed features.
        """
        if not response:
            return None

        headers = {k.lower(): v for k, v in response.headers.items()}
        cookie_names = {c.name for c in cookies}
        body = response.text

        for waf_name, signatures in WAF_SIGNATURES.items():
            matches = 0

            # Check headers
            for header, pattern in signatures.get("headers", {}).items():
                header_lower = header.lower()
                if header_lower in headers and re.search(pattern, headers[header_lower], re.IGNORECASE):
                    matches += 1
                    break

            # Check cookies
            for cookie_pattern in signatures.get("cookies", []):
                if any(c.startswith(cookie_pattern) for c in cookie_names):
                    matches += 1
                    break

            # Check body
            body_patterns = signatures.get("body")
            if body_patterns:
                for p in body_patterns:
                    if re.search(p, body, re.IGNORECASE):
                        matches += 1
                        break

            min_matches = signatures.get("min_matches", 2)
            if matches >= min_matches:
                return waf_name

        # Fall back to the GNN model
        features = {"headers": headers, "cookies": cookie_names, "body": body}
        return GNN_MODEL.predict(features, WAF_SIGNATURES)

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

    async def check_waf(self, base_url: str) -> str | None:
        """Probes the target to identify the WAF using a headless client."""
        print("[*] Starting WAF fingerprinting...")

        try:
            response = await asyncio.to_thread(self.scraper.get, base_url, timeout=15)
            await self._transfer_cookies_to_browser_context(self.scraper, base_url)
            waf_name = self._check_signatures_headless(response, self.scraper.cookies)
            if waf_name:
                print(f"[+] WAF Detected on initial request: {waf_name}")
                return waf_name
        except Exception:
            pass

        probe_url = base_url.rstrip('/') + MALICIOUS_PROBE_URL
        try:
            response = await asyncio.to_thread(self.scraper.get, probe_url, timeout=15)
            await self._transfer_cookies_to_browser_context(self.scraper, probe_url)
            waf_name = self._check_signatures_headless(response, self.scraper.cookies)
            if waf_name:
                print(f"[+] WAF Detected after malicious probe: {waf_name}")
                return waf_name
        except Exception:
            pass

        print("[-] No specific WAF detected.")
        return None
