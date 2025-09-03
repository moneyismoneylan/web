# -*- coding: utf-8 -*-
"""WAF Fingerprinting Engine.

This module identifies the Web Application Firewall protecting the target
application. Signatures are loaded from an external JSON configuration file
and evaluated using multiple criteria (headers, cookies and body) to reduce
false positives.
"""
from __future__ import annotations

from playwright.async_api import BrowserContext, Error
import re
import asyncio
import cloudscraper
from urllib.parse import urlparse
from pathlib import Path
import json


def _load_waf_signatures() -> dict:
    """Load WAF signatures from the JSON configuration file."""
    path = Path(__file__).with_name("waf_signatures.json")
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return {}


# A database of WAF signatures loaded from configuration.
WAF_SIGNATURES = _load_waf_signatures()

MALICIOUS_PROBE_URL = "/?s=<script>alert('XSS')</script>"


class WafDetector:
    """Detects a WAF by sending a malicious probe and checking the response."""

    def __init__(self, browser_context: BrowserContext, scraper: cloudscraper.CloudScraper):
        self.context = browser_context
        self.scraper = scraper

    def _check_signatures_headless(self, response, cookies) -> str | None:
        """Compares response headers, cookies, and body against the WAF signature DB."""
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
