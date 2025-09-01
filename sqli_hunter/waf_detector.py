# -*- coding: utf-8 -*-
"""
WAF Detection Engine.

This module is responsible for identifying the presence and type of a
Web Application Firewall (WAF) protecting the target application.
"""
import httpx
import re

# A dictionary of WAF signatures.
# Each key is the WAF name, and the value contains patterns to search for
# in response headers, cookies, and the response body.
WAF_SIGNATURES = {
    "Cloudflare": {
        "headers": {"Server": "cloudflare"},
        "cookies": ["__cfduid", "cf_clearance"],
        "body": r"cloudflare|ray id|checking your browser"
    },
    "Akamai": {
        "headers": {"Server": "AkamaiGHost"},
        "cookies": [],
        "body": r"akamai|the page you requested was blocked"
    },
    "Sucuri": {
        "headers": {"Server": "Sucuri/Cloudproxy"},
        "cookies": ["sucuri_cloudproxy_uuid"],
        "body": r"sucuri web site firewall|access denied - sucuri"
    },
    "Imperva": {
        "headers": {},
        "cookies": ["incap_ses", "visid_incap"],
        "body": r"incapsula|request unsuccessful"
    }
}

class WafDetector:
    """
    Detects the WAF of a target URL by analyzing HTTP responses.
    """
    def __init__(self, client: httpx.AsyncClient):
        self.client = client
        # A simple, benign payload that is likely to be blocked by a WAF
        self.probe_payload = "/?id=<script>alert('XSS')</script>"

    async def check_waf(self, base_url: str) -> str | None:
        """
        Sends a probe to the target and checks for WAF signatures in the response.

        :param base_url: The base URL of the target application.
        :return: The name of the detected WAF or None if no WAF is identified.
        """
        target_url = base_url.rstrip('/') + self.probe_payload

        try:
            print(f"[*] Probing for WAF on: {target_url}")
            response = await self.client.get(target_url, timeout=10)

            # Check headers
            for waf, sigs in WAF_SIGNATURES.items():
                for header, value in sigs["headers"].items():
                    if response.headers.get(header) and value in response.headers.get(header, ""):
                        print(f"[+] WAF Detected: {waf} (via {header} header)")
                        return waf

            # Check cookies
            for waf, sigs in WAF_SIGNATURES.items():
                for cookie_name in sigs["cookies"]:
                    if cookie_name in response.cookies:
                        print(f"[+] WAF Detected: {waf} (via cookie: {cookie_name})")
                        return waf

            # Check body
            for waf, sigs in WAF_SIGNATURES.items():
                if re.search(sigs["body"], response.text, re.IGNORECASE):
                    print(f"[+] WAF Detected: {waf} (via response body)")
                    return waf

        except httpx.RequestError as e:
            print(f"[!] WAF probe failed for {target_url}: {e}")
            return None

        print("[-] No WAF detected or WAF is not recognized.")
        return None

# Test code has been removed. This module is intended to be imported.
