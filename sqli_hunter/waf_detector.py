# -*- coding: utf-8 -*-
"""
WAF Detection Engine.

This module is responsible for identifying the presence and type of a
Web Application Firewall (WAF) protecting the target application.
"""
from playwright.async_api import BrowserContext, Error
import re

# A dictionary of WAF signatures.
# Each key is the WAF name, and the value contains patterns to search for
# in response headers, cookies, and the response body.
WAF_SIGNATURES = {
    "Cloudflare": {
        "headers": {"server": "cloudflare"},
        "cookies": ["__cfduid", "cf_clearance"],
        "body": r"cloudflare|ray id|checking your browser"
    },
    "Akamai": {
        "headers": {"server": "AkamaiGHost"},
        "cookies": [],
        "body": r"akamai|the page you requested was blocked"
    },
    "Sucuri": {
        "headers": {"server": "Sucuri/Cloudproxy"},
        "cookies": ["sucuri_cloudproxy_uuid"],
        "body": r"sucuri web site firewall|access denied - sucuri"
    },
    "Imperva": {
        "headers": {},
        "cookies": ["incap_ses", "visid_incap"],
        "body": r"incapsula|request unsuccessful"
    },
    "AWS WAF": {
        "headers": {"server": "awselb"},
        "cookies": [],
        "body": r"aws|amazon-web-services"
    },
    "F5 BIG-IP": {
        "headers": {"server": "big-ip"},
        "cookies": ["BIGipServer"],
        "body": r"f5|big-ip"
    },
    "Barracuda": {
        "headers": {"server": "barracuda"},
        "cookies": ["barracuda_waf_cookie"],
        "body": r"barracuda"
    },
    "ModSecurity": {
        "headers": {"server": "mod_security"},
        "cookies": [],
        "body": r"mod_security|modsecurity"
    }
}

class WafDetector:
    """
    Detects the WAF of a target URL by analyzing HTTP responses using a browser context.
    """
    def __init__(self, browser_context: BrowserContext):
        self.context = browser_context
        # A simple, benign payload that is likely to be blocked by a WAF
        self.probe_payload = "/?id=<script>alert('XSS')</script>"

    async def check_waf(self, base_url: str) -> str | None:
        """
        Sends a probe to the target and checks for WAF signatures in the response.

        :param base_url: The base URL of the target application.
        :return: The name of the detected WAF or None if no WAF is identified.
        """
        target_url = base_url.rstrip('/') + self.probe_payload
        page = None
        try:
            print(f"[*] Probing for WAF on: {target_url}")
            page = await self.context.new_page()
            response = await page.goto(target_url, wait_until="domcontentloaded", timeout=15000)

            if response is None:
                print(f"[!] WAF probe failed for {target_url}: No response received.")
                return None

            headers = {k.lower(): v for k, v in response.headers.items()}
            cookies = await self.context.cookies([target_url])
            cookie_names = {c['name'] for c in cookies}
            body = await response.text()

            # Check headers
            for waf, sigs in WAF_SIGNATURES.items():
                for header, value in sigs["headers"].items():
                    if headers.get(header) and value in headers.get(header, ""):
                        print(f"[+] WAF Detected: {waf} (via {header} header)")
                        return waf

            # Check cookies
            for waf, sigs in WAF_SIGNATURES.items():
                for cookie_name in sigs["cookies"]:
                    if cookie_name in cookie_names:
                        print(f"[+] WAF Detected: {waf} (via cookie: {cookie_name})")
                        return waf

            # Check body
            for waf, sigs in WAF_SIGNATURES.items():
                if re.search(sigs["body"], body, re.IGNORECASE):
                    print(f"[+] WAF Detected: {waf} (via response body)")
                    return waf

        except Error as e:
            print(f"[!] WAF probe failed for {target_url}: {e}")
            return None
        finally:
            if page:
                await page.close()

        print("[-] No WAF detected or WAF is not recognized.")
        return None

# Test code has been removed. This module is intended to be imported.
