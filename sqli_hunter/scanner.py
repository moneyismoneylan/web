# -*- coding: utf-8 -*-
import asyncio
from playwright.async_api import BrowserContext, Page, Error
import re
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
import time
import base64
from sqli_hunter.payloads import SQL_ERROR_PATTERNS, ERROR_BASED_PAYLOADS, BOOLEAN_BASED_PAYLOADS, TIME_BASED_PAYLOADS, OOB_PAYLOADS
from sqli_hunter.tamper import apply_tampers
from sqli_hunter.polymorphic_engine import PolymorphicEngine

class Scanner:
    def __init__(self, browser_context: BrowserContext):
        self.context = browser_context
        self.vulnerable_points = []
        self.lock = asyncio.Lock()
        self.polymorphic_engine = PolymorphicEngine()

    async def _get_response_text(self, page: Page, url: str, timeout: int = 15000) -> str | None:
        try:
            response = await page.goto(url, wait_until="domcontentloaded", timeout=timeout)
            if not response: return None
            return await response.text()
        except Error:
            return None

    def _check_for_sql_errors(self, html_content: str) -> str | None:
        if not html_content: return None
        for pattern in SQL_ERROR_PATTERNS:
            if re.search(pattern, html_content, re.IGNORECASE):
                return pattern
        return None

    async def _scan_url(self, page: Page, url: str, tampers: list[str], db_type: str | None):
        print(f"[*] Testing for Error-Based SQLi on: {url}")
        parsed_url = urlparse(url)
        query_params = parse_qs(parsed_url.query)
        if not query_params: return

        base_payloads = list(ERROR_BASED_PAYLOADS)
        if db_type == "MSSQL":
            from sqli_hunter.payloads import MSSQL_ERROR_BASED_PAYLOADS_B64
            for p in MSSQL_ERROR_BASED_PAYLOADS_B64:
                base_payloads.append(base64.b64decode(p).decode('utf-8', errors='ignore'))

        for param_name, param_values in query_params.items():
            original_value = param_values[0]
            for base_payload in base_payloads:
                payload_variations = self.polymorphic_engine.generate(base_payload)
                for payload in payload_variations:
                    injected_params = query_params.copy()
                    injected_params[param_name] = original_value + payload
                    injected_url = urlunparse(parsed_url._replace(query=urlencode(injected_params, doseq=True)))

                    response_text = await self._get_response_text(page, injected_url)
                    error_found = self._check_for_sql_errors(response_text)
                    if error_found:
                        vuln_info = {"url": injected_url, "type": "Error-Based SQLi", "parameter": param_name, "payload": payload, "error": error_found}
                        async with self.lock:
                            print(f"[+] Vulnerability Found: {vuln_info}")
                            self.vulnerable_points.append(vuln_info)
                        return

    async def _scan_form(self, page: Page, form_details: dict, tampers: list[str], db_type: str | None):
        url = form_details["url"]
        method = form_details["method"].upper()
        inputs = form_details["inputs"]
        print(f"[*] Testing Form for Error-Based SQLi on: {url} ({method})")

        base_payloads = list(ERROR_BASED_PAYLOADS)
        if db_type == "MSSQL":
            from sqli_hunter.payloads import MSSQL_ERROR_BASED_PAYLOADS_B64
            for p in MSSQL_ERROR_BASED_PAYLOADS_B64:
                base_payloads.append(base64.b64decode(p).decode('utf-8', errors='ignore'))

        for input_to_test in inputs:
            if input_to_test.get("type") not in ["text", "textarea", "password", "email", "search", "url", "tel"]:
                continue
            for base_payload in base_payloads:
                payload_variations = self.polymorphic_engine.generate(base_payload)
                for payload in payload_variations:
                    data = {inp["name"]: inp.get("value", "") for inp in inputs}
                    data[input_to_test["name"]] += payload

                    try:
                        response = await page.request.post(url, data=data) if method == "POST" else await page.request.get(url, params=data)
                        response_text = await response.text()
                        error_found = self._check_for_sql_errors(response_text)
                        if error_found:
                            vuln_info = {"url": url, "type": "Error-Based SQLi (FORM)", "parameter": input_to_test["name"], "payload": payload, "error": error_found}
                            async with self.lock:
                                print(f"[+] Vulnerability Found: {vuln_info}")
                                self.vulnerable_points.append(vuln_info)
                            return
                    except Error as e:
                        print(f"[!] Request failed for form at {url}: {e}")

    async def scan_target(self, target_item: dict, tampers: list[str], collaborator_url: str | None = None, db_type: str | None = None):
        target_type = target_item.get("type")
        target_data = target_item.get("target")
        if not target_type or not target_data: return

        page = await self.context.new_page()
        try:
            scan_identifier = target_data if target_type == "url" else target_data["url"]
            async with self.lock:
                if any(p['url'].split('?')[0] == scan_identifier.split('?')[0] for p in self.vulnerable_points):
                    print(f"[*] Skipping {scan_identifier} as a vulnerability has already been found on this page/form action.")
                    return

            if target_type == "url":
                await self._scan_url(page, target_data, tampers, db_type)
            elif target_type == "form":
                await self._scan_form(page, target_data, tampers, db_type)
        finally:
            await page.close()
