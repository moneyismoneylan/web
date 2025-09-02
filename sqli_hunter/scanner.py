# -*- coding: utf-8 -*-
import asyncio
from playwright.async_api import BrowserContext, Page, Error
import re
from urllib.parse import urlparse, parse_qs, urljoin
import time
import statistics
import uuid
import json
import random
import itertools
from simhash import Simhash
import dns.asyncresolver
import cloudscraper
from bs4 import BeautifulSoup
from sqli_hunter.payloads import SQL_ERROR_PATTERNS
from sqli_hunter.tamper import apply_tampers
from sqli_hunter.ast_payload_generator import AstPayloadGenerator
from sqli_hunter.bayesian_tamper_optimizer import BayesianTamperOptimizer, TAMPER_CATEGORIES
from sqli_hunter.db_fingerprinter import BEHAVIORAL_PROBES
from typing import Callable, Awaitable, Any, Tuple, List, Set, Dict
from collections import defaultdict

WAF_TEMPO_MAP = { "Cloudflare": 1.5, "AWS WAF": 0.5, "Imperva (Incapsula)": 1.0 }
MAX_BACKOFF_DELAY = 60.0

class Scanner:
    def __init__(self, browser_context: BrowserContext, canary_store: Dict, waf_name: str | None = None, n_calls: int = 20):
        self.context = browser_context
        self.vulnerable_points = []
        self.lock = asyncio.Lock()
        self.dns_resolver = dns.asyncresolver.Resolver()
        self.canary_store = canary_store
        self.static_request_delay = WAF_TEMPO_MAP.get(waf_name, 0)
        self.rate_limit_active = False
        self.rate_limit_delay = 1.0
        self.successful_requests_since_rl = 0
        self.payload_generator = None
        self.n_calls = n_calls
        if self.static_request_delay > 0: print(f"[*] WAF policy adaptation: Applying a {self.static_request_delay}s delay between requests.")

    def _update_rate_limit_status(self, status: int, is_waf_block: bool):
        is_rate_limited = status in [429, 503]
        if is_rate_limited:
            self.rate_limit_active = True; self.successful_requests_since_rl = 0
            new_delay = self.rate_limit_delay * 2; self.rate_limit_delay = min(new_delay, MAX_BACKOFF_DELAY)
            print(f"[!] Rate limit detected! Increasing backoff delay to {self.rate_limit_delay:.2f}s.")
        elif self.rate_limit_active and not is_waf_block:
            self.successful_requests_since_rl += 1
            if self.successful_requests_since_rl >= 10:
                self.rate_limit_delay = max(1.0, self.rate_limit_delay / 2); self.successful_requests_since_rl = 0
                print(f"[*] Rate limit seems to have eased. Reducing backoff delay to {self.rate_limit_delay:.2f}s.")
                if self.rate_limit_delay == 1.0: self.rate_limit_active = False; print("[*] Rate limiting deactivated.")

    async def _send_headless_request(self, scraper: cloudscraper.CloudScraper, url: str, method: str = "GET", params: dict = None, data: dict = None, json_data: dict = None, timeout: int = 30) -> tuple[str | None, float, bool]:
        start_time = time.monotonic()

        def sync_request():
            method_upper = method.upper()
            if method_upper == "GET":
                return scraper.get(url, params=params, timeout=timeout)
            elif method_upper == "POST":
                post_body = json_data if json_data is not None else data
                return scraper.post(url, params=params, data=post_body, json=json_data, timeout=timeout)
            else:
                raise NotImplementedError(f"Method {method_upper} not implemented")

        try:
            response = await asyncio.to_thread(sync_request)
            duration = time.monotonic() - start_time
            body = response.text
            status = response.status_code
            is_blocked = status in [403, 406] or any(s in body.lower() for s in ["request blocked", "forbidden", "waf"])
            self._update_rate_limit_status(status, is_blocked)
            return body, duration, is_blocked
        except Exception as e:
            # print(f"  [!] cloudscraper request failed: {e}")
            return None, time.monotonic() - start_time, False

    async def _send_browser_request(self, page: Page, url: str, method: str = "GET", params: dict = None, data: dict = None, json_data: dict = None, timeout: int = 30000) -> tuple[str | None, float, bool]:
        start_time = time.monotonic()
        try:
            method_upper = method.upper()
            if method_upper == "GET":
                response = await page.request.get(url, params=params, timeout=timeout)
            elif method_upper == "POST":
                post_body = json_data if json_data is not None else data
                response = await page.request.post(url, params=params, data=post_body, timeout=timeout)
            else:
                raise NotImplementedError(f"Method {method} not implemented in _send_browser_request")

            duration = time.monotonic() - start_time
            body = await response.text()
            status = response.status
            is_blocked = status in [403, 406] or any(s in body.lower() for s in ["request blocked", "forbidden", "waf"])
            self._update_rate_limit_status(status, is_blocked)
            return body, duration, is_blocked
        except Error as e:
            # print(f"  [DEBUG] Playwright error in browser request: {e}")
            return None, time.monotonic() - start_time, False

    async def _get_baseline(self, page: Page, url: str, method: str, params: dict = None, data: dict = None, json_data: dict = None) -> tuple[float, Simhash | None]:
        timings, content_for_hash = [], None
        for _ in range(3):
            content, duration, _ = await self._send_browser_request(page, url, method=method, params=params, data=data, json_data=json_data)
            timings.append(duration)
            if content and content_for_hash is None: content_for_hash = content
        if not timings: return 0.0, None
        return statistics.median(timings), Simhash(content_for_hash) if content_for_hash else None

    async def _perform_taint_analysis(self, page: Page, url: str, method: str, create_request_args: Callable) -> str:
        taint = "sqlihunter" + uuid.uuid4().hex[:8]
        request_args = await create_request_args(taint)
        body, _, is_blocked = await self._send_browser_request(page, url, method, **request_args)
        if is_blocked or not body or taint not in body: return "HTML_TEXT"

        if re.search(f"'[^>]*{taint}[^>]*'", body, re.IGNORECASE): return "HTML_ATTRIBUTE_SINGLE_QUOTED"
        if re.search(f'"[^>]*{taint}[^>]*"', body, re.IGNORECASE): return "HTML_ATTRIBUTE_DOUBLE_QUOTED"
        if re.search(f">(?!'|\")[^<]*{taint}[^<]*<", body, re.IGNORECASE): return "HTML_TEXT"
        return "HTML_TEXT"

    def _create_objective_wrapper(self, async_objective_func: Callable) -> Callable:
        current_loop = asyncio.get_running_loop()
        def sync_objective_wrapper(tamper_chain: List[str]) -> float:
            future = asyncio.run_coroutine_threadsafe(async_objective_func(tuple(tamper_chain)), current_loop)
            try:
                return future.result(timeout=60)
            except (asyncio.TimeoutError, Exception):
                return 0.0
        return sync_objective_wrapper

    def _create_error_based_objective(self, scraper: cloudscraper.CloudScraper, url: str, method: str, context: str, original_value: str, create_request_args: Callable) -> Callable:
        async def async_objective(tamper_chain: Tuple[str, ...]) -> float:
            payload, _ = self.payload_generator.generate("ERROR_BASED", context)[0]
            tampered_payload = apply_tampers(payload, list(tamper_chain))
            args = await create_request_args(tampered_payload)
            body, _, is_blocked = await self._send_headless_request(scraper, url, method, **args)
            if is_blocked: return 1.0
            if body and any(re.search(p, body, re.IGNORECASE) for p in SQL_ERROR_PATTERNS):
                return -1.0
            return 0.0
        return self._create_objective_wrapper(async_objective)

    def _create_boolean_based_objective(self, scraper: cloudscraper.CloudScraper, url: str, method: str, context: str, original_value: str, create_request_args: Callable, baseline_hash: Simhash) -> Callable:
        async def async_objective(tamper_chain: Tuple[str, ...]) -> float:
            true_payload, false_payload, _ = self.payload_generator.generate("BOOLEAN_BASED", context)[0]

            tampered_true = apply_tampers(true_payload, list(tamper_chain))
            true_args = await create_request_args(tampered_true)
            true_body, _, is_blocked_true = await self._send_headless_request(scraper, url, method, **true_args)
            if is_blocked_true: return 1.0

            tampered_false = apply_tampers(false_payload, list(tamper_chain))
            false_args = await create_request_args(tampered_false)
            false_body, _, is_blocked_false = await self._send_headless_request(scraper, url, method, **false_args)
            if is_blocked_false: return 1.0

            if true_body and false_body and baseline_hash.distance(Simhash(true_body)) < 3 and Simhash(true_body).distance(Simhash(false_body)) > 3:
                return -1.0
            return 0.0
        return self._create_objective_wrapper(async_objective)

    async def _exhaustive_time_scan(self, scraper: cloudscraper.CloudScraper, url: str, method: str, context: str, original_value: str, create_request_args: Callable, baseline_median: float) -> Tuple[str | None, tuple | None]:
        """A more exhaustive, systematic scan for time-based vulnerabilities."""
        print("  [+] Running Exhaustive Time-Based scan...")
        sleep_time = 5
        # We get the first payload generated, assuming it's a good generic one.
        payload, _ = self.payload_generator.generate("TIME_BASED", context, options={"sleep_time": sleep_time})[0]

        # A set of tamper chains to test, starting with the most basic.
        tampers_to_test = [('none',)] + \
                          [(t,) for t in TAMPER_CATEGORIES if t != 'none'] + \
                          list(itertools.combinations([t for t in TAMPER_CATEGORIES if t != 'none'], 2))

        for chain in tampers_to_test:
            tampered_payload = apply_tampers(payload, list(chain))
            args = await create_request_args(tampered_payload)
            _, duration, is_blocked = await self._send_headless_request(scraper, url, method, **args)

            if not is_blocked and duration is not None and duration > baseline_median + (sleep_time * 0.8):
                return payload, chain

        return None, None


    async def _fingerprint_parameter(self, scraper: cloudscraper.CloudScraper, page: Page, url: str, method: str, create_request_args: Callable, original_value: str) -> str | None:
        """
        Sends behavioral probes to the target parameter and analyzes the responses to
        determine the most likely database engine.
        """
        print(f"[*] Starting smart database fingerprinting for parameter...")
        db_scores = defaultdict(int)

        # Get a baseline response using a non-malicious value
        baseline_args = await create_request_args(original_value)
        baseline_body, baseline_duration, _ = await self._send_headless_request(scraper, url, method, **baseline_args)
        if baseline_body is None:
             # Fallback to browser request if headless fails for baseline
             baseline_body, baseline_duration, _ = await self._send_browser_request(page, url, method, **baseline_args)

        # If we can't even get a valid (non-empty) baseline, we can't fingerprint.
        if not baseline_body:
            print("[!] Could not retrieve a valid (non-empty) baseline response for fingerprinting. Aborting.")
            return None

        baseline_hash = Simhash(baseline_body)

        for probe in BEHAVIORAL_PROBES:
            # The payloads are crafted to be injected into a string context
            args = await create_request_args(original_value + probe['payload'])
            body, duration, is_blocked = await self._send_headless_request(scraper, url, method, **args, timeout=10)

            if is_blocked: continue

            was_successful = False
            if body is not None and probe['type'] == 'time':
                if duration > baseline_duration + (probe['validator'] * 0.7):
                    was_successful = True
            elif body is not None and probe['type'] == 'content':
                if probe['validator'] and probe['validator'] in body:
                    was_successful = True
                elif probe['validator'] is None and body is not None:
                     if Simhash(body).distance(baseline_hash) < 10:
                          was_successful = True
            elif body is not None and probe['type'] == 'error':
                 if re.search(probe['validator'], body):
                     was_successful = True

            if was_successful:
                db_scores[probe['db']] += 1
                print(f"  [+] Hit for {probe['db']} (Type: {probe['type']})")

        if not db_scores:
            print("[-] Smart fingerprinting did not identify a database for this parameter.")
            return None

        most_likely_db = max(db_scores, key=db_scores.get)
        print(f"[*] Fingerprinting finished. Scores: {dict(db_scores)}")
        print(f"[+] Most likely database detected: {most_likely_db}")
        return most_likely_db

    async def _run_scan_for_parameter(self, scraper: cloudscraper.CloudScraper, page: Page, url: str, method: str, param_name: str, original_value: str, baseline_median: float, baseline_hash: Simhash, collaborator_url: str, create_request_args: Callable):
        total_delay = self.static_request_delay
        if self.rate_limit_active: total_delay += self.rate_limit_delay
        if total_delay > 0: await asyncio.sleep(total_delay * random.uniform(0.8, 1.2))

        # Fingerprint the parameter to determine the database type
        db_type = await self._fingerprint_parameter(scraper, page, url, method, create_request_args, original_value)
        if not db_type:
            print(f"  [!] Could not determine database for param '{param_name}', skipping.")
            return

        # Instantiate the payload generator with the detected dialect
        self.payload_generator = AstPayloadGenerator(dialect=db_type)

        context = await self._perform_taint_analysis(page, url, method, lambda taint: create_request_args(original_value + taint))
        print(f"  [*] Taint Analysis for param '{param_name}' found reflection context: {context}")

        # --- Error-Based Scan (Optimizer) ---
        print(f"  [+] Running Error-Based Optimizer for '{param_name}'...")
        error_objective = self._create_error_based_objective(scraper, url, method, context, original_value, lambda p: create_request_args(p))
        error_optimizer = BayesianTamperOptimizer(objective_func=error_objective, n_calls=self.n_calls, n_initial_points=5)
        best_error_chain, best_error_score = await asyncio.to_thread(error_optimizer.optimize)
        if best_error_score < 0:
            payload_used, _ = self.payload_generator.generate("ERROR_BASED", context)[0]
            await self._report_vulnerability(url, "Error-Based SQLi", param_name, payload_used, best_error_chain)
            return

        # --- Time-Based Scan (Exhaustive) ---
        time_payload, time_chain = await self._exhaustive_time_scan(scraper, url, method, context, original_value, lambda p: create_request_args(p), baseline_median)
        if time_payload:
            await self._report_vulnerability(url, "Time-Based SQLi", param_name, time_payload, time_chain)
            return

        # --- Boolean-Based Scan (Optimizer) ---
        if baseline_hash:
            print(f"  [+] Running Boolean-Based Optimizer for '{param_name}'...")
            boolean_objective = self._create_boolean_based_objective(scraper, url, method, context, original_value, lambda p: create_request_args(p), baseline_hash)
            boolean_optimizer = BayesianTamperOptimizer(objective_func=boolean_objective, n_calls=self.n_calls, n_initial_points=5)
            best_boolean_chain, best_boolean_score = await asyncio.to_thread(boolean_optimizer.optimize)
            if best_boolean_score < 0:
                true_payload, false_payload, _ = self.payload_generator.generate("BOOLEAN_BASED", context)[0]
                payload_used = f"TRUE: {true_payload}, FALSE: {false_payload}"
                await self._report_vulnerability(url, "Boolean-Based SQLi", param_name, payload_used, best_boolean_chain)
                return

        print(f"  [-] No vulnerabilities found for param '{param_name}'.")

    async def _report_vulnerability(self, url, vuln_type, param, payload, chain):
        vuln_info = {"url": url, "type": vuln_type, "parameter": param, "payload": payload, "tamper_chain": list(chain)}
        async with self.lock:
            print(f"[bold red][+] Vulnerability Found: {json.dumps(vuln_info)}[/bold red]")
            self.vulnerable_points.append(vuln_info)

    async def _scan_url(self, scraper: cloudscraper.CloudScraper, page: Page, url: str, collaborator_url: str | None):
        parsed_url = urlparse(url); query_params = parse_qs(parsed_url.query)
        if not query_params: return
        baseline_median, baseline_hash = await self._get_baseline(page, url, "GET", params=query_params)
        for param_name, values in query_params.items():
            async def create_request_args(p_value):
                return {'params': {**query_params, param_name: p_value}}
            await self._run_scan_for_parameter(scraper, page, url, "GET", param_name, values[0], baseline_median, baseline_hash, collaborator_url, create_request_args)

    async def _scan_json_endpoint(self, scraper: cloudscraper.CloudScraper, page: Page, url: str, json_body: dict, collaborator_url: str | None):
        baseline_median, baseline_hash = await self._get_baseline(page, url, "POST", json_data=json_body)
        for key, value in json_body.items():
            if not isinstance(value, str): continue
            async def create_request_args(p_value):
                return {'json_data': {**json_body, key: p_value}}
            await self._run_scan_for_parameter(scraper, page, url, "POST", key, value, baseline_median, baseline_hash, collaborator_url, create_request_args)

    async def _get_fresh_csrf_token(self, page: Page, form_page_url: str, csrf_field_name: str) -> str | None:
        try:
            await page.goto(form_page_url, wait_until="domcontentloaded"); soup = BeautifulSoup(await page.content(), 'html.parser')
            token_element = soup.find('input', {'name': csrf_field_name}); return token_element['value'] if token_element else None
        except Error as e: print(f"[!] Failed to fetch fresh CSRF token from {form_page_url}: {e}"); return None

    async def _scan_form(self, scraper: cloudscraper.CloudScraper, page: Page, form_details: dict, collaborator_url: str | None):
        url, method, inputs = form_details['url'], form_details['method'].upper(), form_details['inputs']
        csrf_field_name = form_details.get('csrf_field_name'); form_page_url = url
        base_data = {inp["name"]: inp.get("value", "") for inp in inputs if inp.get("name")}
        if csrf_field_name:
            fresh_token = await self._get_fresh_csrf_token(page, form_page_url, csrf_field_name)
            if not fresh_token: print(f"[!] Could not get CSRF token for baseline on {url}. Scan may fail."); return
            base_data[csrf_field_name] = fresh_token
        baseline_median, baseline_hash = await self._get_baseline(page, url, method, data=base_data)
        for input_to_test in inputs:
            param_name = input_to_test.get("name")
            if not param_name or input_to_test.get("type") not in ["text", "textarea", "password", "email", "search", "url", "tel"] or param_name == csrf_field_name: continue
            async def create_form_request_args(p_value):
                return {'data': {**base_data, param_name: p_value}}
            await self._run_scan_for_parameter(scraper, page, url, method, param_name, input_to_test.get("value", ""), baseline_median, baseline_hash, collaborator_url, create_form_request_args)

    async def scan_target(self, target_item: dict, collaborator_url: str | None = None):
        scraper = cloudscraper.create_scraper()

        cookies = await self.context.cookies()
        for cookie in cookies:
            scraper.cookies.set(cookie['name'], cookie['value'], domain=cookie['domain'])

        page = await self.context.new_page()
        try:
            target_type, url = target_item.get("type"), target_item.get("url")
            async with self.lock:
                if any(p['url'] == url and p.get('parameter') for p in self.vulnerable_points):
                    print(f"[*] Skipping {url} as a vulnerability has already been found in this URL.")
                    return

            if target_type == 'form': await self._scan_form(scraper, page, target_item, collaborator_url)
            elif target_type == 'api' or (target_item.get("method", "GET").upper() == "POST" and target_item.get("content_type")):
                method, content_type = target_item.get("method", "GET").upper(), target_item.get("content_type")
                if method == "POST" and content_type and 'application/json' in content_type:
                    post_data = target_item.get("post_data")
                    json_body = json.loads(post_data) if isinstance(post_data, str) else post_data
                    await self._scan_json_endpoint(scraper, page, url, json_body, collaborator_url)
                else: await self._scan_url(scraper, page, url, collaborator_url)
            elif target_type == 'url': await self._scan_url(scraper, page, url, collaborator_url)
            else: print(f"[!] Skipping target with unhandled type: {target_type}")
        finally: await page.close()
