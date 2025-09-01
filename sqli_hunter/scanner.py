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
from simhash import Simhash
import dns.asyncresolver
from curl_cffi.requests import AsyncSession
from bs4 import BeautifulSoup
from sqli_hunter.payloads import SQL_ERROR_PATTERNS, ERROR_BASED_PAYLOADS, OOB_PAYLOADS
from sqli_hunter.tamper import apply_tampers
from sqli_hunter.ast_payload_generator import AstPayloadGenerator
from sqli_hunter.bayesian_tamper_optimizer import BayesianTamperOptimizer
from typing import Callable, Awaitable, Any, Tuple, List, Set, Dict

WAF_TEMPO_MAP = { "Cloudflare": 1.5, "AWS WAF": 0.5, "Imperva (Incapsula)": 1.0 }
MAX_BACKOFF_DELAY = 60.0

class Scanner:
    def __init__(self, browser_context: BrowserContext, canary_store: Dict, waf_name: str | None = None):
        self.context = browser_context
        self.vulnerable_points = []
        self.lock = asyncio.Lock()
        self.dns_resolver = dns.asyncresolver.Resolver()
        self.canary_store = canary_store
        self.static_request_delay = WAF_TEMPO_MAP.get(waf_name, 0)
        self.rate_limit_active = False
        self.rate_limit_delay = 1.0
        self.successful_requests_since_rl = 0
        self.http_session: AsyncSession | None = None
        self.payload_generator = None # Will be initialized in scan_target
        if self.static_request_delay > 0: print(f"[*] WAF policy adaptation: Applying a {self.static_request_delay}s delay between requests.")

    async def _initialize_http_session(self):
        if getattr(self, 'http_session', None) is None:
            cookies = await self.context.cookies()
            # curl_cffi expects cookies in a dict format
            cookie_dict = {cookie['name']: cookie['value'] for cookie in cookies}
            self.http_session = AsyncSession(
                cookies=cookie_dict,
                impersonate="chrome110", # Impersonate Chrome 110 to bypass TLS fingerprinting
                allow_redirects=True,
                verify=False
            )

    async def close(self):
        if getattr(self, 'http_session', None): await self.http_session.close()

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

    async def _send_headless_request(self, url: str, method: str = "GET", params: dict = None, data: dict = None, json_data: dict = None, timeout: int = 30) -> tuple[str | None, float, bool]:
        start_time = time.monotonic()
        try:
            # curl_cffi uses a different API than httpx
            method_upper = method.upper()
            if method_upper == "GET":
                response = await self.http_session.get(url, params=params, timeout=timeout)
            elif method_upper == "POST":
                post_body = json_data if json_data is not None else data
                response = await self.http_session.post(url, params=params, data=post_body, json=json_data, timeout=timeout)
            else:
                raise NotImplementedError(f"Method {method_upper} not implemented in _send_headless_request")

            duration = time.monotonic() - start_time
            body = response.text
            status = response.status_code
            is_blocked = status in [403, 406] or any(s in body.lower() for s in ["request blocked", "forbidden", "waf"])
            self._update_rate_limit_status(status, is_blocked)
            return body, duration, is_blocked
        except Exception:
            return None, time.monotonic() - start_time, False

    async def _send_browser_request(self, page: Page, url: str, method: str = "GET", params: dict = None, data: dict = None, json_data: dict = None, timeout: int = 30000) -> tuple[str | None, float, bool]:
        start_time = time.monotonic()
        try:
            method_upper = method.upper()
            if method_upper == "GET":
                response = await page.request.get(url, params=params, timeout=timeout)
            elif method_upper == "POST":
                # To send a JSON body, the `data` parameter should be a dictionary.
                # Playwright will automatically set the Content-Type to application/json.
                # The 'json' kwarg is not valid for page.request.post.
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
            print(f"  [DEBUG] Playwright error in browser request: {e}")
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
        if is_blocked or not body or taint not in body: return "HTML_TEXT" # Default context

        if re.search(f"'[^>]*{taint}[^>]*'", body, re.IGNORECASE): return "HTML_ATTRIBUTE_SINGLE_QUOTED"
        if re.search(f'"[^>]*{taint}[^>]*"', body, re.IGNORECASE): return "HTML_ATTRIBUTE_DOUBLE_QUOTED"
        # More specific JS checks could be added here
        if re.search(f">(?!'|\")[^<]*{taint}[^<]*<", body, re.IGNORECASE): return "HTML_TEXT"

        return "HTML_TEXT" # Default fallback

    async def _check_oast_interaction(self, domain: str) -> bool:
        await asyncio.sleep(2);
        try: await self.dns_resolver.resolve(domain, 'A'); return True
        except Exception: return False

    async def _scan_boolean_based(self, sender_func: Callable, baseline_hash: Simhash, context: str) -> Tuple[str | None, tuple | None]:
        if not baseline_hash: return None, None
        payloads = self.payload_generator.generate("BOOLEAN_BASED", context)
        for true_payload, false_payload, _ in payloads:
            true_content, _, is_blocked_true, chain_true = await sender_func(true_payload)
            if is_blocked_true or not true_content: continue
            false_content, _, is_blocked_false, _ = await sender_func(false_payload)
            if is_blocked_false or not false_content: continue
            if baseline_hash.distance(Simhash(true_content)) < 3 and Simhash(true_content).distance(Simhash(false_content)) > 3:
                return f"TRUE: {true_payload}, FALSE: {false_payload}", chain_true
        return None, None

    async def _run_scan_for_parameter(self, page: Page, url: str, method: str, param_name: str, original_value: str, baseline_median: float, baseline_hash: Simhash, collaborator_url: str, create_request_args: Callable):
        total_delay = self.static_request_delay
        if self.rate_limit_active: total_delay += self.rate_limit_delay
        if total_delay > 0: await asyncio.sleep(total_delay * random.uniform(0.8, 1.2))

        context = await self._perform_taint_analysis(page, url, method, lambda taint: create_request_args(param_name, original_value + taint))
        print(f"  [*] Taint Analysis for param '{param_name}' found reflection context: {context}")

        # Define the async part of the objective function
        async def async_objective(tamper_chain: Tuple[str, ...]) -> float:
            sleep_time = 5
            # Use a high-confidence time-based payload for the optimization probe
            payloads = self.payload_generator.generate("TIME_BASED", context, options={"sleep_time": sleep_time})
            if not payloads: return 0.0

            payload_to_inject, _ = payloads[0]
            tampered_payload = apply_tampers(payload_to_inject, list(tamper_chain))
            request_args = await create_request_args(param_name, original_value + tampered_payload)

            _, duration, is_blocked = await self._send_headless_request(url, method, **request_args)

            if is_blocked: return 1.0  # WAF Penalty
            if duration is not None and duration > baseline_median + (sleep_time * 0.7): return -1.0  # Detection Signal
            return 0.0  # Neutral

        # Create a synchronous wrapper for the optimizer that closes over the event loop
        def create_sync_wrapper(loop):
            def sync_objective_wrapper(tamper_chain: List[str]) -> float:
                # This function is now a closure and has access to 'loop'
                future = asyncio.run_coroutine_threadsafe(async_objective(tuple(tamper_chain)), loop)
                try:
                    # Add a timeout to prevent blocking indefinitely
                    return future.result(timeout=25)
                except (asyncio.TimeoutError, Exception) as e:
                    print(f"  [!] Objective function timed out or failed: {e}")
                    return 0.0 # Return a neutral score on failure
            return sync_objective_wrapper

        # Get the current event loop and create the specific wrapper for it
        current_loop = asyncio.get_running_loop()
        objective_wrapper = create_sync_wrapper(current_loop)

        # Instantiate and run the optimizer
        optimizer = BayesianTamperOptimizer(
            objective_func=objective_wrapper,
            n_calls=20,
            n_initial_points=5
        )

        # The optimizer's optimize method is synchronous, so we run it in a thread
        best_chain, best_score = await asyncio.to_thread(optimizer.optimize)

        # If the optimizer found a vulnerability, report it and use the chain for other checks
        if best_score < 0:
            vuln_type = f"Time-Based SQLi (via BO)"
            # Re-generate the payload that was used inside the optimizer
            payload_used = self.payload_generator.generate("TIME_BASED", context, options={"sleep_time": 5})[0][0]
            await self._report_vulnerability(url, vuln_type, param_name, payload_used, best_chain)
            # Since we found a vuln, we can stop here for this parameter
            return

        # If no time-based vuln was found via BO, let's try boolean-based with the best chain
        print(f"  [*] Optimizer didn't find time-based vuln. Trying boolean-based with best chain: {best_chain}")
        async def sender_with_best_chain(payload_to_inject):
            tampered_payload = apply_tampers(payload_to_inject, list(best_chain))
            request_args = await create_request_args(param_name, original_value + tampered_payload)
            body, duration, is_blocked = await self._send_headless_request(url, method, **request_args)
            return body, duration, is_blocked, best_chain

        bool_payload, bool_chain = await self._scan_boolean_based(sender_with_best_chain, baseline_hash, context)
        if bool_payload:
            await self._report_vulnerability(url, "Boolean-Based SQLi", param_name, bool_payload, bool_chain)
            return

        # TODO: Add OAST and Error-based checks here, also using the best_chain

    async def _report_vulnerability(self, url, vuln_type, param, payload, chain):
        vuln_info = {"url": url, "type": vuln_type, "parameter": param, "payload": payload, "tamper_chain": list(chain)}
        async with self.lock:
            print(f"[bold red][+] Vulnerability Found: {json.dumps(vuln_info)}[/bold red]")
            self.vulnerable_points.append(vuln_info)

    async def _scan_url(self, page: Page, url: str, collaborator_url: str | None):
        parsed_url = urlparse(url); query_params = parse_qs(parsed_url.query)
        if not query_params: return
        baseline_median, baseline_hash = await self._get_baseline(page, url, "GET", params=query_params)
        for param_name, values in query_params.items():
            def create_request_args(p_name, p_value):
                new_params = query_params.copy(); new_params[p_name] = p_value; return {'params': new_params}
            await self._run_scan_for_parameter(page, url, "GET", param_name, values[0], baseline_median, baseline_hash, collaborator_url, create_request_args)

    async def _scan_json_endpoint(self, page: Page, url: str, json_body: dict, collaborator_url: str | None):
        baseline_median, baseline_hash = await self._get_baseline(page, url, "POST", json_data=json_body)
        for key, value in json_body.items():
            if not isinstance(value, str): continue
            def create_request_args(k, v):
                new_json = json_body.copy(); new_json[k] = v; return {'json_data': new_json}
            await self._run_scan_for_parameter(page, url, "POST", key, value, baseline_median, baseline_hash, collaborator_url, create_request_args)

    async def _get_fresh_csrf_token(self, page: Page, form_page_url: str, csrf_field_name: str) -> str | None:
        try:
            await page.goto(form_page_url, wait_until="domcontentloaded"); soup = BeautifulSoup(await page.content(), 'html.parser')
            token_element = soup.find('input', {'name': csrf_field_name}); return token_element['value'] if token_element else None
        except Error as e: print(f"[!] Failed to fetch fresh CSRF token from {form_page_url}: {e}"); return None

    async def _scan_form(self, page: Page, form_details: dict, collaborator_url: str | None):
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
            async def create_form_request_args(p_name, p_value):
                form_data = base_data.copy(); form_data[p_name] = p_value
                if csrf_field_name:
                    fresh_token = await self._get_fresh_csrf_token(page, form_page_url, csrf_field_name)
                    if fresh_token: form_data[csrf_field_name] = fresh_token
                return {'data': form_data}
            await self._run_scan_for_parameter(page, url, method, param_name, input_to_test.get("value", ""), baseline_median, baseline_hash, collaborator_url, create_form_request_args)

    async def scan_target(self, target_item: dict, collaborator_url: str | None = None, db_type: str | None = None):
        # Initialize the payload generator with the detected DB type
        self.payload_generator = AstPayloadGenerator(dialect=db_type)

        await self._initialize_http_session()
        page = await self.context.new_page()
        try:
            target_type, url = target_item.get("type"), target_item.get("url")
            # Simple lock to prevent re-scanning the same URL if a vuln is found
            # A more robust check might be needed for complex apps
            async with self.lock:
                if any(p['url'] == url and p.get('parameter') for p in self.vulnerable_points):
                    print(f"[*] Skipping {url} as a vulnerability has already been found in this URL.")
                    return

            if target_type == 'form': await self._scan_form(page, target_item, collaborator_url)
            elif target_type == 'api' or (target_item.get("method", "GET").upper() == "POST" and target_item.get("content_type")):
                method, content_type = target_item.get("method", "GET").upper(), target_item.get("content_type")
                if method == "POST" and content_type and 'application/json' in content_type:
                    post_data = target_item.get("post_data")
                    json_body = json.loads(post_data) if isinstance(post_data, str) else post_data
                    await self._scan_json_endpoint(page, url, json_body, collaborator_url)
                else: await self._scan_url(page, url, collaborator_url)
            elif target_type == 'url': await self._scan_url(page, url, collaborator_url)
            else: print(f"[!] Skipping target with unhandled type: {target_type}")
        finally: await page.close()
