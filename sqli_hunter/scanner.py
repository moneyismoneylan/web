# -*- coding: utf-8 -*-
import asyncio
from playwright.async_api import BrowserContext, Page, Error
import re
from urllib.parse import urlparse, parse_qs, urljoin
import time
import base64
import statistics
import uuid
import json
import random
from simhash import Simhash
import dns.asyncresolver
import httpx
from bs4 import BeautifulSoup
from sqli_hunter.payloads import SQL_ERROR_PATTERNS, ERROR_BASED_PAYLOADS, BOOLEAN_BASED_PAYLOADS, TIME_BASED_PAYLOADS, OOB_PAYLOADS
from sqli_hunter.tamper import apply_tampers, TamperSelector
from sqli_hunter.polymorphic_engine import PolymorphicEngine
from typing import Callable, Awaitable, Any, Tuple, List, Set, Dict
from collections import defaultdict

WAF_TEMPO_MAP = { "Cloudflare": 1.5, "AWS WAF": 0.5, "Imperva (Incapsula)": 1.0 }
CONTEXT_PAYLOAD_PREFIX = {
    "HTML_ATTRIBUTE_SINGLE_QUOTED": "'", "HTML_ATTRIBUTE_DOUBLE_QUOTED": "\"",
    "JS_STRING_SINGLE_QUOTED": "'", "JS_STRING_DOUBLE_QUOTED": "\"",
}
MAX_BACKOFF_DELAY = 60.0

class Scanner:
    def __init__(self, browser_context: BrowserContext, canary_store: Dict, waf_name: str | None = None):
        self.context = browser_context
        self.vulnerable_points = []
        self.lock = asyncio.Lock()
        self.polymorphic_engine = PolymorphicEngine()
        self.dns_resolver = dns.asyncresolver.Resolver()
        self.tamper_selector = TamperSelector(waf_name=waf_name)
        self.canary_store = canary_store
        self.static_request_delay = WAF_TEMPO_MAP.get(waf_name, 0)
        self.rate_limit_active = False
        self.rate_limit_delay = 1.0
        self.successful_requests_since_rl = 0
        self.httpx_client: httpx.AsyncClient | None = None
        if self.static_request_delay > 0: print(f"[*] WAF policy adaptation: Applying a {self.static_request_delay}s delay between requests.")

    async def _initialize_httpx_client(self):
        if getattr(self, 'httpx_client', None) is None:
            cookies = await self.context.cookies()
            httpx_cookies = httpx.Cookies()
            for cookie in cookies: httpx_cookies.set(cookie['name'], cookie['value'], domain=cookie['domain'])
            self.httpx_client = httpx.AsyncClient(cookies=httpx_cookies, follow_redirects=True, verify=False)

    async def close(self):
        if getattr(self, 'httpx_client', None): await self.httpx_client.aclose()

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
            response = await self.httpx_client.request(method, url, params=params, data=data, json=json_data, timeout=timeout)
            duration = time.monotonic() - start_time; body = response.text; status = response.status_code
            is_blocked = status in [403, 406] or any(s in body.lower() for s in ["request blocked", "forbidden", "waf"])
            self._update_rate_limit_status(status, is_blocked)
            return body, duration, is_blocked
        except httpx.RequestError: return None, time.monotonic() - start_time, False

    async def _send_browser_request(self, page: Page, url: str, method: str = "GET", params: dict = None, data: dict = None, json_data: dict = None, timeout: int = 30000) -> tuple[str | None, float, bool]:
        start_time = time.monotonic()
        try:
            response = await page.request.request(url, method=method, params=params, data=data, json=json_data, timeout=timeout)
            duration = time.monotonic() - start_time; body = await response.text(); status = response.status
            is_blocked = status in [403, 406] or any(s in body.lower() for s in ["request blocked", "forbidden", "waf"])
            self._update_rate_limit_status(status, is_blocked)
            return body, duration, is_blocked
        except Error: return None, time.monotonic() - start_time, False

    async def _get_baseline(self, page: Page, url: str, method: str, params: dict = None, data: dict = None, json_data: dict = None) -> tuple[float, Simhash | None]:
        timings, content_for_hash = [], None
        for _ in range(3):
            content, duration, _ = await self._send_browser_request(page, url, method=method, params=params, data=data, json_data=json_data)
            timings.append(duration)
            if content and content_for_hash is None: content_for_hash = content
        if not timings: return 0.0, None
        return statistics.median(timings), Simhash(content_for_hash) if content_for_hash else None

    async def _perform_taint_analysis(self, page: Page, url: str, method: str, create_request_args: Callable) -> Set[str]:
        taint = "sqlihunter" + uuid.uuid4().hex[:8]
        request_args = create_request_args(taint)
        body, _, is_blocked = await self._send_browser_request(page, url, method, **request_args)
        if is_blocked or not body or taint not in body: return set()
        contexts = set()
        if re.search(f"'[^>]*{taint}[^>]*'", body, re.IGNORECASE): contexts.update(["HTML_ATTRIBUTE_SINGLE_QUOTED", "JS_STRING_SINGLE_QUOTED"])
        if re.search(f'"[^>]*{taint}[^>]*"', body, re.IGNORECASE): contexts.update(["HTML_ATTRIBUTE_DOUBLE_QUOTED", "JS_STRING_DOUBLE_QUOTED"])
        if re.search(f">(?!'|\")[^<]*{taint}[^<]*<", body, re.IGNORECASE): contexts.add("HTML_TEXT")
        if contexts: print(f"  [*] Taint Analysis found reflection contexts: {list(contexts)}")
        return contexts

    async def _check_oast_interaction(self, domain: str) -> bool:
        await asyncio.sleep(2);
        try: await self.dns_resolver.resolve(domain, 'A'); return True
        except Exception: return False

    async def _scan_oast(self, payloads: List, sender_func: Callable, collaborator_url: str) -> Tuple[str | None, tuple | None]:
        if not collaborator_url: return None, None
        for payload_template in payloads:
            oast_id = uuid.uuid4().hex[:12]; oast_domain = f"{oast_id}.{collaborator_url}"
            payload = payload_template.format(collaborator_url=oast_domain)
            _, _, _, chain = await sender_func(payload)
            if await self._check_oast_interaction(oast_domain): return payload, chain
        return None, None

    async def _scan_boolean_based(self, payloads: List, sender_func: Callable, baseline_hash: Simhash) -> Tuple[str | None, tuple | None]:
        if not baseline_hash: return None, None
        for true_payload, false_payload, _ in payloads:
            true_content, _, is_blocked_true, chain_true = await sender_func(true_payload)
            if is_blocked_true or not true_content: continue
            false_content, _, is_blocked_false, _ = await sender_func(false_payload)
            if is_blocked_false or not false_content: continue
            if baseline_hash.distance(Simhash(true_content)) < 3 and Simhash(true_content).distance(Simhash(false_content)) > 3:
                return f"TRUE: {true_payload}, FALSE: {false_payload}", chain_true
        return None, None

    async def _scan_time_based(self, payloads: List, sender_func: Callable, baseline_median: float) -> Tuple[str | None, tuple | None]:
        for payload_template, sleep_time, _ in payloads:
            payload = payload_template.format(sleep=sleep_time); durations, chain = [], None
            for _ in range(2):
                _, duration, is_blocked, used_chain = await sender_func(payload)
                if chain is None: chain = used_chain
                durations.append(baseline_median if is_blocked else duration)
            if statistics.median(durations) > baseline_median + (sleep_time * 0.7): return payload, chain
        return None, None

    async def _run_scan_for_parameter(self, page: Page, url: str, method: str, param_name: str, original_value: str, baseline_median: float, baseline_hash: Simhash, collaborator_url: str, create_request_args: Callable):
        total_delay = self.static_request_delay
        if self.rate_limit_active: total_delay += self.rate_limit_delay
        if total_delay > 0: await asyncio.sleep(total_delay * random.uniform(0.8, 1.2))

        taint_contexts = await self._perform_taint_analysis(page, url, method, lambda taint: create_request_args(param_name, original_value + taint))
        prefix = CONTEXT_PAYLOAD_PREFIX.get(next(iter(taint_contexts), None), "")

        async def sender_with_learning(payload_to_inject):
            chain = self.tamper_selector.select_chain()
            tampered_payload = apply_tampers(prefix + payload_to_inject, list(chain))
            request_args = create_request_args(param_name, original_value + tampered_payload)
            body, duration, is_blocked = await self._send_headless_request(url, method, **request_args)
            if is_blocked: self.tamper_selector.update_stats(chain, -1.0)
            return body, duration, is_blocked, chain

        # --- Prioritized Payload Scheduling ---
        family_scores = defaultdict(lambda: 1.0)

        # Seeding round
        seeding_payloads = {p[2]: p for p in TIME_BASED_PAYLOADS}.values() # Get one from each family
        print(f"  [*] Running seeding round with {len(seeding_payloads)} payload families...")
        for p_template, sleep, family in seeding_payloads:
            _, duration, is_blocked, _ = await sender_with_learning(p_template.format(sleep=2)) # Use short sleep for seeding
            if is_blocked: family_scores[family] *= 0.1 # Heavily penalize
            elif duration > baseline_median + 1.4: family_scores[family] *= 5.0 # Boost

        # Prioritize payload lists
        sorted_time_payloads = sorted(TIME_BASED_PAYLOADS, key=lambda p: family_scores[p[2]], reverse=True)
        sorted_bool_payloads = sorted(BOOLEAN_BASED_PAYLOADS, key=lambda p: family_scores[p[2]], reverse=True)

        scan_functions = [
            (self._scan_time_based, (sorted_time_payloads, sender_with_learning, baseline_median), "Time-Based SQLi"),
            (self._scan_boolean_based, (sorted_bool_payloads, sender_with_learning, baseline_hash), "Boolean-Based SQLi"),
            (self._scan_oast, (OOB_PAYLOADS, sender_with_learning, collaborator_url), "OAST-Based SQLi"),
        ]
        if self.rate_limit_active: random.shuffle(scan_functions)

        for scan_func, args, vuln_type in scan_functions:
            payload, chain = await scan_func(*args)
            if payload:
                self.tamper_selector.update_stats(chain, 1.0)
                await self._report_vulnerability(url, vuln_type, param_name, prefix + payload, chain)
                return

    async def _report_vulnerability(self, url, vuln_type, param, payload, chain):
        vuln_info = {"url": url, "type": vuln_type, "parameter": param, "payload": payload, "tamper_chain": list(chain)}
        async with self.lock: print(f"[+] Vulnerability Found: {vuln_info}"); self.vulnerable_points.append(vuln_info)

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
        await self._initialize_httpx_client()
        page = await self.context.new_page()
        try:
            target_type, url = target_item.get("type"), target_item.get("url")
            async with self.lock:
                if any(p['url'] == url and p.get('parameter') for p in self.vulnerable_points):
                    print(f"[*] Skipping {url} as a vulnerability has already been found."); return
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
