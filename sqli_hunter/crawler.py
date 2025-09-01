# -*- coding: utf-8 -*-
"""
Web Crawler Engine.

This module provides the Crawler class, which is responsible for discovering
links, forms, and JavaScript-initiated API endpoints on a target website.
"""
import asyncio
import random
from urllib.parse import urljoin, urlparse
from playwright.async_api import BrowserContext, Error, Page, Request
from bs4 import BeautifulSoup
from typing import Set, List

class Crawler:
    """
    Crawls a website to find all injectable entry points (URLs, forms, API endpoints).
    """
    def __init__(self, base_url: str, max_depth: int, queue: asyncio.Queue, browser_context: BrowserContext):
        self.base_url = base_url
        self.domain = urlparse(base_url).netloc
        self.max_depth = max_depth
        self.scan_queue = queue # Renamed for clarity
        self.context = browser_context
        self.visited_urls: Set[str] = set()
        self.discovered_endpoints: Set[str] = set()

    async def _handle_request(self, request: Request):
        """Intercepts and analyzes network requests to find hidden API endpoints."""
        if self.domain not in request.url:
            return
        if request.resource_type not in ["fetch", "xhr"]:
            return
        if any(request.url.endswith(ext) for ext in ['.js', '.css', '.png', '.jpg', '.svg']):
            return

        endpoint_signature = f"{request.method}::{request.url.split('?')[0]}"
        if endpoint_signature in self.discovered_endpoints:
            return

        self.discovered_endpoints.add(endpoint_signature)
        print(f"[*] JS-focused Crawler found new API endpoint: {request.method} {request.url}")

        target_item = {
            "type": "api",
            "url": request.url,
            "method": request.method,
            "post_data": request.post_data,
            "content_type": request.headers.get('content-type')
        }
        await self.scan_queue.put(target_item)

    async def crawl_page(self, url: str) -> List[str]:
        """
        Crawls a single page, queues injectable targets for the scanner,
        and returns a list of new, in-scope links to be crawled.
        """
        if url in self.visited_urls:
            return []
        self.visited_urls.add(url)

        page = await self.context.new_page()
        # Stealth is now applied automatically by the context manager in main.py

        found_links = []
        try:
            # --- Header Jitter Implementation ---
            async def handle_route(route):
                headers = await route.request.all_headers()

                # Randomize case of header keys
                new_headers = {k.capitalize() if random.random() > 0.5 else k.lower(): v for k, v in headers.items()}

                # Shuffle header order
                new_headers_list = list(new_headers.items())
                random.shuffle(new_headers_list)

                await route.continue_(headers=dict(new_headers_list))

            # Intercept all requests to apply header jitter
            await page.route("**/*", handle_route)
            # --- End Header Jitter ---

            page.on('request', self._handle_request)
            response = await page.goto(url, wait_until="domcontentloaded", timeout=15000)

            if not response:
                print(f"  [!] Crawler received no response from {url}")
                return []

            if not response.ok:
                print(f"  [!] Crawler received non-OK status {response.status} from {url}")
                return []

            # Wait for the network to be idle, which is a better signal for SPAs
            print(f"  [*] Waiting for network idle on {url}...")
            await page.wait_for_load_state('networkidle', timeout=10000)
            print(f"  [*] Network is idle. Parsing page content.")

            # --- Simulate Human-like Interaction ---
            try:
                await page.mouse.move(random.randint(100, 500), random.randint(100, 500), steps=5)
                await asyncio.sleep(0.5)
                await page.mouse.wheel(delta_y=random.randint(100, 300), delta_x=0)
            except Exception as e:
                print(f"  [!] Could not simulate mouse movement: {e}")
            # --- End Human-like Interaction ---

            # --- DEBUGGING: Save screenshot and HTML content ---
            screenshot_path = f"debug_screenshot_{url.replace('/', '_').replace(':', '')}.png"
            print(f"  [DEBUG] Saving screenshot to {screenshot_path}")
            await page.screenshot(path=screenshot_path)

            content = await page.content()

            # print(f"  [DEBUG] Page HTML:\n{content}\n") # This might be too verbose
            # --- END DEBUGGING ---

            soup = BeautifulSoup(content, 'html.parser')

            # Find and queue URLs with query parameters for scanning
            if '?' in url:
                await self.scan_queue.put({"type": "url", "url": url, "method": "GET"})

            # Find and return traditional links for further crawling
            for link in soup.find_all('a', href=True):
                absolute_link = urljoin(self.base_url, link['href']).split('#')[0]
                if self.domain in absolute_link and absolute_link not in self.visited_urls:
                    found_links.append(absolute_link)

            # Find and queue forms for scanning
            for form in soup.find_all('form'):
                action = form.get('action', url)
                method = form.get('method', 'GET').upper()
                absolute_action = urljoin(self.base_url, action)
                inputs = [{"name": i.get('name'), "type": i.get('type', 'text'), "value": i.get('value', '')} for i in form.find_all(['input', 'textarea', 'select'])]
                await self.scan_queue.put({"type": "form", "url": absolute_action, "method": method, "inputs": inputs})

        except Error as e:
            print(f"[!] Error crawling {url}: {e}")
        finally:
            page.remove_listener('request', self._handle_request)
            await page.close()

        return found_links

    async def start(self):
        """Starts the crawling process from the base URL."""
        crawl_queue = asyncio.Queue()
        await crawl_queue.put((self.base_url, 0))

        in_crawl_queue = {self.base_url}

        while not crawl_queue.empty():
            url, depth = await crawl_queue.get()

            print(f"[*] Crawling (depth {depth}): {url}")

            if depth >= self.max_depth:
                print(f"  [!] Max depth ({self.max_depth}) reached. Not crawling links from this page.")
                # We still crawl the page itself to find forms/apis, but not its children.
                await self.crawl_page(url)
                continue

            new_links = await self.crawl_page(url)

            for link in new_links:
                if link not in in_crawl_queue:
                    in_crawl_queue.add(link)
                    await crawl_queue.put((link, depth + 1))

        print("[*] Crawler finished discovering entry points.")
