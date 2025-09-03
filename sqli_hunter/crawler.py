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
        self.scan_queue = queue
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
        await self.scan_queue.put({
            "type": "api", "url": request.url, "method": request.method,
            "post_data": request.post_data, "content_type": request.headers.get('content-type')
        })

    async def crawl_page(self, url: str) -> List[str]:
        if url in self.visited_urls:
            return []
        self.visited_urls.add(url)

        page = await self.context.new_page()
        found_links = []
        try:
            page.on('request', self._handle_request)

            print(f"  [*] Navigating to {url} with Playwright...")
            response = await page.goto(url, wait_until="domcontentloaded", timeout=120000)

            # Simulate human-like mouse movements to evade behavioral bot detection
            try:
                for i in range(10):
                    await page.mouse.move(
                        random.randint(0, 1000),
                        random.randint(0, 800),
                        steps=random.randint(5, 15)
                    )
                    await asyncio.sleep(random.uniform(0.1, 0.3))
            except Exception:
                pass # Ignore errors if the page closes unexpectedly

            await page.wait_for_timeout(5000) # Wait for potential background JS checks

            if not response.ok:
                print(f"  [!] Received non-OK status {response.status} from {url}. Checking for JS challenge...")
                content = await page.content()
                if "challenge-platform" in content or "cf-challenge" in content:
                    print("  [!] Cloudflare challenge detected. Waiting for resolution...")
                    try:
                        # Wait for either a successful navigation or for the network to be idle for a while
                        await page.wait_for_url(lambda url: url != page.url, timeout=60000)
                        print("  [+] Navigation after challenge detected. Proceeding...")
                    except Error:
                        print("  [!] Timed out waiting for navigation. Trying to wait for network idle...")
                        await page.wait_for_load_state('networkidle', timeout=60000)
                        print("  [*] Network is now idle. Proceeding with page content.")
                else:
                    print("  [!] No JS challenge detected. Aborting crawl for this page.")
                    return []

            content = await page.content()
            soup = BeautifulSoup(content, 'html.parser')

            if '?' in page.url:
                await self.scan_queue.put({"type": "url", "url": page.url, "method": "GET"})

            for link in soup.find_all('a', href=True):
                absolute_link = urljoin(page.url, link['href']).split('#')[0]
                if self.domain in absolute_link and absolute_link not in self.visited_urls:
                    found_links.append(absolute_link)

            for form in soup.find_all('form'):
                action = form.get('action', page.url)
                method = form.get('method', 'GET').upper()
                absolute_action = urljoin(page.url, action)
                inputs = [{"name": i.get('name'), "type": i.get('type', 'text'), "value": i.get('value', '')} for i in form.find_all(['input', 'textarea', 'select'])]
                await self.scan_queue.put({"type": "form", "url": absolute_action, "method": method, "inputs": inputs})

        except Error as e:
            print(f"[!] Critical Playwright error crawling {url}: {e}")
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
                print(f"  [!] Max depth reached. Not crawling links from this page.")
                await self.crawl_page(url)
                continue

            new_links = await self.crawl_page(url)
            for link in new_links:
                if link not in in_crawl_queue:
                    in_crawl_queue.add(link)
                    await crawl_queue.put((link, depth + 1))

        print("[*] Crawler finished discovering entry points.")
