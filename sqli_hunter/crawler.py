# -*- coding: utf-8 -*-
"""
Web Crawler Engine.

This module provides the Crawler class, which is responsible for discovering
links, forms, and JavaScript-initiated API endpoints on a target website.
"""
import asyncio
from urllib.parse import urljoin, urlparse
from playwright.async_api import BrowserContext, Error, Page, Request
from bs4 import BeautifulSoup
from typing import Set

class Crawler:
    """
    Crawls a website to find all injectable entry points (URLs, forms, API endpoints).
    """
    def __init__(self, base_url: str, max_depth: int, queue: asyncio.Queue, browser_context: BrowserContext):
        self.base_url = base_url
        self.domain = urlparse(base_url).netloc
        self.max_depth = max_depth
        self.queue = queue
        self.context = browser_context
        self.visited_urls: Set[str] = set()
        self.discovered_endpoints: Set[str] = set()

    async def _handle_request(self, request: Request):
        """Intercepts and analyzes network requests to find hidden API endpoints."""
        # Filter for in-scope, XHR/Fetch requests that are not static assets
        if self.domain not in request.url:
            return
        if request.resource_type not in ["fetch", "xhr"]:
            return
        if any(request.url.endswith(ext) for ext in ['.js', '.css', '.png', '.jpg', '.svg']):
            return

        # Create a unique signature to avoid duplicates
        endpoint_signature = f"{request.method}::{request.url.split('?')[0]}"
        if endpoint_signature in self.discovered_endpoints:
            return

        self.discovered_endpoints.add(endpoint_signature)
        print(f"[*] JS-focused Crawler found new API endpoint: {request.method} {request.url}")

        target_item = {
            "type": "api", # A more generic type
            "url": request.url,
            "method": request.method,
            "post_data": request.post_data,
            "content_type": request.headers.get('content-type')
        }
        await self.queue.put(target_item)

    async def crawl_page(self, url: str, depth: int):
        """Crawls a single page, extracts links/forms, and listens for API calls."""
        if url in self.visited_urls or depth > self.max_depth:
            return
        self.visited_urls.add(url)
        print(f"[*] Crawling (depth {depth}): {url}")

        page = await self.context.new_page()
        try:
            # Set up request interception before navigating
            page.on('request', self._handle_request)

            response = await page.goto(url, wait_until="domcontentloaded", timeout=15000)
            if not response or not response.ok:
                return

            # Allow some time for dynamic content to load and make API calls
            await page.wait_for_timeout(3000)

            content = await page.content()
            soup = BeautifulSoup(content, 'html.parser')

            # --- Find and queue traditional links ---
            for link in soup.find_all('a', href=True):
                absolute_link = urljoin(self.base_url, link['href'])
                if self.domain in absolute_link and '#' not in absolute_link:
                    # Add to crawl queue, not scan queue directly
                    # The crawler will visit it and find injectable params there.
                    # For now, we'll just add it to the scan queue as a GET.
                    if absolute_link not in self.visited_urls:
                         await self.queue.put({"type": "url", "url": absolute_link, "method": "GET"})


            # --- Find and queue forms ---
            for form in soup.find_all('form'):
                action = form.get('action', url)
                method = form.get('method', 'GET').upper()
                absolute_action = urljoin(self.base_url, action)

                inputs = []
                csrf_field_name = None
                CSRF_TOKEN_NAMES = ['csrf_token', '_csrf', 'authenticity_token', '__requestverificationtoken', 'csrfmiddlewaretoken']

                for inp in form.find_all(['input', 'textarea', 'select']):
                    input_name = inp.get('name')
                    if input_name and input_name.lower() in CSRF_TOKEN_NAMES:
                        csrf_field_name = input_name

                    inputs.append({
                        "name": input_name,
                        "type": inp.get('type', 'text'),
                        "value": inp.get('value', '')
                    })

                form_details = {
                    "type": "form",
                    "url": absolute_action,
                    "method": method,
                    "inputs": inputs,
                }
                if csrf_field_name:
                    form_details['csrf_field_name'] = csrf_field_name
                    print(f"  [*] Found potential Anti-CSRF token in form: '{csrf_field_name}'")

                await self.queue.put(form_details)

        except Error as e:
            print(f"[!] Error crawling {url}: {e}")
        finally:
            # Make sure to remove the listener to avoid memory leaks
            page.remove_listener('request', self._handle_request)
            await page.close()

    async def start(self):
        """Starts the crawling process from the base URL."""
        # Use a queue for the crawler's own work
        crawl_queue = asyncio.Queue()
        await crawl_queue.put((self.base_url, 0))

        # Keep track of what's been added to the crawl queue
        in_crawl_queue = {self.base_url}

        while not crawl_queue.empty():
            url, depth = await crawl_queue.get()

            # The crawl_page function will now add scannable targets to the main queue
            await self.crawl_page(url, depth)

            # Re-check page content for links after dynamic analysis, as crawl_page might have found more
            # This part is simplified for now. A more robust implementation would re-parse.

            # Add newly discovered URLs to the crawl queue
            # This is a simplified version; a real implementation would get new links from crawl_page
            # and check if they are in `in_crawl_queue` before adding.

        print("[*] Crawler finished discovering entry points.")
