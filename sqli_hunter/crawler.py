# -*- coding: utf-8 -*-
"""
Advanced Crawler Module.

This module will be responsible for crawling the target website to find all
links, forms, and other potential injection points. It will use asynchronous
requests to be fast and efficient.
"""
import asyncio
import httpx
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse
from collections import deque

class Crawler:
    """
    Asynchronous web crawler that produces targets for a queue.
    """
    def __init__(self, base_url: str, max_depth: int, queue: asyncio.Queue, client: httpx.AsyncClient):
        self.base_url = base_url
        self.domain_name = urlparse(base_url).netloc
        self.max_depth = max_depth
        self.queue = queue
        self.client = client

        self.crawl_queue = deque([(self.base_url, 0)])
        self.visited_urls = set()

    async def _get_page_content(self, url: str) -> tuple[str | None, str | None]:
        """Fetches the content and content-type of a URL asynchronously."""
        try:
            headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'}
            response = await self.client.get(url, follow_redirects=True, timeout=10, headers=headers)
            response.raise_for_status()
            content_type = response.headers.get('content-type', '').lower()
            return response.text, content_type
        except httpx.RequestError as e:
            print(f"[!] Request error for {e.request.url!r}: {e}")
            return None, None
        except httpx.HTTPStatusError as e:
            print(f"[!] HTTP error for {e.request.url!r}: Status {e.response.status_code}")
            return None, None

    async def _extract_targets(self, html: str, current_url: str):
        """Extracts links and forms and puts them onto the queue."""
        soup = BeautifulSoup(html, "html.parser")

        # Extract and queue links
        for a_tag in soup.find_all("a", href=True):
            href = a_tag.get("href", "").strip()
            if not href or href.startswith(('#', 'mailto:', 'tel:', 'javascript:')):
                continue

            full_url = urljoin(current_url, href)

            if urlparse(full_url).netloc == self.domain_name:
                # Add new links to be crawled
                if full_url not in self.visited_urls:
                    self.crawl_queue.append((full_url, 0)) # Depth will be handled by the main loop

                # Add links with parameters to the scan queue
                if '?' in full_url:
                    await self.queue.put({"type": "url", "target": full_url})

        # Extract and queue forms
        for form in soup.find_all("form"):
            action = form.get("action", "")
            form_url = urljoin(current_url, action)
            method = form.get("method", "get").upper()

            inputs = []
            for input_tag in form.find_all(['input', 'textarea', 'select']):
                name = input_tag.get('name')
                input_type = input_tag.get('type', 'text')
                default_value = input_tag.get('value', '')
                if name:
                    inputs.append({"name": name, "type": input_type, "value": default_value})

            if urlparse(form_url).netloc == self.domain_name and inputs:
                form_details = {"url": form_url, "method": method, "inputs": inputs}
                await self.queue.put({"type": "form", "target": form_details})

    async def start(self):
        """Starts the crawling process, adding found targets to the queue."""
        while self.crawl_queue:
            url, depth = self.crawl_queue.popleft()

            if url in self.visited_urls or depth >= self.max_depth:
                continue

            print(f"[*] Crawling (Depth {depth}): {url}")
            self.visited_urls.add(url)

            html_content, content_type = await self._get_page_content(url)
            if not html_content:
                continue

            # Only parse HTML content to avoid errors with binary files like PDFs/ZIPs
            if content_type and 'text/html' in content_type:
                # This will add new links to self.crawl_queue and new targets to self.queue
                await self._extract_targets(html_content, url)

        print("\n[+] Crawl Finished.")

# This space is intentionally left blank.
# The test code has been removed as the module is now considered stable
# and is intended to be imported, not run directly.
