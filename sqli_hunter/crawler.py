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
    Asynchronous web crawler to discover links and forms on a website.
    """
    def __init__(self, base_url: str, max_depth: int = 2):
        self.base_url = base_url
        self.domain_name = urlparse(base_url).netloc
        self.max_depth = max_depth

        self.queue = deque([(self.base_url, 0)])
        self.visited_urls = set()

        self.discovered_links = set()
        self.discovered_forms = []

    async def _get_page_content(self, client: httpx.AsyncClient, url: str) -> str | None:
        """Fetches the content of a URL asynchronously."""
        try:
            # Using a common user-agent
            headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'}
            response = await client.get(url, follow_redirects=True, timeout=10, headers=headers)
            response.raise_for_status()
            return response.text
        except httpx.RequestError as e:
            print(f"[!] Request error for {e.request.url!r}: {e}")
            return None
        except httpx.HTTPStatusError as e:
            print(f"[!] HTTP error for {e.request.url!r}: Status {e.response.status_code}")
            return None

    def _extract_all_links(self, html: str, current_url: str):
        """Extracts all valid, same-domain links from HTML content."""
        soup = BeautifulSoup(html, "html.parser")
        for a_tag in soup.find_all("a", href=True):
            href = a_tag.get("href", "").strip()
            if not href or href.startswith(('#', 'mailto:', 'tel:', 'javascript:')):
                continue

            full_url = urljoin(current_url, href)

            if urlparse(full_url).netloc == self.domain_name:
                self.discovered_links.add(full_url)

    def _extract_all_forms(self, html: str, current_url: str):
        """Extracts all forms and their input fields from HTML content."""
        soup = BeautifulSoup(html, "html.parser")
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

            # Only add forms that have injectable fields and are on the same domain
            if urlparse(form_url).netloc == self.domain_name and inputs:
                self.discovered_forms.append({
                    "url": form_url,
                    "method": method,
                    "inputs": inputs
                })

    async def start_crawling(self):
        """Starts the crawling process."""
        async with httpx.AsyncClient() as client:
            while self.queue:
                url, depth = self.queue.popleft()

                if url in self.visited_urls or depth >= self.max_depth:
                    continue

                print(f"[*] Crawling (Depth {depth}): {url}")
                self.visited_urls.add(url)

                html_content = await self._get_page_content(client, url)
                if not html_content:
                    continue

                self._extract_all_links(html_content, url)
                self._extract_all_forms(html_content, url)

                # Add newly discovered links to the queue
                for link in self.discovered_links:
                    if link not in self.visited_urls:
                        self.queue.append((link, depth + 1))

        print("\n[+] Crawl Finished.")
        print(f"[*] Found {len(self.discovered_links)} unique links.")
        print(f"[*] Found {len(self.discovered_forms)} forms.")
        return list(self.discovered_links), self.discovered_forms

# This space is intentionally left blank.
# The test code has been removed as the module is now considered stable
# and is intended to be imported, not run directly.
