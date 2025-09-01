# -*- coding: utf-8 -*-
"""
Advanced Crawler Module.

This module will be responsible for crawling the target website to find all
links, forms, and other potential injection points. It will use asynchronous
requests to be fast and efficient.
"""
import asyncio
from playwright.async_api import BrowserContext, Error
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse
from collections import deque

class Crawler:
    """
    Asynchronous, browser-based web crawler that produces targets for a queue.
    """
    def __init__(self, base_url: str, max_depth: int, queue: asyncio.Queue, browser_context: BrowserContext):
        self.base_url = base_url
        self.domain_name = urlparse(base_url).netloc
        self.max_depth = max_depth
        self.queue = queue
        self.context = browser_context

        self.crawl_queue = deque([(self.base_url, 0)])
        self.visited_urls = set()

    async def _get_page_content(self, page, url: str) -> tuple[str | None, str | None]:
        """Navigates to a URL and returns its content and content-type."""
        try:
            response = await page.goto(url, wait_until="domcontentloaded", timeout=15000)
            if response is None: return None, None

            content_type = response.headers.get('content-type', '').lower()
            content = await page.content()
            return content, content_type
        except Error as e:
            print(f"[!] Playwright error for {url}: {e}")
            return None, None

    async def _extract_targets(self, page, current_url: str):
        """Extracts links and forms from a Playwright page and puts them onto the queue."""
        # Extract and queue links
        links = await page.eval_on_selector_all("a", "elements => elements.map(a => a.href)")
        for link in links:
            if not link or link.startswith(('#', 'mailto:', 'tel:', 'javascript:')):
                continue

            full_url = urljoin(current_url, link)

            if urlparse(full_url).netloc == self.domain_name:
                if full_url not in self.visited_urls:
                    self.crawl_queue.append((full_url, 0))

                if '?' in full_url:
                    await self.queue.put({"type": "url", "target": full_url})

        # Extract and queue forms using Playwright's locators
        forms = await page.locator("form").all()
        for form in forms:
            action = await form.get_attribute("action") or ""
            form_url = urljoin(current_url, action)
            method = await form.get_attribute("method") or "GET"

            inputs = []
            input_locators = await form.locator("input, textarea, select").all()
            for locator in input_locators:
                name = await locator.get_attribute("name")
                if name:
                    inputs.append({
                        "name": name,
                        "type": await locator.get_attribute("type") or "text",
                        "value": await locator.input_value()
                    })

            if urlparse(form_url).netloc == self.domain_name and inputs:
                form_details = {"url": form_url, "method": method.upper(), "inputs": inputs}
                await self.queue.put({"type": "form", "target": form_details})

    async def start(self):
        """Starts the crawling process, adding found targets to the queue."""
        page = await self.context.new_page()
        try:
            while self.crawl_queue:
                url, depth = self.crawl_queue.popleft()

                if url in self.visited_urls or depth >= self.max_depth:
                    continue

                print(f"[*] Crawling (Depth {depth}): {url}")
                self.visited_urls.add(url)

                html_content, content_type = await self._get_page_content(page, url)
                if not html_content:
                    continue

                if content_type and 'text/html' in content_type:
                    await self._extract_targets(page, url)
        finally:
            await page.close()
            print("\n[+] Crawl Finished.")

# This space is intentionally left blank.
# The test code has been removed as the module is now considered stable
# and is intended to be imported, not run directly.
