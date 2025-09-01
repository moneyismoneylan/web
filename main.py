# -*- coding: utf-8 -*-
"""
SQLi Hunter - Main Entry Point.

This is the main script to run the SQLi scanner. It uses argparse to handle
command-line arguments and orchestrates the Crawler and Scanner modules to
deliver a full end-to-end scan.
"""
import argparse
import asyncio
import httpx
from urllib.parse import urlparse

from rich.console import Console
from rich.table import Table

from sqli_hunter.crawler import Crawler
from sqli_hunter.scanner import Scanner
from sqli_hunter.exploiter import Exploiter
from sqli_hunter.waf_detector import WafDetector
from sqli_hunter.tamper import get_tampers_for_waf

# Number of concurrent scanner tasks
SCANNER_WORKERS = 10

def display_banner(console: Console):
    """Displays a cool ASCII art banner."""
    banner = """
[bold cyan]
   _____ ____  _     _   _    _    _   _ _____ _______   ____
  / ____/ __ \\| |   | | | |  | |  | | | |_   _|__   __| |  _ \\
 | (___| |  | | |   | | | |  | |  | | | | | |    | |    | |_) |
  \\___ \\ |  | | |   | | | |  | |  | | | | | |    | |    |  _ <
  ____) | |__| | |___| |_| |  | |__| |_| |_| |_   | |    | |_) |
 |_____/ \\____/|______\\___/    \\____/ \\___/|_____|  |_|    |____/
[/bold cyan]
[bold yellow]                         An Advanced SQLi DAST Tool[/bold yellow]
    """
    console.print(banner)

async def scanner_worker(queue: asyncio.Queue, scanner: Scanner, tampers: list[str], collaborator_url: str | None):
    """The consumer task that pulls targets from the queue and scans them."""
    while True:
        target_item = await queue.get()
        if target_item is None:
            # Sentinel value received, so exit
            break

        await scanner.scan_target(target_item, tampers, collaborator_url)
        queue.task_done()

async def main():
    """Main function to run the scanner with a producer-consumer model."""
    parser = argparse.ArgumentParser(description="SQLi Hunter - An Advanced SQLi DAST Tool")
    parser.add_argument("-u", "--url", required=True, help="The target URL to scan (e.g., http://testphp.vulnweb.com)")
    parser.add_argument("-d", "--depth", type=int, default=2, help="The depth for the crawler to explore.")
    parser.add_argument("--no-crawl", action="store_true", help="Disable the crawler and only scan the provided URL.")
    parser.add_argument("--collaborator", help="Your Out-of-Band server URL (e.g., from Interactsh).")
    parser.add_argument("--dump-db", action="store_true", help="Attempt to extract the database name after finding a vulnerability.")

    args = parser.parse_args()

    console = Console()
    display_banner(console)

    if not urlparse(args.url).scheme:
        args.url = "http://" + args.url

    console.print(f"[bold green][*] Target URL:[/] [link={args.url}]{args.url}[/link]")
    console.print(f"[bold green][*] Crawl Depth:[/] {args.depth}")
    if args.collaborator:
        console.print(f"[bold green][*] OOB Collaborator:[/] {args.collaborator}")

    queue = asyncio.Queue()

    async with httpx.AsyncClient() as client:
        # Detect WAF and select tampers once at the beginning
        waf_detector = WafDetector(client)
        waf_name = await waf_detector.check_waf(args.url)
        tampers_to_use = get_tampers_for_waf(waf_name)

        scanner = Scanner(client)

        # Create and start scanner workers
        scanner_tasks = []
        for _ in range(SCANNER_WORKERS):
            task = asyncio.create_task(scanner_worker(queue, scanner, tampers_to_use, args.collaborator))
            scanner_tasks.append(task)

        if args.no_crawl:
            console.print("[yellow][!] Crawler disabled. Scanning only the provided URL.[/yellow]")
            await queue.put({"type": "url", "target": args.url})
        else:
            console.print("\n[bold cyan]--- Starting Concurrent Crawl & Scan ---[/bold cyan]")
            crawler = Crawler(base_url=args.url, max_depth=args.depth, queue=queue, client=client)
            await crawler.start()

        # Wait for the queue to be fully processed
        await queue.join()

        # Signal scanner workers to exit
        for _ in range(SCANNER_WORKERS):
            await queue.put(None)

        # Wait for all scanner workers to finish
        await asyncio.gather(*scanner_tasks)

        console.print("\n[bold cyan]--- Scan Finished ---[/bold cyan]")
        if scanner.vulnerable_points:
            console.print("\n[bold red][!!!] VULNERABILITIES FOUND [!!!][/bold red]")
            table = Table(title="SQLi Hunter Scan Results")
            table.add_column("URL", style="cyan", no_wrap=True)
            table.add_column("Parameter", style="magenta")
            table.add_column("Type", style="green")
            table.add_column("Payload", style="red")

            for vuln in scanner.vulnerable_points:
                table.add_row(vuln['url'], vuln['parameter'], vuln['type'], str(vuln['payload']))

            console.print(table)

            if args.dump_db:
                # Try to exploit the first found error-based vulnerability
                error_based_vuln = next((v for v in scanner.vulnerable_points if "Error-Based" in v['type']), None)
                if error_based_vuln:
                    exploiter = Exploiter(client)
                    await exploiter.extract_data_error_based(error_based_vuln, tampers_to_use)
                else:
                    console.print("\n[yellow][!] --dump-db requires an error-based vulnerability, none was found.[/yellow]")

        else:
            console.print("\n[bold green][-] No vulnerabilities were found.[/bold green]")

if __name__ == "__main__":
    asyncio.run(main())
