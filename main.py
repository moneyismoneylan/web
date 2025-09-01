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

async def main():
    """Main function to run the scanner."""
    parser = argparse.ArgumentParser(description="SQLi Hunter - An Advanced SQLi DAST Tool")
    parser.add_argument("-u", "--url", required=True, help="The target URL to scan (e.g., http://testphp.vulnweb.com)")
    parser.add_argument("-d", "--depth", type=int, default=2, help="The depth for the crawler to explore.")
    parser.add_argument("--no-crawl", action="store_true", help="Disable the crawler and only scan the provided URL.")
    parser.add_argument("--collaborator", help="Your Out-of-Band server URL (e.g., from Interactsh).")

    args = parser.parse_args()

    console = Console()
    display_banner(console)

    if not urlparse(args.url).scheme:
        args.url = "http://" + args.url

    console.print(f"[bold green][*] Target URL:[/] [link={args.url}]{args.url}[/link]")
    console.print(f"[bold green][*] Crawl Depth:[/] {args.depth}")
    if args.collaborator:
        console.print(f"[bold green][*] OOB Collaborator:[/] {args.collaborator}")

    target_urls = []

    async with httpx.AsyncClient() as client:
        if args.no_crawl:
            console.print("[yellow][!] Crawler disabled. Scanning only the provided URL.[/yellow]")
            target_urls.append(args.url)
        else:
            console.print("\n[bold cyan]--- Starting Crawler ---[/bold cyan]")
            crawler = Crawler(base_url=args.url, max_depth=args.depth)
            links, _ = await crawler.start_crawling() # We only care about links with params for now

            # Filter for URLs with query parameters, as they are injectable
            target_urls = [link for link in links if '?' in link]
            if not target_urls:
                 console.print("[yellow][!] No links with parameters found by the crawler.[/yellow]")
                 return

        console.print(f"\n[bold cyan]--- Starting Scanner on {len(target_urls)} URLs ---[/bold cyan]")
        scanner = Scanner(client)
        await scanner.scan(base_url=args.url, target_urls=target_urls, collaborator_url=args.collaborator)

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
        else:
            console.print("\n[bold green][-] No vulnerabilities were found.[/bold green]")

if __name__ == "__main__":
    asyncio.run(main())
