# -*- coding: utf-8 -*-
"""
SQLi Hunter - Main Entry Point.
"""
import argparse
import asyncio
import json
import random
from urllib.parse import urlparse
from playwright.async_api import async_playwright
from playwright_stealth.stealth import Stealth
from rich.console import Console
from rich.table import Table
import dns.asyncresolver
import cloudscraper

from sqli_hunter.crawler import Crawler
from sqli_hunter.scanner import Scanner
from sqli_hunter.exploiter import Exploiter
from sqli_hunter.waf_detector import WafDetector

SCANNER_WORKERS = 10

def display_banner(console: Console):
    banner = "[bold cyan]... (banner omitted for brevity) ...[/bold cyan]"
    console.print(banner)

def deduplicate_vulnerabilities(vulnerabilities: list) -> list:
    """Groups vulnerabilities by root cause (URL, parameter, type) and returns a unique list."""
    seen_signatures = set()
    unique_vulns = []
    for vuln in vulnerabilities:
        vuln_type_general = vuln['type'].split('(')[0].strip()
        signature = (vuln['url'], vuln.get('parameter'), vuln_type_general)
        if signature not in seen_signatures:
            unique_vulns.append(vuln)
            seen_signatures.add(signature)
    return unique_vulns

async def scanner_worker(queue: asyncio.Queue, scanner: Scanner, collaborator_url: str | None):
    while True:
        target_item = await queue.get()
        if target_item is None: break
        try:
            await asyncio.wait_for(
                scanner.scan_target(target_item, collaborator_url),
                timeout=600.0
            )
        except asyncio.TimeoutError:
            url = target_item.get("url", "Unknown Target")
            print(f"[!] Target timed out and was skipped: {url}")
        except Exception as e:
            url = target_item.get("url", "Unknown Target")
            print(f"[!] An unexpected error occurred while scanning {url}: {e}")
        finally:
            queue.task_done()

async def run_scan_logic(args: dict, console: Console | None = None):
    """The core logic of the scanner, refactored to be callable from other modules."""
    if console is None:
        console = Console()

    url = args.get("url")
    if not url:
        console.print("[red]URL is a required argument.[/red]")
        return

    if not urlparse(url).scheme:
        url = "http://" + url

    console.print(f"[bold green][*] Target URL:[/] [link={url}]{url}[/link]")

    async with Stealth().use_async(async_playwright()) as p:
        browser = await p.chromium.launch()
        context = await browser.new_context(
            user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0.0.0 Safari/537.36",
            viewport={
                'width': 1280 + random.randint(0, 100),
                'height': 720 + random.randint(0, 100)
            },
            locale='en-US',
            timezone_id='America/New_York'
        )
        if args.get("cookie"):
            try:
                name, value = args["cookie"].split('=', 1)
                await context.add_cookies([{"name": name.strip(), "value": value.strip(), "domain": urlparse(url).netloc}])
                console.print("[green][*] Session cookie set.[/green]")
            except ValueError:
                console.print("[red][!] Invalid cookie format. Please use 'name=value'.[/red]")

        queue = asyncio.Queue()
        scraper = cloudscraper.create_scraper()
        waf_detector = WafDetector(context, scraper)
        waf_name = await waf_detector.check_waf(url)

        canary_store = {}
        scanner = Scanner(
            context,
            scraper,
            canary_store=canary_store,
            waf_name=waf_name,
            n_calls=args.get("n_calls", 25),
            debug=args.get("debug", False),
            adv_tamper=args.get("adv_tamper", False)
        )
        scanner_tasks = [asyncio.create_task(scanner_worker(queue, scanner, args.get("collaborator"))) for _ in range(SCANNER_WORKERS)]

        if args.get("retest"):
            console.print(f"\n[bold cyan]--- Running in Re-test Mode using {args['retest']} ---[/bold cyan]")
            try:
                with open(args['retest'], 'r') as f:
                    previous_vulns = json.load(f)
                urls_to_test = {vuln['url'] for vuln in previous_vulns}
                for u in urls_to_test:
                    await queue.put({"type": "url", "url": u, "method": "GET"})
                console.print(f"[*] Queued {len(urls_to_test)} unique URLs for re-testing.")
            except (IOError, json.JSONDecodeError) as e:
                console.print(f"[bold red][!] Error reading re-test file: {e}[/bold red]")
                return
        elif args.get("no_crawl"):
            console.print("[yellow][!] Crawler disabled. Scanning only the provided URL.[/yellow]")
            await queue.put({"type": "url", "url": url, "method": "GET"})
        else:
            console.print("\n[bold cyan]--- Starting Concurrent Crawl & Scan ---[/bold cyan]")
            crawler = Crawler(base_url=url, max_depth=args.get("depth", 3), queue=queue, browser_context=context)
            await crawler.start()

        await queue.join()
        for _ in range(SCANNER_WORKERS): await queue.put(None)
        await asyncio.gather(*scanner_tasks)

        if canary_store and args.get("collaborator"):
            console.print("\n[bold cyan]--- Verifying Stored SQLi Canaries ---[/bold cyan]")
            resolver = dns.asyncresolver.Resolver()
            for canary_id, sink_info in canary_store.items():
                domain_to_check = f"{canary_id}.stored.{args['collaborator']}"
                try:
                    await resolver.resolve(domain_to_check, 'A')
                    vuln_info = {"url": sink_info['url'], "type": "Stored SQLi (via OAST)", "parameter": sink_info['param'], "payload": f"Canary {canary_id} triggered."}
                    scanner.vulnerable_points.append(vuln_info)
                    console.print(f"[bold red][+] Stored SQLi Detected![/bold red] Canary from {sink_info['url']} (param: {sink_info['param']}) triggered.")
                except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer): pass
                except Exception as e: console.print(f"[yellow][!] Error checking canary {canary_id}: {e}[/yellow]")

        console.print("\n[bold cyan]--- Scan Finished ---[/bold cyan]")
        unique_vulnerabilities = deduplicate_vulnerabilities(scanner.vulnerable_points)

        if unique_vulnerabilities:
            console.print("\n[bold red][!!!] VULNERABILITIES FOUND [!!!][/bold red]")
            table = Table(title="SQLi Hunter Scan Results (De-duplicated)")
            table.add_column("URL", style="cyan", no_wrap=True); table.add_column("Parameter", style="magenta")
            table.add_column("Type", style="green"); table.add_column("Example Payload", style="red")
            for vuln in unique_vulnerabilities:
                table.add_row(vuln['url'], vuln.get('parameter', 'N/A'), vuln['type'], str(vuln['payload']))
            console.print(table)
            if args.get("dump_db"):
                error_based_vuln = next((v for v in unique_vulnerabilities if "Error-Based" in v['type'] and v.get('dialect') == 'mssql'), None)
                if error_based_vuln:
                    exploiter = Exploiter(context)
                    await exploiter.extract_data(error_based_vuln)
                else:
                    console.print("\n[yellow][!] --dump-db requires a supported vulnerability type (e.g., MSSQL Error-Based), none was found.[/yellow]")
        else:
            console.print("\n[bold green][-] No vulnerabilities were found.[/bold green]")

        if args.get("json_report"):
            with open(args["json_report"], 'w') as f:
                json.dump(unique_vulnerabilities, f, indent=4)
            console.print(f"[green][*] Scan report saved to {args['json_report']}[/green]")

        await browser.close()

def main():
    parser = argparse.ArgumentParser(description="SQLi Hunter - An Advanced SQLi DAST Tool")
    parser.add_argument("-u", "--url", help="The target URL to scan")
    parser.add_argument("-d", "--depth", type=int, default=3, help="The depth for the crawler to explore.")
    parser.add_argument("--no-crawl", action="store_true", help="Disable the crawler and only scan the provided URL.")
    parser.add_argument("--collaborator", help="Your Out-of-Band server URL.")
    parser.add_argument("--dump-db", action="store_true", help="Attempt to extract the database name.")
    parser.add_argument("--cookie", help="The session cookie to use for authenticated scans (e.g., 'name=value').")
    parser.add_argument("--json-report", help="Save the scan results to a JSON file.")
    parser.add_argument("--n-calls", type=int, default=25, help="Number of Bayesian Optimizer calls per parameter (higher is more thorough).")
    parser.add_argument("--retest", help="Run in regression mode using a previous JSON report.")
    parser.add_argument("--debug", action="store_true", help="Enable detailed debug logging of requests and responses.")
    parser.add_argument("--adv-tamper", action="store_true", help="Enable advanced AST-based payload tampering (AdvSQLi).")
    parser.add_argument("--use-diffusion", action="store_true", help="Use the diffusion model to generate payload variations.")
    parser.add_argument("--use-llm-mutator", action="store_true", help="Use an LLM to mutate payloads.")
    args = parser.parse_args()

    if not args.url:
        # This will be handled by the GUI, but for CLI, it's an error.
        parser.error("the following arguments are required: -u/--url")

    console = Console()
    display_banner(console)
    asyncio.run(run_scan_logic(vars(args)))

if __name__ == "__main__":
    main()
