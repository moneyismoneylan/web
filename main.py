# -*- coding: utf-8 -*-
"""
SQLi Hunter - Main Entry Point.
"""
import argparse
import asyncio
import json
from urllib.parse import urlparse
from playwright.async_api import async_playwright
from playwright_stealth.stealth import Stealth
from rich.console import Console
from rich.table import Table
import dns.asyncresolver

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
            # Circuit breaker: Timeout for each scan target to prevent stalls
            await asyncio.wait_for(
                scanner.scan_target(target_item, collaborator_url),
                timeout=600.0  # 10-minute timeout per target
            )
        except asyncio.TimeoutError:
            url = target_item.get("url", "Unknown Target")
            print(f"[!] Target timed out and was skipped: {url}")
        except Exception as e:
            url = target_item.get("url", "Unknown Target")
            print(f"[!] An unexpected error occurred while scanning {url}: {e}")
        finally:
            queue.task_done()

async def main():
    parser = argparse.ArgumentParser(description="SQLi Hunter - An Advanced SQLi DAST Tool")
    parser.add_argument("-u", "--url", required=True, help="The target URL to scan")
    parser.add_argument("-d", "--depth", type=int, default=3, help="The depth for the crawler to explore.")
    parser.add_argument("--no-crawl", action="store_true", help="Disable the crawler and only scan the provided URL.")
    parser.add_argument("--collaborator", help="Your Out-of-Band server URL.")
    parser.add_argument("--dump-db", action="store_true", help="Attempt to extract the database name.")
    parser.add_argument("--cookie", help="The session cookie to use for authenticated scans (e.g., 'name=value').")
    parser.add_argument("--json-report", help="Save the scan results to a JSON file.")
    parser.add_argument("--n-calls", type=int, default=25, help="Number of Bayesian Optimizer calls per parameter (higher is more thorough).")
    parser.add_argument("--retest", help="Run in regression mode using a previous JSON report.")

    args = parser.parse_args()
    console = Console()
    display_banner(console)

    if not urlparse(args.url).scheme: args.url = "http://" + args.url
    console.print(f"[bold green][*] Target URL:[/] [link={args.url}]{args.url}[/link]")

    async with Stealth().use_async(async_playwright()) as p:
        browser = await p.chromium.launch()
        # Use a common User-Agent and other properties to avoid simple bot detection
        # Note: The stealth plugin may override some of these, but we set them as a baseline.
        context = await browser.new_context(
            user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/99.0.4844.51 Safari/537.36",
            viewport={'width': 1920, 'height': 1080},
            locale='en-US',
            timezone_id='America/New_York'
        )
        if args.cookie:
            try:
                name, value = args.cookie.split('=', 1)
                await context.add_cookies([{"name": name.strip(), "value": value.strip(), "domain": urlparse(args.url).netloc}])
                console.print("[green][*] Session cookie set.[/green]")
            except ValueError:
                console.print("[red][!] Invalid cookie format. Please use 'name=value'.[/red]")

        queue = asyncio.Queue()
        waf_detector = WafDetector(context)
        waf_name = await waf_detector.check_waf(args.url)

        canary_store = {}
        scanner = Scanner(context, canary_store=canary_store, waf_name=waf_name, n_calls=args.n_calls)
        scanner_tasks = [asyncio.create_task(scanner_worker(queue, scanner, args.collaborator)) for _ in range(SCANNER_WORKERS)]

        if args.retest:
            console.print(f"\n[bold cyan]--- Running in Re-test Mode using {args.retest} ---[/bold cyan]")
            try:
                with open(args.retest, 'r') as f:
                    previous_vulns = json.load(f)

                urls_to_test = {vuln['url'] for vuln in previous_vulns}
                for url in urls_to_test:
                    # This is a simplified re-test. It just re-scans the entire URL.
                    # A more advanced version would re-test the specific parameter.
                    await queue.put({"type": "url", "url": url, "method": "GET"})
                console.print(f"[*] Queued {len(urls_to_test)} unique URLs for re-testing.")

            except (IOError, json.JSONDecodeError) as e:
                console.print(f"[bold red][!] Error reading re-test file: {e}[/bold red]")
                return
        elif args.no_crawl:
            console.print("[yellow][!] Crawler disabled. Scanning only the provided URL.[/yellow]")
            await queue.put({"type": "url", "url": args.url, "method": "GET"})
        else:
            console.print("\n[bold cyan]--- Starting Concurrent Crawl & Scan ---[/bold cyan]")
            crawler = Crawler(base_url=args.url, max_depth=args.depth, queue=queue, browser_context=context)
            await crawler.start()

        await queue.join()
        for _ in range(SCANNER_WORKERS): await queue.put(None)
        await asyncio.gather(*scanner_tasks)

        if canary_store and args.collaborator:
            console.print("\n[bold cyan]--- Verifying Stored SQLi Canaries ---[/bold cyan]")
            resolver = dns.asyncresolver.Resolver()
            for canary_id, sink_info in canary_store.items():
                domain_to_check = f"{canary_id}.stored.{args.collaborator}"
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
            if args.dump_db:
                error_based_vuln = next((v for v in unique_vulnerabilities if "Error-Based" in v['type']), None)
                if error_based_vuln:
                    exploiter = Exploiter(context)
                    # Use the same tamper chain that was successful for detection
                    successful_chain = error_based_vuln.get('tamper_chain', [])
                    print(f"[*] Attempting to dump data using successful tamper chain: {successful_chain}")
                    await exploiter.extract_data_error_based(error_based_vuln, successful_chain)
                else: console.print("\n[yellow][!] --dump-db requires an error-based vulnerability, none was found.[/yellow]")
        else:
            console.print("\n[bold green][-] No vulnerabilities were found.[/bold green]")

        if args.json_report:
            with open(args.json_report, 'w') as f:
                json.dump(unique_vulnerabilities, f, indent=4)
            console.print(f"[green][*] Scan report saved to {args.json_report}[/green]")

        # Close all resources
        await browser.close()

if __name__ == "__main__":
    asyncio.run(main())
