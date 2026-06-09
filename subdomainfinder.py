
import asyncio
import aiohttp
import dns.resolver
import dns.asyncresolver
import argparse
import sys
import json
import csv
import re
import time
import random
from urllib.parse import urlparse
from collections import defaultdict
from typing import List, Set, Dict, Optional, Tuple

# ----------------------------------------------------------------------
# Configuration
# ----------------------------------------------------------------------
DEFAULT_TIMEOUT = 8
DEFAULT_RATE_LIMIT = 50  # queries per second (approx)
DEFAULT_CONCURRENCY = 100
USER_AGENT = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"

# Passive API endpoints
CRT_SH_URL = "https://crt.sh/?q=%25.{domain}&output=json"
OTX_URL = "https://otx.alienvault.com/api/v1/indicators/domain/{domain}/passive_dns"
WAYBACK_URL = "http://web.archive.org/cdx/search/cdx?url=*.{domain}/*&output=json&fl=original&collapse=urlkey"
# DNSDumpster (no API key required) uses a scraping approach – we'll implement a simplified version

# ----------------------------------------------------------------------
# Helper functions
# ----------------------------------------------------------------------
def sanitize_domain(domain: str) -> str:
    """Remove protocol, trailing slashes, etc."""
    domain = domain.strip().lower()
    domain = urlparse(domain).netloc or domain
    domain = re.sub(r'^www\.', '', domain)
    return domain.rstrip('/')

async def resolve_hostname(hostname: str, resolver: dns.asyncresolver.Resolver, timeout: int = 5) -> Optional[List[str]]:
    """Resolve A record asynchronously. Return list of IPs or None."""
    try:
        answers = await resolver.resolve(hostname, 'A', lifetime=timeout)
        return [str(rdata) for rdata in answers]
    except Exception:
        return None

# ----------------------------------------------------------------------
# Wildcard Detection
# ----------------------------------------------------------------------
async def detect_wildcard(domain: str, resolver: dns.asyncresolver.Resolver) -> Tuple[bool, Optional[str]]:
    """
    Check if the domain uses a wildcard DNS record.
    Returns (is_wildcard, wildcard_ip) where wildcard_ip is the IP wildcard resolves to.
    """
    test_sub = f"test-wildcard-{random.randint(10000,99999)}.{domain}"
    ips = await resolve_hostname(test_sub, resolver)
    if ips:
        # If multiple IPs, take the first one for filtering
        return True, ips[0]
    return False, None

# ----------------------------------------------------------------------
# Passive Enumeration
# ----------------------------------------------------------------------
async def fetch_crtsh(domain: str, session: aiohttp.ClientSession) -> Set[str]:
    """Get subdomains from crt.sh."""
    subdomains = set()
    url = CRT_SH_URL.format(domain=domain)
    try:
        async with session.get(url, timeout=DEFAULT_TIMEOUT) as resp:
            if resp.status == 200:
                data = await resp.json()
                for entry in data:
                    name = entry.get('name_value', '')
                    # crt.sh returns multiple entries per certificate, separated by newline
                    for sub in name.split('\n'):
                        sub = sub.strip().lower()
                        if sub.endswith(f".{domain}") and sub != domain:
                            subdomains.add(sub)
    except Exception as e:
        if args.verbose:
            print(f"[!] crt.sh error: {e}")
    return subdomains

async def fetch_otx(domain: str, session: aiohttp.ClientSession) -> Set[str]:
    """Get subdomains from AlienVault OTX."""
    subdomains = set()
    url = OTX_URL.format(domain=domain)
    try:
        async with session.get(url, timeout=DEFAULT_TIMEOUT) as resp:
            if resp.status == 200:
                data = await resp.json()
                for record in data.get('passive_dns', []):
                    host = record.get('hostname', '').lower()
                    if host.endswith(f".{domain}"):
                        subdomains.add(host)
    except Exception as e:
        if args.verbose:
            print(f"[!] OTX error: {e}")
    return subdomains

async def fetch_wayback(domain: str, session: aiohttp.ClientSession) -> Set[str]:
    """Get subdomains from Wayback Machine."""
    subdomains = set()
    url = WAYBACK_URL.format(domain=domain)
    try:
        async with session.get(url, timeout=DEFAULT_TIMEOUT) as resp:
            if resp.status == 200:
                data = await resp.json()
                # First element is usually header
                for item in data[1:]:
                    original = item[0] if isinstance(item, list) else item.get('original', '')
                    # Extract subdomain from URL
                    match = re.search(r'([a-zA-Z0-9.-]+)\.' + re.escape(domain), original)
                    if match:
                        sub = match.group(1) + f".{domain}"
                        subdomains.add(sub)
    except Exception as e:
        if args.verbose:
            print(f"[!] Wayback error: {e}")
    return subdomains

async def fetch_dnsdumpster(domain: str, session: aiohttp.ClientSession) -> Set[str]:
    """Simplified DNSDumpster scraping (no API key)."""
    subdomains = set()
    # DNSDumpster requires a CSRF token – we'll use a simpler alternative here.
    # For production, implement proper POST with token extraction.
    # As a fallback, we skip or you can integrate a local wordlist.
    # This is left as a placeholder; you can add more robust passive sources.
    return subdomains

async def passive_enum(domain: str, session: aiohttp.ClientSession) -> Set[str]:
    """Run all passive sources concurrently."""
    tasks = [
        fetch_crtsh(domain, session),
        fetch_otx(domain, session),
        fetch_wayback(domain, session),
        fetch_dnsdumpster(domain, session)
    ]
    results = await asyncio.gather(*tasks, return_exceptions=True)
    all_subs = set()
    for res in results:
        if isinstance(res, set):
            all_subs.update(res)
        elif isinstance(res, Exception) and args.verbose:
            print(f"[!] Passive source error: {res}")
    return all_subs

# ----------------------------------------------------------------------
# Active Brute-force
# ----------------------------------------------------------------------
async def brute_force(domain: str, wordlist: List[str], resolver: dns.asyncresolver.Resolver,
                      concurrency: int, wildcard_ip: Optional[str]) -> Set[str]:
    """
    Resolve each word + domain, filter out wildcard IPs.
    """
    found = set()
    semaphore = asyncio.Semaphore(concurrency)

    async def check(sub: str):
        async with semaphore:
            full = f"{sub}.{domain}"
            ips = await resolve_hostname(full, resolver)
            if ips:
                if wildcard_ip and wildcard_ip in ips:
                    # Likely wildcard – ignore
                    return
                found.add(full)

    tasks = [check(word) for word in wordlist]
    await asyncio.gather(*tasks)
    return found

# ----------------------------------------------------------------------
# Permutation Generation
# ----------------------------------------------------------------------
def generate_permutations(known_subs: Set[str], domain: str) -> Set[str]:
    """
    Generate new subdomain candidates based on common mutations:
    - replace numbers (e.g., api1 -> api2)
    - prefix/suffix with common words (admin, test, dev, staging, backup)
    - join two subdomains with hyphen or dot (e.g., admin-api, admin.api)
    """
    common_tokens = ["admin", "dev", "test", "staging", "backup", "vpn", "mail", "remote",
                     "portal", "dashboard", "api", "cdn", "static", "assets", "ns", "dns"]
    permutations = set()

    # Extract base names (without domain)
    base_names = {sub.replace(f".{domain}", "") for sub in known_subs}

    for name in base_names:
        # Append tokens with hyphen/dot
        for token in common_tokens:
            permutations.add(f"{name}-{token}.{domain}")
            permutations.add(f"{name}.{token}.{domain}")
            permutations.add(f"{token}-{name}.{domain}")
            permutations.add(f"{token}.{name}.{domain}")
        # Number replacement (e.g., web1 -> web2)
        if re.search(r'\d+$', name):
            num = re.search(r'\d+$', name).group()
            new_num = str(int(num) + 1)
            permutations.add(name.replace(num, new_num, 1) + f".{domain}")
    # Remove any that already exist
    permutations -= {f"{base}.{domain}" for base in base_names}
    return permutations

# ----------------------------------------------------------------------
# Main Runner
# ----------------------------------------------------------------------
async def main(args):
    domain = sanitize_domain(args.domain)
    print(f"[*] Target domain: {domain}")

    # Configure resolver
    resolver = dns.asyncresolver.Resolver()
    if args.resolvers:
        resolver.nameservers = args.resolvers.split(',')
    else:
        resolver.nameservers = ['8.8.8.8', '1.1.1.1']
    resolver.timeout = args.timeout
    resolver.lifetime = args.timeout * 2

    # Wildcard detection
    print("[*] Detecting wildcard DNS ...")
    is_wild, wild_ip = await detect_wildcard(domain, resolver)
    if is_wild:
        print(f"[*] Wildcard detected! IP: {wild_ip} (results will be filtered)")
    else:
        print("[*] No wildcard DNS found")

    # Load wordlist
    wordlist = []
    if args.wordlist:
        try:
            with open(args.wordlist, 'r') as f:
                wordlist = [line.strip().lower() for line in f if line.strip()]
            print(f"[*] Loaded {len(wordlist)} words from {args.wordlist}")
        except Exception as e:
            print(f"[-] Failed to load wordlist: {e}")
            sys.exit(1)

    all_subs = set()

    # 1. Passive enumeration
    if args.passive:
        print("[*] Starting passive enumeration ...")
        async with aiohttp.ClientSession(headers={'User-Agent': USER_AGENT}) as session:
            passive_subs = await passive_enum(domain, session)
        print(f"[+] Passive sources found {len(passive_subs)} unique subdomains")
        all_subs.update(passive_subs)

    # 2. Active brute-force
    if args.active and wordlist:
        print("[*] Starting active brute-force ...")
        brute_subs = await brute_force(domain, wordlist, resolver, args.threads, wild_ip if is_wild else None)
        print(f"[+] Active brute-force found {len(brute_subs)} subdomains")
        all_subs.update(brute_subs)

    # 3. Permutation scan (only if we have some found subs)
    if args.permutations and len(all_subs) > 0:
        print("[*] Generating permutation candidates ...")
        perms = generate_permutations(all_subs, domain)
        if perms:
            print(f"[*] Testing {len(perms)} permutation candidates ...")
            perm_subs = await brute_force(domain, [p.replace(f".{domain}", "") for p in perms],
                                          resolver, args.threads, wild_ip if is_wild else None)
            print(f"[+] Permutations found {len(perm_subs)} new subdomains")
            all_subs.update(perm_subs)

    # 4. Resolve IPs for final set
    print("[*] Resolving IP addresses (final check) ...")
    final_results = {}
    async def resolve_and_collect(sub: str):
        ips = await resolve_hostname(sub, resolver)
        if ips:
            # Filter wildcard again (safety)
            if is_wild and wild_ip in ips:
                return
            final_results[sub] = ips

    tasks = [resolve_and_collect(sub) for sub in all_subs]
    await asyncio.gather(*tasks)

    print(f"\n[+] Total unique, resolved subdomains: {len(final_results)}")
    if args.verbose:
        for sub, ips in final_results.items():
            print(f"  {sub} -> {', '.join(ips)}")

    # Output
    if args.output:
        if args.output_format == 'txt':
            with open(args.output, 'w') as f:
                for sub in sorted(final_results.keys()):
                    f.write(f"{sub}\n")
        elif args.output_format == 'json':
            with open(args.output, 'w') as f:
                json.dump(final_results, f, indent=2)
        elif args.output_format == 'csv':
            with open(args.output, 'w', newline='') as f:
                writer = csv.writer(f)
                writer.writerow(['subdomain', 'ips'])
                for sub, ips in final_results.items():
                    writer.writerow([sub, ';'.join(ips)])
        print(f"[*] Results saved to {args.output}")

    return final_results

# ----------------------------------------------------------------------
# CLI Entry Point
# ----------------------------------------------------------------------
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Advanced Subdomain Finder for Kali Linux")
    parser.add_argument("-d", "--domain", required=True, help="Target domain (e.g., example.com)")
    parser.add_argument("-w", "--wordlist", help="Wordlist file for active brute-force")
    parser.add_argument("-t", "--threads", type=int, default=DEFAULT_CONCURRENCY, help="Concurrent DNS queries")
    parser.add_argument("-o", "--output", help="Output file")
    parser.add_argument("-f", "--output-format", choices=['txt', 'json', 'csv'], default='txt', help="Output format")
    parser.add_argument("--passive", action="store_true", default=True, help="Enable passive sources (default: on)")
    parser.add_argument("--no-passive", action="store_false", dest="passive", help="Disable passive sources")
    parser.add_argument("--active", action="store_true", default=True, help="Enable active brute-force (default: on)")
    parser.add_argument("--no-active", action="store_false", dest="active", help="Disable active brute-force")
    parser.add_argument("--permutations", action="store_true", default=True, help="Enable permutation scanning (default: on)")
    parser.add_argument("--no-permutations", action="store_false", dest="permutations", help="Disable permutation scanning")
    parser.add_argument("--resolvers", help="Comma-separated custom DNS resolvers (e.g., 8.8.8.8,1.1.1.1)")
    parser.add_argument("--timeout", type=int, default=5, help="DNS resolution timeout (seconds)")
    parser.add_argument("-v", "--verbose", action="store_true", help="Verbose output")
    parser.add_argument("--rate-limit", type=int, default=DEFAULT_RATE_LIMIT, help="Approximate queries per second (throttle)")

    args = parser.parse_args()

    if not args.active and not args.passive and not args.permutations:
        print("[-] At least one of --passive, --active, --permutations must be enabled.")
        sys.exit(1)

    # Run asyncio event loop
    asyncio.run(main(args))