import requests
import argparse
import logging
import urllib3
import socket
import re
import time
from urllib.parse import urlparse
from concurrent.futures import ThreadPoolExecutor, as_completed
from functools import lru_cache
from collections import defaultdict
from typing import Dict, List, Tuple, Optional

# Initialize logging without timestamps
logging.basicConfig(level=logging.INFO, format="%(levelname)s - %(message)s")

# Disable InsecureRequestWarning
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Default security headers
DEFAULT_SECURITY_HEADERS = [
    'Content-Security-Policy',
    'X-Frame-Options',
    'Strict-Transport-Security'
]

# Information disclosure headers to detect
INFO_DISCLOSURE_HEADERS = {
    'Technology Stack': [
        'X-Powered-By',
        'X-AspNet-Version',
        'X-AspNetMvc-Version',
        'X-Runtime',
        'X-Version',
        'X-Generator',
        'X-Drupal-Cache',
        'X-Drupal-Dynamic-Cache',
        'X-Django-Version',
        'Server',
        'X-Server',
        'X-Turbo-Charged-By',
        'X-Mod-Pagespeed',
        'X-Page-Speed',
        'X-CF-Powered-By'
    ],
    'Debugging/Development': [
        'X-Debug-Token',
        'X-Debug-Token-Link',
        'X-Trace-Id',
        'X-Request-Id',
        'X-Correlation-Id',
        'X-B3-TraceId',
        'X-B3-SpanId',
        'X-Amz-Trace-Id',
        'X-Cloud-Trace-Context',
        'X-SourceFiles',
        'X-Stacktrace',
        'X-Exception',
        'X-Error',
        'X-Error-Message'
    ],
    'Infrastructure/Proxy': [
        'Via',
        'X-Real-IP',
        'X-Forwarded-Server',
        'X-Backend-Server',
        'X-Upstream-Addr',
        'X-Upstream-Response-Time',
        'X-Upstream-Status',
        'X-Served-By',
        'X-Host',
        'X-Backend-Host',
        'X-Original-Host',
        'X-Forwarded-Host',
        'X-Forwarded-Port',
        'X-Forwarded-Proto',
        'X-Real-Port',
        'X-Scheme'
    ],
    'Caching/CDN': [
        'X-Varnish',
        'X-Varnish-Cache',
        'X-Cache',
        'X-Cache-Hits',
        'X-Cache-Status',
        'X-Proxy-Cache',
        'CF-Ray',
        'CF-Cache-Status',
        'X-Amz-Cf-Id',
        'X-Amz-Cf-Pop',
        'X-Amz-Request-Id',
        'X-Amz-Id-2',
        'X-Fastly-Request-ID',
        'X-Azure-Ref',
        'X-Akamai-Request-ID',
        'X-CDN',
        'X-Pull-Key',
        'X-Device-Type'
    ],
    'Container/Orchestration': [
        'X-Kubernetes-PF-FlowSchema-UID',
        'X-Kubernetes-PF-PriorityLevel-UID',
        'X-Docker-Container-ID',
        'X-Served-By-Pod',
        'X-Served-By-Namespace'
    ],
    'Load Balancer': [
        'X-Haproxy-Server-State',
        'X-Load-Balancer',
        'X-LB-Server',
        'X-Balancer-Worker-IP',
        'X-Balancer-Worker-Route'
    ],
    'Authentication': [
        'X-Auth-Server',
        'X-Authentication-Type',
        'X-Auth-Method',
        'WWW-Authenticate',
        'X-OAuth-Scopes',
        'X-User-Id',
        'X-User-Email',
        'X-Username'
    ],
    'Miscellaneous': [
        'X-Rack-Cache',
        'X-Old-Content-Length',
        'X-Runtime-Version',
        'X-Hostname',
        'X-Server-Name',
        'X-Node',
        'X-Pod-Name',
        'X-Instance-ID',
        'X-EC2-Instance-ID',
        'X-Request-Start',
        'X-Queue-Start',
        'X-Render-Time'
    ]
}

# Default User-Agent - Firefox on Windows
DEFAULT_USER_AGENT = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:120.0) Gecko/20100101 Firefox/120.0'

@lru_cache(maxsize=1000)
def fetch_url_with_retry(url, timeout=10, user_agent=DEFAULT_USER_AGENT, max_retries=3):
    """
    Fetches a URL with retry logic and caching to avoid repetitive checks.
    Ignores SSL certificate verification.
    """
    headers = {'User-Agent': user_agent}
    
    for attempt in range(max_retries):
        try:
            response = requests.get(url, timeout=timeout, verify=False, headers=headers)
            return response.headers, None
        except requests.ConnectionError as e:
            error_msg = f"Connection error: Unable to connect to {url}. Check if the host is reachable."
            if attempt < max_retries - 1:
                time.sleep(0.5 * (attempt + 1))  # Exponential backoff
                continue
            logging.error(error_msg)
            return None, error_msg
        except requests.Timeout as e:
            error_msg = f"Timeout error: Connection to {url} timed out after {timeout} seconds. Host may be slow or unresponsive."
            if attempt < max_retries - 1:
                time.sleep(0.5 * (attempt + 1))
                continue
            logging.error(error_msg)
            return None, error_msg
        except requests.TooManyRedirects as e:
            error_msg = f"Redirect error: Too many redirects for {url}. Check for redirect loops."
            logging.error(error_msg)
            return None, error_msg
        except requests.RequestException as e:
            error_msg = f"HTTP error for {url}: {e}. Verify URL format and network connectivity."
            if attempt < max_retries - 1:
                time.sleep(0.5 * (attempt + 1))
                continue
            logging.error(error_msg)
            return None, error_msg
    return None, "Max retries exceeded"

@lru_cache(maxsize=1000)
def get_ip_address(url):
    """
    Extracts the domain from a URL and resolves it to an IP address.
    """
    try:
        domain = urlparse(url).netloc.split(':')[0]
        return socket.gethostbyname(domain)
    except socket.gaierror:
        return None

def fetch_headers(url: str, timeout: int = 10, user_agent: str = DEFAULT_USER_AGENT) -> Tuple[Optional[Dict], Optional[str], Optional[str]]:
    """
    Fetches headers and IP address for a URL.
    Returns: (headers_dict, ip_address, error_message)
    """
    headers_result, error = fetch_url_with_retry(url, timeout, user_agent)
    if headers_result is None:
        return None, None, error
    
    ip_address = get_ip_address(url)
    return headers_result, ip_address, None

def analyze_security_headers(headers: Dict, url: str, security_headers: List[str]) -> List[str]:
    """
    Analyzes headers and returns list of missing security headers.
    """
    missing_headers = []
    is_https = url.lower().startswith('https://')
    
    for header in security_headers:
        if header not in headers:
            if header == 'Strict-Transport-Security' and not is_https:
                continue
            missing_headers.append(header)
    return missing_headers


def check_headers(url: str, header_results: Dict, info_headers: Dict, security_headers: List[str], stats: Dict, timeout: int = 10, user_agent: str = DEFAULT_USER_AGENT) -> None:
    """
    Orchestrates header checking and result collection for a given URL.
    """
    stats['total_checked'] += 1
    
    headers, ip_address, error = fetch_headers(url, timeout, user_agent)
    if headers is None:
        stats['failed_checks'] += 1
        return
    
    stats['successful_checks'] += 1
    missing_headers = analyze_security_headers(headers, url, security_headers)
    
    for header in missing_headers:
        header_results[header].append((url, ip_address))
        stats['missing_headers'][header] += 1
    # Server header collection removed - now handled in INFO_DISCLOSURE_HEADERS
    
    # Check for information disclosure headers (always enabled)
    for category, header_list in INFO_DISCLOSURE_HEADERS.items():
        for header_name in header_list:
            header_value = headers.get(header_name)
            if header_value:
                if category not in info_headers:
                    info_headers[category] = {}
                if header_name not in info_headers[category]:
                    info_headers[category][header_name] = []
                info_headers[category][header_name].append((url, ip_address, header_value))
                if category not in stats['info_disclosure_headers']:
                    stats['info_disclosure_headers'][category] = defaultdict(int)
                stats['info_disclosure_headers'][category][header_name] += 1

def validate_url(url: str) -> Tuple[bool, str]:
    """
    Validates URL format and returns (is_valid, error_message).
    """
    if not url or not url.strip():
        return False, "Empty URL provided"
    
    url = url.strip()
    
    # Basic URL pattern validation
    url_pattern = re.compile(
        r'^(?:http[s]?://)?'  # Optional protocol
        r'(?:[a-zA-Z0-9-]+\.)*'  # Subdomains
        r'[a-zA-Z0-9-]+'  # Domain
        r'(?:\.[a-zA-Z]{2,})'  # TLD
        r'(?::[0-9]{1,5})?'  # Optional port
        r'(?:/.*)?$'  # Optional path
    )
    
    if not url_pattern.match(url):
        return False, f"Invalid URL format: {url}"
    
    # Check for suspicious patterns
    if any(char in url for char in ['<', '>', '"', "'", '`']):
        return False, f"URL contains suspicious characters: {url}"
    
    return True, ""

def expand_hosts(hosts: List[str]) -> List[str]:
    """
    Expands a list of hosts to include both HTTP and HTTPS protocols.
    Only includes valid URLs.
    """
    expanded_hosts = []
    for host in hosts:
        if "://" in host:
            is_valid, error = validate_url(host)
            if is_valid:
                expanded_hosts.append(host)
            else:
                logging.warning(f"Skipping invalid URL: {error}")
        else:
            http_url = f"http://{host}"
            https_url = f"https://{host}"
            
            is_valid_http, error_http = validate_url(http_url)
            is_valid_https, error_https = validate_url(https_url)
            
            if is_valid_http:
                expanded_hosts.append(http_url)
            else:
                logging.warning(f"Skipping invalid HTTP URL: {error_http}")
                
            if is_valid_https:
                expanded_hosts.append(https_url)
            else:
                logging.warning(f"Skipping invalid HTTPS URL: {error_https}")
    
    return expanded_hosts

def sort_urls(urls):
    """
    Sorts URLs first by protocol (HTTP, then HTTPS), and then numerically by IP address.
    """
    def get_protocol_and_ip(url_data):
        protocol = urlparse(url_data[0]).scheme
        ip = url_data[1]
        # Convert IP address to a tuple of integers for proper numerical sorting
        if ip and '.' in ip:
            try:
                ip_tuple = tuple(int(part) for part in ip.split('.'))
            except ValueError:
                ip_tuple = (0, 0, 0, 0)
        else:
            ip_tuple = (0, 0, 0, 0)
        return (protocol, ip_tuple)

    return sorted(urls, key=get_protocol_and_ip)

def calculate_optimal_workers(url_count: int) -> int:
    """
    Calculates optimal number of worker threads based on URL count.
    """
    if url_count <= 10:
        return min(url_count, 3)
    elif url_count <= 50:
        return min(url_count, 8)
    elif url_count <= 200:
        return min(url_count, 15)
    else:
        return 20

def batch_dns_resolution(urls: List[str]) -> Dict[str, str]:
    """
    Pre-resolves DNS for all unique domains to reduce redundant lookups.
    """
    domains = set()
    for url in urls:
        try:
            domain = urlparse(url).netloc.split(':')[0]
            domains.add(domain)
        except Exception:
            continue
    
    dns_cache = {}
    for domain in domains:
        try:
            ip = socket.gethostbyname(domain)
            dns_cache[domain] = ip
        except socket.gaierror:
            dns_cache[domain] = None
    
    return dns_cache

def generate_summary_stats(stats: Dict, header_results: Dict, total_urls: int) -> List[str]:
    """
    Generates summary statistics for the scan.
    """
    summary = ["\n" + "="*50, "SCAN SUMMARY", "="*50]
    summary.append(f"Total URLs processed: {stats['total_checked']}")
    summary.append(f"Successful checks: {stats['successful_checks']}")
    summary.append(f"Failed checks: {stats['failed_checks']}")
    
    if stats['successful_checks'] > 0:
        success_rate = (stats['successful_checks'] / stats['total_checked']) * 100
        summary.append(f"Success rate: {success_rate:.1f}%")
    
    summary.append("\nSecurity Header Analysis:")
    for header, missing_count in stats['missing_headers'].items():
        if stats['successful_checks'] > 0:
            missing_percent = (missing_count / stats['successful_checks']) * 100
            summary.append(f"  {header}: {missing_count}/{stats['successful_checks']} missing ({missing_percent:.1f}%)")
    
    if stats['info_disclosure_headers']:
        summary.append("\nInformation Disclosure Headers Found:")
        for category, headers_dict in sorted(stats['info_disclosure_headers'].items()):
            summary.append(f"\n  [{category}]")
            for header, count in sorted(headers_dict.items()):
                if stats['successful_checks'] > 0:
                    percent = (count / stats['successful_checks']) * 100
                    summary.append(f"    {header}: {count} sites ({percent:.1f}%)")
    
    return summary

def main():
    parser = argparse.ArgumentParser(description='Inspect security headers of a website.')
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('-u', '--url', help='Specify a single host or URL')
    group.add_argument('-iL', help='Specify a file containing a list of hosts or URLs')
    parser.add_argument('-o', '--output', help='Specify an output file to export results')
    parser.add_argument('-hL', '--headers', nargs='+', help='Specify headers to check', default=DEFAULT_SECURITY_HEADERS)
    parser.add_argument('-to', '--timeout', type=int, default=10, help='Request timeout in seconds (default: 10)')
    parser.add_argument('--user-agent', default=DEFAULT_USER_AGENT, help=f'Custom User-Agent string (default: {DEFAULT_USER_AGENT})')
    args = parser.parse_args()
    
    # Validate timeout
    if args.timeout <= 0:
        logging.error("Timeout must be a positive integer")
        return

    header_results = {header: [] for header in args.headers}
    info_headers = {}
    stats = {
        'total_checked': 0,
        'successful_checks': 0,
        'failed_checks': 0,
        'missing_headers': defaultdict(int),
        'info_disclosure_headers': defaultdict(int)
    }

    hosts_to_check = []
    if args.url:
        hosts_to_check.append(args.url)
    elif args.iL:
        try:
            with open(args.iL, 'r') as file:
                hosts_to_check.extend([host.strip() for host in file.readlines() if host.strip()])
        except FileNotFoundError:
            logging.error(f"Error: File '{args.iL}' not found. Please check the file path.")
            return
        except IOError as e:
            logging.error(f"Error reading file '{args.iL}': {e}")
            return

    expanded_hosts = expand_hosts(hosts_to_check)
    if not expanded_hosts:
        logging.error("No valid URLs to check after validation.")
        return
    
    total_checks = len(expanded_hosts)
    optimal_workers = calculate_optimal_workers(total_checks)
    logging.info(f"Starting header checks for {total_checks} URLs using {optimal_workers} workers.")
    
    # Pre-resolve DNS for performance
    logging.info("Pre-resolving DNS entries...")
    dns_cache = batch_dns_resolution(expanded_hosts)

    with ThreadPoolExecutor(max_workers=optimal_workers) as executor:
        futures = {executor.submit(check_headers, url, header_results, info_headers, args.headers, stats, args.timeout, args.user_agent): url for url in expanded_hosts}

        completed = 0
        for future in as_completed(futures):
            url = futures[future]
            completed += 1
            remaining = total_checks - completed
            logging.info(f"Checked {url}. {remaining} URLs remaining.")

    # Sorting logic for results
    for header in header_results:
        header_results[header] = sort_urls(header_results[header])

    results = ["Results:"]
    for header, urls in header_results.items():
        results.append(f"\n{header} Header Missing:\n{'-'*30}")
        if urls:
            for url, _ in urls:
                results.append(url)
        else:
            results.append("All hosts had this security header.")

    # Add information disclosure headers section
    if info_headers:
        results.append(f"\n\nINFORMATION DISCLOSURE HEADERS DETECTED:\n{'='*60}")
        for category, headers_dict in sorted(info_headers.items()):
            results.append(f"\n[{category}]")
            results.append('-' * (len(category) + 2))
            for header_name, entries in sorted(headers_dict.items()):
                results.append(f"\n{header_name}:")
                for url, ip, value in entries:
                    # Truncate very long values
                    display_value = value if len(value) <= 100 else value[:97] + '...'
                    results.append(f"  {url} [{ip}] - {display_value}")
    
    # Add summary statistics
    summary_stats = generate_summary_stats(stats, header_results, total_checks)
    results.extend(summary_stats)

    if args.output:
        try:
            with open(args.output, 'w') as outfile:
                outfile.write('\n'.join(results))
        except IOError as e:
            logging.error(f"Error writing to file '{args.output}': {e}")
    else:
        for line in results:
            print(line)

if __name__ == "__main__":
    main()
