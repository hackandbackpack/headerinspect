import requests
import argparse
import logging
import urllib3
import socket
from urllib.parse import urlparse
from concurrent.futures import ThreadPoolExecutor, as_completed
from functools import lru_cache

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

@lru_cache(maxsize=100)
def fetch_url(url):
    """
    Fetches a URL with caching to avoid repetitive checks.
    Ignores SSL certificate verification.
    """
    try:
        response = requests.get(url, timeout=10, verify=False)
        return response.headers
    except requests.ConnectionError:
        logging.error(f"Connection error: Unable to connect to {url}")
    except requests.Timeout:
        logging.error(f"Timeout error: Connection to {url} timed out")
    except requests.TooManyRedirects:
        logging.error(f"Redirect error: Too many redirects for {url}")
    except requests.RequestException as e:
        logging.error(f"HTTP error for {url}: {e}")
    return None

@lru_cache(maxsize=100)
def get_ip_address(url):
    """
    Extracts the domain from a URL and resolves it to an IP address.
    """
    try:
        domain = urlparse(url).netloc.split(':')[0]
        return socket.gethostbyname(domain)
    except socket.gaierror:
        return None

def check_headers(url, header_results, server_headers, security_headers):
    """
    Checks the specified security headers for a given URL.
    """
    headers = fetch_url(url)

    if headers is None:
        return

    is_https = url.lower().startswith('https://')
    ip_address = get_ip_address(url)

    for header in security_headers:
        if header not in headers:
            if header == 'Strict-Transport-Security' and not is_https:
                continue
            header_results[header].append((url, ip_address))
    if 'Server' in headers:
        server_value = headers['Server']
        if server_value not in server_headers:
            server_headers[server_value] = []
        server_headers[server_value].append((url, ip_address))

def expand_hosts(hosts):
    """
    Expands a list of hosts to include both HTTP and HTTPS protocols.
    """
    expanded_hosts = []
    for host in hosts:
        if "://" in host:
            expanded_hosts.append(host)
        else:
            expanded_hosts.append(f"http://{host}")
            expanded_hosts.append(f"https://{host}")
    return expanded_hosts

def sort_urls(urls):
    """
    Sorts URLs first by protocol (HTTP, then HTTPS), and then numerically by IP address.
    """
    def get_protocol_and_ip(url):
        protocol = urlparse(url[0]).scheme
        ip = url[1]
        # Convert IP address to a tuple of integers for proper numerical sorting
        ip_tuple = tuple(int(part) for part in ip.split('.'))
        return (protocol, ip_tuple)

    return sorted(urls, key=get_protocol_and_ip)

def main():
    parser = argparse.ArgumentParser(description='Inspect security headers of a website.')
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('-u', '--url', help='Specify a single host or URL')
    group.add_argument('-iL', help='Specify a file containing a list of hosts or URLs')
    parser.add_argument('-o', '--output', help='Specify an output file to export results')
    parser.add_argument('-hL', '--headers', nargs='+', help='Specify headers to check', default=DEFAULT_SECURITY_HEADERS)
    args = parser.parse_args()

    header_results = {header: [] for header in args.headers}
    server_headers = {}

    hosts_to_check = []
    if args.url:
        hosts_to_check.append(args.url)
    elif args.iL:
        try:
            with open(args.iL, 'r') as file:
                hosts_to_check.extend([host.strip() for host in file.readlines()])
        except FileNotFoundError:
            logging.error(f"Error: File '{args.iL}' not found.")
            return

    expanded_hosts = expand_hosts(hosts_to_check)
    total_checks = len(expanded_hosts)
    logging.info(f"Starting header checks for {total_checks} URLs.")

    with ThreadPoolExecutor(max_workers=10) as executor:
        futures = {executor.submit(check_headers, url, header_results, server_headers, args.headers): url for url in expanded_hosts}

        for future in as_completed(futures):
            url = futures[future]
            total_checks -= 1
            logging.info(f"Checked {url}. {total_checks} URLs remaining.")

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

    # Apply the same sorting logic to server headers
    for server_value, urls in server_headers.items():
        server_headers[server_value] = sort_urls(urls)
        results.append(f"\nServer Header: {server_value}\n{'-'*30}")
        for url, _ in urls:
            results.append(url)

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
