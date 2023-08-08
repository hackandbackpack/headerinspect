import requests
import argparse

# Define the security headers to be checked
SECURITY_HEADERS = [
    'Content-Security-Policy',
    'X-Frame-Options',
    'Strict-Transport-Security'
]

def check_headers(host, header_results, server_headers):
    """
    Checks the specified security headers for a given URL or IP.
    """
    # If provided input looks like an IP or if it's just a URL without a protocol,
    # we will attempt both http and https.
    protocols = ['http', 'https'] if (host.replace('.', '').isdigit() or "://" not in host) else [host.split('://')[0]]

    for protocol in protocols:
        url = f"{protocol}://{host}" if (host.replace('.', '').isdigit() or "://" not in host) else host

        try:
            response = requests.get(url, timeout=10)
            headers = response.headers

            # Check if the URL uses HTTPS to decide the need for HSTS
            is_https = url.lower().startswith('https://')

            for header in SECURITY_HEADERS:
                if header not in headers:
                    if header == 'Strict-Transport-Security' and not is_https:
                        continue
                    header_results[header].append(url)
            if 'Server' in headers:
                server_value = headers['Server']
                if server_value not in server_headers:
                    server_headers[server_value] = []
                server_headers[server_value].append(url)

        except requests.RequestException as e:
            print(f"Error fetching {url}: {e}")

def main():
    # Argument parsing
    parser = argparse.ArgumentParser(description='Inspect security headers of a website.')
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('-u', '--url', help='Specify a single host or IP (e.g., http://example.com or 192.168.1.1)')
    group.add_argument('-iL', help='Specify a file containing a list of hosts or IPs (one per line)')
    parser.add_argument('-o', '--output', help='Specify an output file to export results', required=False)
    args = parser.parse_args()

    header_results = {header: [] for header in SECURITY_HEADERS}
    server_headers = {}

    # Checking headers for single host/IP or list of hosts/IPs
    if args.url:
        check_headers(args.url, header_results, server_headers)
    elif args.iL:
        try:
            with open(args.iL, 'r') as file:
                hosts = file.readlines()
                for host in hosts:
                    check_headers(host.strip(), header_results, server_headers)
        except FileNotFoundError:
            print(f"Error: File '{args.iL}' not found.")
            return

    results = []

    # Building the result strings
    results.append("Results:")
    for header, urls in header_results.items():
        results.append(f"\n{header} Header\n{'-'*30}")
        if urls:
            results.append("Missing On:")
            for url in urls:
                results.append(url)
        else:
            results.append("All hosts had this security header.")

    # Collecting the 'Server' header information
    if server_headers:
        for server_value, urls in server_headers.items():
            results.append(f"\nServer Header: {server_value}\n{'-'*30}")
            for url in urls:
                results.append(url)
    else:
        results.append("\nServer Header\n" + "-"*30)
        results.append("No servers were using a Server header.")

    # Outputting results to file or console
    if args.output:
        try:
            with open(args.output, 'w') as outfile:
                outfile.write('\n'.join(results))
        except IOError as e:
            print(f"Error writing to file '{args.output}': {e}")
    else:
        for line in results:
            print(line)

if __name__ == "__main__":
    main()
