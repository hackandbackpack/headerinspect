# HeaderInspect

A fast and reliable security header scanner that checks websites for missing security headers. Perfect for security assessments, penetration testing, and compliance checks.

## Features

- **Fast Concurrent Scanning** - Adaptive thread pool automatically scales from 3-20 workers based on URL count
- **Smart Retry Logic** - Handles network issues with exponential backoff and detailed error reporting
- **URL Validation** - Automatically validates and sanitizes input URLs, skipping invalid entries
- **Comprehensive Statistics** - Shows success rates, missing header percentages, and scan summaries
- **Stealth Mode** - Uses realistic Firefox User-Agent by default to avoid detection
- **Flexible Input** - Single URLs or bulk scanning from files
- **Custom Headers** - Check any headers you want, not just the defaults

## Quick Start

```bash
# Check a single website
python headerinspect.py -u example.com

# Scan multiple sites from a file
python headerinspect.py -iL urls.txt

# Custom timeout and save results
python headerinspect.py -iL sites.txt -to 15 -o results.txt
```

## Installation

```bash
git clone https://github.com/hackandbackpack/headerinspect.git
cd headerinspect
pip install requests
```

## Usage

```
python headerinspect.py [-h] (-u URL | -iL FILE) [-o OUTPUT] [-hL HEADERS] [-to TIMEOUT] [--user-agent USER_AGENT]

Options:
  -u, --url URL                 Single host or URL to check
  -iL FILE                      File containing list of hosts/URLs (one per line)
  -o, --output OUTPUT           Save results to file
  -hL, --headers HEADERS        Custom headers to check (space separated)
  -to, --timeout TIMEOUT       Request timeout in seconds (default: 10)
  --user-agent USER_AGENT       Custom User-Agent string
```

## Default Security Headers Checked

- **Content-Security-Policy** - Prevents XSS and data injection attacks
- **X-Frame-Options** - Protects against clickjacking
- **Strict-Transport-Security** - Enforces HTTPS connections (HTTPS only)

## Examples

### Basic scan with custom headers
```bash
python headerinspect.py -u google.com -hL "X-Content-Type-Options" "Referrer-Policy"
```

### Bulk scanning with custom settings
```bash
python headerinspect.py -iL targets.txt -to 5 --user-agent "Custom Scanner 1.0" -o scan_results.txt
```

### Input file format (urls.txt)
```
example.com
https://secure-site.com
http://legacy-site.org:8080
```

## Sample Output

```
Results:

Content-Security-Policy Header Missing:
------------------------------
http://example.com
https://example.com

X-Frame-Options Header Missing:
------------------------------
http://example.com

Server Header: nginx/1.18.0
------------------------------
https://example.com

==================================================
SCAN SUMMARY
==================================================
Total URLs processed: 2
Successful checks: 2
Failed checks: 0
Success rate: 100.0%

Security Header Analysis:
  Content-Security-Policy: 2/2 missing (100.0%)
  X-Frame-Options: 1/2 missing (50.0%)
  Strict-Transport-Security: 0/2 missing (0.0%)
```

## Performance

- **Small scans** (1-10 URLs): 3 workers, completes in seconds
- **Medium scans** (11-50 URLs): 8 workers, efficient batch processing
- **Large scans** (50+ URLs): Up to 20 workers with DNS pre-resolution
- **Caching**: 1000-entry LRU cache prevents duplicate requests

## Error Handling

The tool gracefully handles:
- Network timeouts and connection errors
- Invalid URLs and malformed input
- DNS resolution failures
- SSL/TLS certificate issues
- Rate limiting and server errors

## Security Features

- Uses realistic Firefox User-Agent to avoid detection
- Disables SSL verification for testing purposes
- Input validation prevents injection attacks
- No sensitive data logged or cached

## Requirements

- Python 3.6+
- requests library
- urllib3 (included with requests)

## Contributing

Found a bug or want to add a feature? Pull requests welcome!

## License

MIT License - feel free to use this for security testing and assessments.