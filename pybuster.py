#!/usr/bin/env python3
"""
pybusterTN - Professional Directory & File Bruteforcer

A fast, multithreaded directory and file discovery tool for web applications.
Similar to gobuster/dirbuster but written in Python.

Author: Ghariani Oussema
License: MIT
"""

import argparse
import os
import sys
import time
import signal
import logging
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from typing import List, Optional, Tuple, Set
from urllib.parse import urljoin, urlparse

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

try:
    from colorama import Fore, Style, init
    init(autoreset=True)
    COLORS_AVAILABLE = True
except ImportError:
    COLORS_AVAILABLE = False
    class Fore:
        RED = GREEN = YELLOW = BLUE = CYAN = MAGENTA = WHITE = ""
    class Style:
        RESET_ALL = BRIGHT = ""

# Configuration
VERSION = "2.0.0"
DEFAULT_USER_AGENT = f"pybusterTN/{VERSION}"
DEFAULT_THREADS = 10
DEFAULT_TIMEOUT = 10

# Status code categories
SUCCESS_CODES = {200, 201, 202, 203, 204}
REDIRECT_CODES = {301, 302, 303, 307, 308}
AUTH_CODES = {401, 403}
ERROR_CODES = {500, 501, 502, 503, 504}

# Logging setup
logging.basicConfig(
    level=logging.INFO,
    format="%(message)s"
)
logger = logging.getLogger(__name__)


@dataclass
class ScanResult:
    """Represents a scan result."""
    url: str
    status_code: int
    content_length: int
    redirect_url: Optional[str] = None


class Colors:
    """Color helper class."""
    
    @staticmethod
    def success(text: str) -> str:
        return f"{Fore.GREEN}{text}{Style.RESET_ALL}"
    
    @staticmethod
    def error(text: str) -> str:
        return f"{Fore.RED}{text}{Style.RESET_ALL}"
    
    @staticmethod
    def warning(text: str) -> str:
        return f"{Fore.YELLOW}{text}{Style.RESET_ALL}"
    
    @staticmethod
    def info(text: str) -> str:
        return f"{Fore.CYAN}{text}{Style.RESET_ALL}"
    
    @staticmethod
    def highlight(text: str) -> str:
        return f"{Fore.MAGENTA}{text}{Style.RESET_ALL}"
    
    @staticmethod
    def status_color(code: int) -> str:
        if code in SUCCESS_CODES:
            return Fore.GREEN
        elif code in REDIRECT_CODES:
            return Fore.BLUE
        elif code in AUTH_CODES:
            return Fore.YELLOW
        elif code in ERROR_CODES:
            return Fore.RED
        return Fore.WHITE


def print_banner():
    """Print the tool banner."""
    banner = f"""
{Fore.CYAN}╔═══════════════════════════════════════════════════════════╗
║                                                             ║
║   ██████╗ ██╗   ██╗██████╗ ██╗   ██╗███████╗████████╗      ║
║   ██╔══██╗╚██╗ ██╔╝██╔══██╗██║   ██║██╔════╝╚══██╔══╝      ║
║   ██████╔╝ ╚████╔╝ ██████╔╝██║   ██║███████╗   ██║         ║
║   ██╔═══╝   ╚██╔╝  ██╔══██╗██║   ██║╚════██║   ██║         ║
║   ██║        ██║   ██████╔╝╚██████╔╝███████║   ██║  TN     ║
║   ╚═╝        ╚═╝   ╚═════╝  ╚═════╝ ╚══════╝   ╚═╝         ║
║                                                             ║
║          Professional Directory Bruteforcer v{VERSION}        ║
║                  by Ghariani Oussema 🇹🇳                    ║
╚═══════════════════════════════════════════════════════════╝{Style.RESET_ALL}
"""
    print(banner)


class DirectoryScanner:
    """
    Professional directory and file scanner.
    
    Features:
    - Multithreaded scanning
    - Custom headers and cookies
    - Extension bruteforcing
    - Recursive scanning
    - Progress tracking
    """
    
    def __init__(
        self,
        target: str,
        threads: int = DEFAULT_THREADS,
        timeout: int = DEFAULT_TIMEOUT,
        user_agent: str = DEFAULT_USER_AGENT,
        cookies: Optional[str] = None,
        headers: Optional[dict] = None,
        proxy: Optional[str] = None,
        follow_redirects: bool = False,
        verify_ssl: bool = True
    ):
        self.target = self._normalize_url(target)
        self.threads = threads
        self.timeout = timeout
        self.user_agent = user_agent
        self.cookies = self._parse_cookies(cookies)
        self.headers = headers or {}
        self.proxy = {"http": proxy, "https": proxy} if proxy else None
        self.follow_redirects = follow_redirects
        self.verify_ssl = verify_ssl
        
        self.session = self._create_session()
        self.results: List[ScanResult] = []
        self.scanned_count = 0
        self.found_count = 0
        self.error_count = 0
        self.running = True
        
        # Handle Ctrl+C gracefully
        signal.signal(signal.SIGINT, self._signal_handler)
    
    def _normalize_url(self, url: str) -> str:
        """Ensure URL has proper scheme."""
        if not url.startswith(("http://", "https://")):
            url = f"http://{url}"
        return url.rstrip("/")
    
    def _parse_cookies(self, cookies_str: Optional[str]) -> dict:
        """Parse cookie string into dictionary."""
        if not cookies_str:
            return {}
        
        cookies = {}
        for cookie in cookies_str.split(";"):
            if "=" in cookie:
                key, value = cookie.strip().split("=", 1)
                cookies[key.strip()] = value.strip()
        return cookies
    
    def _create_session(self) -> requests.Session:
        """Create a requests session with retry logic."""
        session = requests.Session()
        
        retry_strategy = Retry(
            total=2,
            backoff_factor=0.5,
            status_forcelist=[429, 500, 502, 503, 504],
        )
        adapter = HTTPAdapter(max_retries=retry_strategy, pool_maxsize=self.threads)
        session.mount("http://", adapter)
        session.mount("https://", adapter)
        
        session.headers.update({
            "User-Agent": self.user_agent,
            **self.headers
        })
        
        if self.cookies:
            session.cookies.update(self.cookies)
        
        return session
    
    def _signal_handler(self, signum, frame):
        """Handle interrupt signal."""
        print(f"\n{Colors.warning('[!] Scan interrupted by user')}")
        self.running = False
    
    def _scan_path(self, path: str) -> Optional[ScanResult]:
        """Scan a single path."""
        if not self.running:
            return None
        
        url = f"{self.target}/{path.lstrip('/')}"
        
        try:
            response = self.session.get(
                url,
                timeout=self.timeout,
                allow_redirects=self.follow_redirects,
                verify=self.verify_ssl,
                proxies=self.proxy
            )
            
            status = response.status_code
            content_length = len(response.content)
            redirect_url = response.headers.get("Location") if status in REDIRECT_CODES else None
            
            return ScanResult(
                url=url,
                status_code=status,
                content_length=content_length,
                redirect_url=redirect_url
            )
            
        except requests.exceptions.Timeout:
            return None
        except requests.exceptions.SSLError:
            logger.debug(f"SSL error for {url}")
            return None
        except requests.exceptions.ConnectionError:
            return None
        except requests.exceptions.RequestException as e:
            logger.debug(f"Request error for {url}: {e}")
            return None
    
    def scan(
        self,
        wordlist: List[str],
        extensions: Optional[List[str]] = None,
        exclude_codes: Optional[Set[int]] = None,
        include_codes: Optional[Set[int]] = None,
        show_progress: bool = True
    ) -> List[ScanResult]:
        """
        Perform directory/file scan.
        
        Args:
            wordlist: List of paths to scan
            extensions: File extensions to append
            exclude_codes: Status codes to exclude from results
            include_codes: Only include these status codes
            show_progress: Show scanning progress
        
        Returns:
            List of ScanResult objects
        """
        exclude_codes = exclude_codes or {404}
        
        # Build full path list with extensions
        paths = []
        for word in wordlist:
            paths.append(word)
            if extensions:
                for ext in extensions:
                    ext = ext.lstrip(".")
                    paths.append(f"{word}.{ext}")
        
        total = len(paths)
        start_time = time.time()
        
        print(f"\n{Colors.info('[*] Starting scan...')}")
        print(f"{Colors.info(f'[*] Target: {self.target}')}")
        print(f"{Colors.info(f'[*] Threads: {self.threads}')}")
        print(f"{Colors.info(f'[*] Wordlist size: {total}')}")
        print(f"{Colors.info('-' * 60)}\n")
        
        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            futures = {
                executor.submit(self._scan_path, path): path 
                for path in paths
            }
            
            for future in as_completed(futures):
                if not self.running:
                    executor.shutdown(wait=False)
                    break
                
                self.scanned_count += 1
                result = future.result()
                
                if result:
                    # Apply filters
                    if include_codes and result.status_code not in include_codes:
                        continue
                    if result.status_code in exclude_codes:
                        continue
                    
                    self.found_count += 1
                    self.results.append(result)
                    
                    # Print result
                    color = Colors.status_color(result.status_code)
                    size_str = self._format_size(result.content_length)
                    
                    output = f"{color}[{result.status_code}]{Style.RESET_ALL} {result.url}"
                    output += f" {Fore.WHITE}[{size_str}]{Style.RESET_ALL}"
                    
                    if result.redirect_url:
                        output += f" {Fore.BLUE}-> {result.redirect_url}{Style.RESET_ALL}"
                    
                    print(output)
                
                # Progress update
                if show_progress and self.scanned_count % 100 == 0:
                    elapsed = time.time() - start_time
                    rate = self.scanned_count / elapsed if elapsed > 0 else 0
                    progress = (self.scanned_count / total) * 100
                    print(
                        f"\r{Fore.CYAN}[*] Progress: {progress:.1f}% "
                        f"({self.scanned_count}/{total}) "
                        f"| Rate: {rate:.0f} req/s "
                        f"| Found: {self.found_count}{Style.RESET_ALL}",
                        end="",
                        flush=True
                    )
        
        elapsed = time.time() - start_time
        print(f"\n\n{Colors.info('-' * 60)}")
        print(f"{Colors.success(f'[+] Scan completed in {elapsed:.2f}s')}")
        print(f"{Colors.success(f'[+] Requests: {self.scanned_count}')}")
        print(f"{Colors.success(f'[+] Found: {self.found_count}')}")
        
        return self.results
    
    def _format_size(self, size: int) -> str:
        """Format byte size to human readable."""
        for unit in ["B", "KB", "MB", "GB"]:
            if size < 1024:
                return f"{size:.0f}{unit}"
            size /= 1024
        return f"{size:.0f}TB"


def load_wordlist(path: str) -> List[str]:
    """Load wordlist from file."""
    if not os.path.isfile(path):
        print(Colors.error(f"[!] Wordlist not found: {path}"))
        sys.exit(1)
    
    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        words = [line.strip() for line in f if line.strip() and not line.startswith("#")]
    
    return words


def save_results(results: List[ScanResult], output_path: str):
    """Save results to file."""
    with open(output_path, "w") as f:
        for result in results:
            line = f"{result.url} [{result.status_code}] [{result.content_length}]"
            if result.redirect_url:
                line += f" -> {result.redirect_url}"
            f.write(line + "\n")
    
    print(Colors.success(f"[+] Results saved to {output_path}"))


def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(
        description="pybusterTN - Professional Directory Bruteforcer",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s -u http://example.com -w wordlist.txt
  %(prog)s -u https://example.com -w wordlist.txt -t 20 -x php,html
  %(prog)s -u http://example.com -w wordlist.txt -o results.txt --no-ssl
  %(prog)s -u http://example.com -w wordlist.txt -H "Authorization: Bearer token"
        """
    )
    
    # Required arguments
    parser.add_argument(
        "-u", "--url",
        required=True,
        help="Target URL"
    )
    parser.add_argument(
        "-w", "--wordlist",
        required=True,
        help="Path to wordlist file"
    )
    
    # Optional arguments
    parser.add_argument(
        "-t", "--threads",
        type=int,
        default=DEFAULT_THREADS,
        help=f"Number of threads (default: {DEFAULT_THREADS})"
    )
    parser.add_argument(
        "-x", "--extensions",
        help="File extensions to check (comma-separated, e.g., php,html,txt)"
    )
    parser.add_argument(
        "-o", "--output",
        help="Output file for results"
    )
    parser.add_argument(
        "--timeout",
        type=int,
        default=DEFAULT_TIMEOUT,
        help=f"Request timeout in seconds (default: {DEFAULT_TIMEOUT})"
    )
    parser.add_argument(
        "-a", "--user-agent",
        default=DEFAULT_USER_AGENT,
        help="Custom User-Agent string"
    )
    parser.add_argument(
        "-c", "--cookies",
        help="Cookies to include (format: name=value;name2=value2)"
    )
    parser.add_argument(
        "-H", "--header",
        action="append",
        help="Custom header (can be used multiple times)"
    )
    parser.add_argument(
        "--proxy",
        help="Proxy URL (e.g., http://127.0.0.1:8080)"
    )
    parser.add_argument(
        "-f", "--follow-redirects",
        action="store_true",
        help="Follow redirects"
    )
    parser.add_argument(
        "--no-ssl",
        action="store_true",
        help="Disable SSL certificate verification"
    )
    parser.add_argument(
        "-s", "--status-codes",
        help="Only show specific status codes (comma-separated)"
    )
    parser.add_argument(
        "-b", "--blacklist-codes",
        default="404",
        help="Status codes to exclude (default: 404)"
    )
    parser.add_argument(
        "-q", "--quiet",
        action="store_true",
        help="Quiet mode (no banner)"
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"pybusterTN v{VERSION}"
    )
    
    args = parser.parse_args()
    
    # Print banner
    if not args.quiet:
        print_banner()
    
    # Parse headers
    headers = {}
    if args.header:
        for h in args.header:
            if ":" in h:
                key, value = h.split(":", 1)
                headers[key.strip()] = value.strip()
    
    # Parse extensions
    extensions = None
    if args.extensions:
        extensions = [e.strip() for e in args.extensions.split(",")]
    
    # Parse status codes
    include_codes = None
    if args.status_codes:
        include_codes = {int(c.strip()) for c in args.status_codes.split(",")}
    
    exclude_codes = {int(c.strip()) for c in args.blacklist_codes.split(",")}
    
    # Load wordlist
    wordlist = load_wordlist(args.wordlist)
    
    # Create scanner
    scanner = DirectoryScanner(
        target=args.url,
        threads=args.threads,
        timeout=args.timeout,
        user_agent=args.user_agent,
        cookies=args.cookies,
        headers=headers,
        proxy=args.proxy,
        follow_redirects=args.follow_redirects,
        verify_ssl=not args.no_ssl
    )
    
    # Run scan
    results = scanner.scan(
        wordlist=wordlist,
        extensions=extensions,
        exclude_codes=exclude_codes,
        include_codes=include_codes
    )
    
    # Save results
    if args.output and results:
        save_results(results, args.output)


if __name__ == "__main__":
    main()
