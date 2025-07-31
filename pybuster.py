#!/usr/bin/env python3
import requests
import argparse
import sys
import os
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from colorama import Fore, Style

def signature():
    print(Fore.MAGENTA + "=======================================")
    print(Fore.MAGENTA + "        by Ghariani  Oussema TN        ")
    print(Fore.MAGENTA + "=======================================" + Style.RESET_ALL)

def banner():
    print(Fore.CYAN + r"""
  ____        _           _            
 |  _ \  ___ | |__   ___ | |_ ___  _ __ 
 | | | |/ _ \| '_ \ / _ \| __/ _ \| '__|
 | |_| | (_) | |_) | (_) | || (_) | |   
 |____/ \___/|_.__/ \___/ \__\___/|_|   
      Python Directory Bruteforcer
    """ + Style.RESET_ALL)

def scan_url(target, path, user_agent, timeout):
    url = f"{target.rstrip('/')}/{path}"
    headers = {"User-Agent": user_agent}
    try:
        r = requests.get(url, headers=headers, timeout=timeout, allow_redirects=False)
        status = r.status_code
        print(Fore.BLUE + f"[*] Trying: {url} -> Status: {status}" + Style.RESET_ALL)
        if status != 404:
            return url, status
    except requests.exceptions.RequestException as e:
        print(Fore.RED + f"[!] Error on {url}: {e}" + Style.RESET_ALL)
    return None

def main():
    parser = argparse.ArgumentParser(description="Python Gobuster-like tool")
    parser.add_argument("-u", "--url", required=True, help="Target URL")
    parser.add_argument("-w", "--wordlist", required=True, help="Wordlist path")
    parser.add_argument("-t", "--threads", type=int, default=10, help="Number of threads (default=10)")
    parser.add_argument("-o", "--output", help="Save results to file")
    parser.add_argument("--user-agent", default="Mozilla/5.0 (Python Scanner)", help="Custom User-Agent")
    parser.add_argument("--timeout", type=int, default=5, help="Request timeout in seconds (default=5)")
    args = parser.parse_args()

    if not os.path.isfile(args.wordlist):
        print(Fore.RED + "[!] Wordlist not found!" + Style.RESET_ALL)
        sys.exit(1)

    signature()
    banner()

    print(Fore.YELLOW + f"[+] Target: {args.url}" + Style.RESET_ALL)
    print(Fore.YELLOW + f"[+] Threads: {args.threads}" + Style.RESET_ALL)
    print(Fore.YELLOW + f"[+] Wordlist: {args.wordlist}" + Style.RESET_ALL)
    print(Fore.YELLOW + f"[+] Starting scan..." + Style.RESET_ALL)
    
    start_time = time.time()

    with open(args.wordlist, "r") as f:
        paths = [line.strip() for line in f if line.strip()]

    results = []
    with ThreadPoolExecutor(max_workers=args.threads) as executor:
        futures = [executor.submit(scan_url, args.url, path, args.user_agent, args.timeout) for path in paths]
        for future in as_completed(futures):
            result = future.result()
            if result:
                url, code = result
                print(Fore.GREEN + f"[FOUND] {url} -> {code}" + Style.RESET_ALL)
                results.append(f"{url} -> {code}")

    elapsed = time.time() - start_time
    print(Fore.CYAN + f"\nScan completed in {elapsed:.2f}s" + Style.RESET_ALL)

    if args.output:
        with open(args.output, "w") as f:
            f.write("\n".join(results))
        print(Fore.MAGENTA + f"[+] Results saved to {args.output}" + Style.RESET_ALL)

if __name__ == "__main__":
    main()
