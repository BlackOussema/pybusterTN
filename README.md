<p align="center">
  <img src="https://img.shields.io/badge/Python-3.8+-blue.svg" alt="Python">
  <img src="https://img.shields.io/badge/License-MIT-green.svg" alt="License">
  <img src="https://img.shields.io/badge/Platform-Cross--Platform-lightgrey.svg" alt="Platform">
</p>

<h1 align="center">🔍 pybusterTN</h1>

<p align="center">
  <strong>Professional Directory & File Bruteforcer</strong>
</p>

<p align="center">
  A fast, multithreaded directory and file discovery tool for web applications.<br>
  Similar to gobuster/dirbuster but written in Python with enhanced features.
</p>

---

## ✨ Features

- **Multithreaded Scanning** - Configurable thread count for fast scanning
- **Extension Bruteforcing** - Automatically append file extensions
- **Custom Headers & Cookies** - Full request customization
- **Proxy Support** - Route traffic through proxies
- **Status Code Filtering** - Include/exclude specific response codes
- **Progress Tracking** - Real-time scan progress and statistics
- **Colored Output** - Easy-to-read color-coded results
- **Graceful Interruption** - Clean Ctrl+C handling

---

## 🚀 Quick Start

### Installation

```bash
# Clone the repository
git clone https://github.com/BlackOussema/pybusterTN.git
cd pybusterTN

# Install dependencies
pip install -r requirements.txt
```

### Basic Usage

```bash
# Simple scan
python pybuster.py -u http://example.com -w wordlist.txt

# With extensions
python pybuster.py -u http://example.com -w wordlist.txt -x php,html,txt

# More threads
python pybuster.py -u http://example.com -w wordlist.txt -t 20

# Save results
python pybuster.py -u http://example.com -w wordlist.txt -o results.txt
```

---

## 📖 Usage

```
usage: pybuster.py [-h] -u URL -w WORDLIST [-t THREADS] [-x EXTENSIONS]
                   [-o OUTPUT] [--timeout TIMEOUT] [-a USER_AGENT]
                   [-c COOKIES] [-H HEADER] [--proxy PROXY]
                   [-f] [--no-ssl] [-s STATUS_CODES] [-b BLACKLIST_CODES]
                   [-q] [--version]

Options:
  -u, --url URL           Target URL (required)
  -w, --wordlist FILE     Path to wordlist (required)
  -t, --threads N         Number of threads (default: 10)
  -x, --extensions EXT    File extensions (comma-separated)
  -o, --output FILE       Save results to file
  --timeout SECONDS       Request timeout (default: 10)
  -a, --user-agent STR    Custom User-Agent
  -c, --cookies STR       Cookies (name=value;name2=value2)
  -H, --header STR        Custom header (can repeat)
  --proxy URL             Proxy URL
  -f, --follow-redirects  Follow HTTP redirects
  --no-ssl                Disable SSL verification
  -s, --status-codes      Only show these codes (comma-separated)
  -b, --blacklist-codes   Exclude these codes (default: 404)
  -q, --quiet             No banner
  --version               Show version
```

---

## 💡 Examples

### Basic Directory Scan
```bash
python pybuster.py -u http://target.com -w common.txt
```

### Scan with Extensions
```bash
python pybuster.py -u http://target.com -w wordlist.txt -x php,asp,aspx,jsp
```

### Authenticated Scan
```bash
# With cookies
python pybuster.py -u http://target.com -w wordlist.txt \
  -c "session=abc123;token=xyz789"

# With authorization header
python pybuster.py -u http://target.com -w wordlist.txt \
  -H "Authorization: Bearer eyJhbGc..."
```

### Through Proxy (Burp Suite)
```bash
python pybuster.py -u http://target.com -w wordlist.txt \
  --proxy http://127.0.0.1:8080 --no-ssl
```

### Filter Status Codes
```bash
# Only show 200 and 301
python pybuster.py -u http://target.com -w wordlist.txt -s 200,301

# Exclude 404 and 403
python pybuster.py -u http://target.com -w wordlist.txt -b 404,403
```

### High-Speed Scan
```bash
python pybuster.py -u http://target.com -w wordlist.txt -t 50 --timeout 5
```

---

## 📊 Output Format

### Console Output
```
[200] http://target.com/admin [1.2KB]
[301] http://target.com/images -> http://target.com/images/
[403] http://target.com/config [0B]
[200] http://target.com/login.php [4.5KB]
```

### File Output
```
http://target.com/admin [200] [1234]
http://target.com/images [301] [0] -> http://target.com/images/
http://target.com/config [403] [0]
http://target.com/login.php [200] [4567]
```

---

## 📁 Included Wordlists

The repository includes `common.txt` with common directory and file names:

```
admin
backup
config
database
images
includes
js
css
uploads
...
```

### Recommended Wordlists

- [SecLists](https://github.com/danielmiessler/SecLists)
- [dirbuster wordlists](https://github.com/daviddias/node-dirbuster)
- [fuzzdb](https://github.com/fuzzdb-project/fuzzdb)

---

## 🔧 Configuration

### Environment Variables

```bash
# Set default proxy
export HTTP_PROXY="http://127.0.0.1:8080"
export HTTPS_PROXY="http://127.0.0.1:8080"
```

### Custom User-Agent Examples

```bash
# Chrome on Windows
-a "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0.0.0"

# Firefox on Linux
-a "Mozilla/5.0 (X11; Linux x86_64; rv:121.0) Gecko/20100101 Firefox/121.0"

# Mobile
-a "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15"
```

---

## 📋 Requirements

```
requests>=2.28.0
colorama>=0.4.6
urllib3>=1.26.0
```

---

## ⚠️ Legal Disclaimer

**This tool is for authorized security testing only.**

- Only scan websites you own or have explicit permission to test
- Unauthorized scanning may violate laws and terms of service
- The author is not responsible for misuse
- Always follow responsible disclosure practices

---

## 🤝 Contributing

Contributions are welcome! Please:

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Submit a pull request

### Ideas for Contribution
- Add recursive scanning
- Implement response body filtering
- Add JSON output format
- Create GUI interface

---

## 📄 License

This project is licensed under the MIT License.

---

## 👤 Author

**Ghariani Oussema**
- GitHub: [@BlackOussema](https://github.com/BlackOussema)
- Role: Cyber Security Researcher & Full-Stack Developer
- Location: Tunisia 🇹🇳

---

<p align="center">
  Made with ❤️ in Tunisia 🇹🇳
</p>
