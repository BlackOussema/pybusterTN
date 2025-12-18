# Pybuster
Python-based directory brute force tool inspired by Gobuster.

## Features
- Multi-threading
- Custom User-Agent
- Colored terminal output
- Save results to a file
- Signature: by Ghariani Oussema TN

## Installation
```bash
git clone https://github.com/BlackOussema/pybuster.git
cd pybusterTN
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
python3 pybuster.py -u https://target.com -w common.txt -t 15 -o results.txt 
