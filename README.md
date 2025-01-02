# Rekobee Analyzer

A data analysis and visualization tool for Rekobee that enables customer data analysis and trend identification.

## Usage 

```bash
python3 analyze.py [-h] [-c CAPTURE] [-s SECRET] [-o OUTPUT] [-i INDEX] [-v] [--signature HEX]
```

### -c CAPTURE

### -s SECRET

### -o OUTPUT

### -i INDEX

### -v -vv VERBOSE

### --signature 

## Example
```bash
python3 analyze.py -c capture.pcap -s S3cr3tP@ss -o output.txt -vv
```

## Test Environment

| OS | Version | Status |
|----|---------|---------|
| macOS (Apple M2) | Sequoia 15.2 | ✅ Tested & Working |
| Windows | 11 Home 24H2 | 🚧 Not Tested |
| Kali Linux | 2023.4 | 🚧 Not Tested |

## Setup

1. Clone the repository
```bash
git clone https://github.com/replay9zz/rekobee_analyzer.git
cd rekobee_analyzer
```

2. Create and activate virtual environment
```bash
python -m venv .venv
source .venv/bin/activate
```

3. Install required packages
```bash
pip install -r requirements.txt
```
 