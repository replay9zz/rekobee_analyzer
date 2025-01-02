# Rekobee Analyzer

A Python-based tool for analyzing network packet captures.

## Usage 

```bash
python3 analyze.py [-h] [-c CAPTURE] [-s SECRET] [-o OUTPUT] [-i INDEX] [-v] [--signature HEX]
```

### -c CAPTURE
This is a wireshark `pcap` capture file or more modern that tshark supports.

### -s SECRET
This operator uses for password.

### -o OUTPUT
You can save the output to a file.

### -i INDEX
The index of a initial ic2kp packet, 40 bytes in size.

### -v -vv VERBOSE
You can verbose the output.

### --signature 
The magic signature that the client and server used during CHAP.

## Example
```bash
python3 analyze.py -c capture.pcap -s S3cr3tP@ss -o output.txt -vv
```

## Test Environment

| OS | Version | Python | Status |
|----|---------|--------|---------|
| macOS (Apple M2) | Sequoia 15.2 | 3.13.1 | ✅ Tested & Working |
| Windows | 11 Home 24H2 | 3.11.4 | ✅ Tested & Working | 
| Kali Linux | 2024.4 | 3.11.9 | ✅ Tested & Working |

## Setup

1. Clone the repository
```bash
git clone https://github.com/replay9zz/rekobee_analyzer.git
cd rekobee_analyzer
```

2. Create and activate virtual environment (Required)
```bash
python -m venv .venv
source .venv/bin/activate
```

3. Install required packages
```bash
pip install -r requirements.txt
```

4. Change tshark and dumpcap path (Required)

## Acknowledgments
Original repository: [havokzero/rekobee_analyzer](https://github.com/havokzero/rekobee_analyzer)
