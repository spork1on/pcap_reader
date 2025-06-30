# PCAP Reader

Interactive and CLI-based tool for reading, filtering, and exporting packets from `.pcap` and `.pcapng` files

---

## Features

- Read `.pcap` and `.pcapng` files  
- Filter by protocol, source port, and destination port
- Identifies TCP anomalies
- Export results to `.csv` or `.txt`  
- Interactive mode for guided usage  
- Command-line interface (CLI) for quick execution

---

## Requirements

- Python ">=3.11,<4"
- [Scapy](https://scapy.net/)
- [pyfiglet](https://pypi.org/project/pyfiglet/)

Install the dependencies with:

```bash
pip install -r requirements.txt