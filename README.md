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
```

### CLI Syntax

```bash
./pcap_reader "input_file_path" "output_file(.txt or .csv)" [-P PROTOCOL] [-s SOURCE_PORT] [-d DESTINATION_PORT]
```

- `"input_file_path"`: Path to the input `.pcap` or `.pcapng` file  
- `"output_file"`: Output filename (must end in `.txt` or `.csv`)  
- `-P`, `--protocol`: Filter by protocol (**uppercase**, e.g., TCP, UDP)  
- `-s`, `--sport`: Filter by source port  
- `-d`, `--dport`: Filter by destination port