import argparse
import sys
import time
from pathlib import Path
from src import export, filter, scanner, utils

def run_CLI_mode():
    utils.show_banner()
    print("Processing", end="", flush=True)
    for _ in range(3):
        time.sleep(0.5)
        print(".", end="", flush=True)

    print()

    parser = argparse.ArgumentParser()
    parser.add_argument("pcap_file", help="input pcap file")
    parser.add_argument("output_file", help="output file")
    parser.add_argument("-v", "--verbose", action="store_true")
    parser.add_argument("-P", "--protocol", choices=[
        'TCP', 'UDP', 'ICMP', 'IPv4', 'IPv6',
        'HTTP', 'HTTPS', 'DNS', 'FTP', 'SFTP',
        'SMTP', 'POP3', 'IMAP', 'SSH', 'Telnet',
        'DHCP', 'SNMP', 'NTP', 'TLS', 'SSL', 'IPsec',
        'Kerberos', 'SIP', 'RTP', 'RTSP', 'H.323',
        'MGCP', 'SMB', 'CIFS', 'LDAP', 'mDNS', 'SSDP',
        'BitTorrent', 'MQTT', 'AMQP', 'Modbus', 'BACnet'], default=None,
                        help="filter packets by protocol")
    parser.add_argument("-s", "--sport", type=int, default=None,
                        help="filter packets by source port")
    parser.add_argument("-d", "--dport", type=int, default=None,
                        help="filter packets by destination port")

    args = parser.parse_args()

    print(args)

    file_path = Path(args.pcap_file)
    output = args.output_file
    protocol = args.protocol
    src_port = args.sport
    dst_port = args.dport

    filters = utils.cli_check_filters(protocol, src_port, dst_port)

    try:
        packets = scanner.scan(file_path)
        if filters:
            packets = filter.apply(packets, **filters)
    except Exception as e:
        print(f"Error scanning the file: {e}")
        sys.exit(1)

    if output:
        output_path = file_path.parent / output
        export.to_file(protocol, packets, output_path)
        print(f"\n File {output_path} successfully exported.")
        sys.exit(0)
    else:
        n = 0
        for pack in packets:
            print(f"{n + 1} {pack}")
            n = n + 1

    print(f"[INFO] {len(packets)} Packets successfully printed.")

def run_interactive_mode():
    print("Entering interactive mode", end="", flush=True)
    for _ in range(3):
        time.sleep(0.5)
        print(".", end="", flush=True)

    print()

    utils.show_banner()

    file_path = utils.check_path("Path to the pcap file: ")
    protocol = utils.check_protocol("Filter by protocol? ")
    src_port = utils.check_port_prompt("Filter by source port? ")
    dst_port = utils.check_port_prompt("Filter by destination port? ")
    output = utils.check_output("Whats the output? (*.txt, *.csv)? / Enter for print: ")

    filters = {}
    if protocol: filters["protocol"] = protocol
    if src_port: filters["src_port"] = src_port
    if dst_port: filters["dst_port"] = dst_port

    try:
        packets = scanner.scan(file_path)
        if filters:
            packets = filter.apply(packets, **filters)
    except Exception as e:
        print(f"Error scanning the file: {e}")
        sys.exit(1)

    if output:
        output_path = file_path.parent / output
        export.to_file(protocol, packets, output_path)
        print(f"\n File {output_path} successfully exported.")
        sys.exit(0)
    else:
        n = 0
        for pack in packets:
            print(f"{n + 1} {pack}")
            n = n + 1

    print(f"[INFO] {len(packets)} Packets successfully printed.")

def main():
    if len(sys.argv) > 1:
        run_CLI_mode()
    else:
        run_interactive_mode()


if __name__ == "__main__":
    main()