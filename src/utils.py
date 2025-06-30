import pyfiglet
from pathlib import Path

def show_banner(font='slant'):
    banner = pyfiglet.figlet_format("PCAP Reader", font='slant')
    print(banner)

def check_path(prompt_message):
    while True:
        file_path = input(prompt_message).strip()
        p = Path(file_path)
        if p.is_file():
            if p.suffix.lower() == '.pcap' or p.suffix == '.pcapng':
                return p
            else:
                print("Not a PCAP or PCAPNG file, please try again.")
        else:
            print("Invalid path, please try again.")

def check_protocol(prompt_message):
    SUPPORTED_PROTOCOLS = [
        'ARP', 'TCP', 'UDP', 'ICMP', 'IPv4', 'IPv6',
        'HTTP', 'HTTPS', 'DNS', 'FTP', 'SFTP',
        'SMTP', 'POP3', 'IMAP', 'SSH', 'Telnet',
        'DHCP', 'SNMP', 'NTP', 'TLS', 'SSL', 'IPsec',
        'Kerberos', 'SIP', 'RTP', 'RTSP', 'H.323',
        'MGCP', 'SMB', 'CIFS', 'LDAP', 'mDNS', 'SSDP',
        'BitTorrent', 'MQTT', 'AMQP', 'Modbus', 'BACnet'
    ]
    while True:
        user_input = input(prompt_message).strip()
        if not user_input:
            return None
        elif user_input.upper() in SUPPORTED_PROTOCOLS:
            return user_input.upper()
        else:
            print("Invalid protocol\n")

def check_port_prompt(prompt_message):
    while True:
        user_input = input(prompt_message)
        if not user_input:
            return None
        elif user_input.isdigit():
            return int(user_input)
        else:
            print("invalid value")

def check_output(prompt_message):
    while True:
        output = input(prompt_message).strip().lower()
        if output.endswith(".txt") or output.endswith(".csv"):
            return output
        elif not output:
            return None
        else:
            print("Invalid output, please try again.")

def cli_check_filters(protocol, src_port, dst_port):
    filters = {}
    if protocol: filters["protocol"] = protocol
    if src_port: filters["src_port"] = src_port
    if dst_port: filters["dst_port"] = dst_port
    return filters