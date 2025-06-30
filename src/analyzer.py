from scapy.layers.inet import IP, TCP, UDP
from scapy.layers.l2 import ARP
from scapy.packet import Raw
from collections import OrderedDict

class PacketAnalyzer:
    def __init__(self, max_seq_memory = 10000):
        self.seen_sequences = OrderedDict()
        self.max_seq_memory = max_seq_memory

    def _add_sequence(self, key, seq):
        if key not in self.seen_sequences:
            self.seen_sequences[key] = set()
        self.seen_sequences[key].add(seq)

        if len(self.seen_sequences) > self.max_seq_memory:
            self.seen_sequences.popitem(last=False)

    def is_retransmission(self, key, seq):
        return key in self.seen_sequences and seq in self.seen_sequences[key]

    def extract_info(self, packet):
        data = {}
        if packet.haslayer(IP):
            ip = packet[IP]
            data["src_IP"] = ip.src
            data["dst_IP"] = ip.dst
        if packet.haslayer(TCP):
            data["anomaly"] = False
            data["retransmission"] = False
            tcp = packet[TCP]
            data["protocol"] = "TCP"
            data["src_port"] = tcp.sport
            data["dst_port"] = tcp.dport
            data["tcp_seq"] = tcp.seq
            data["tcp_ack"] = tcp.ack
            data["tcp_window"] = tcp.window
            data["tcp_flags"] = str(tcp.flags)

            if tcp.options:
                for opt in tcp.options:
                    if opt[0] == "MSS":
                        data["tcp_mss"] = opt[1]

            key = (data["src_IP"], data["dst_IP"], data["src_port"], data["dst_port"])
            seq = data["tcp_seq"]
            has_payload = Raw in packet

            if "S" not in tcp.flags and "F" not in tcp.flags:
                if self.is_retransmission(key, seq):
                    data["retransmission"] = True
                    if not has_payload and "P" in tcp.flags:
                        data["anomaly"] = True
                else:
                    self._add_sequence(key, seq)

        elif packet.haslayer(UDP):
            udp = packet[UDP]
            data["protocol"] = "UDP"
            data["src_port"] = udp.sport
            data["dst_port"] = udp.dport

        if packet.haslayer(ARP):
            arp = packet[ARP]
            data["protocol"] = "ARP"
            data["arp_op"] = arp.op
            data["psrc"] = arp.psrc
            data["pdst"] = arp.pdst
            data["hwsrc"] = arp.hwsrc
            data["hwdst"] = arp.hwdst

        data["info"] = self.format_info(data)
        return data

    def format_info(self, data):
        info_parts = []
        if data.get("protocol") == "ARP":
            if data.get("arp_op") == 1:
                info_parts.append(f'ARP Request: Who has {data.get("pdst")}? Tell {data.get("psrc")}')
            elif data.get("arp_op") == 2:
                info_parts.append(f'ARP Reply: {data.get("psrc")} is at {data.get("hwsrc")}')
        if "protocol" in data:
            info_parts.append(data["protocol"])
        if "src_IP" in data and "src_port" in data:
            info_parts.append(f'{data["src_IP"]}:{data["src_port"]} → {data["dst_IP"]}:{data["dst_port"]}')
        elif "src_IP" in data:
            info_parts.append(f'{data["src_IP"]} → {data["dst_IP"]}')
        if "tcp_seq" in data and "tcp_ack" in data:
            info_parts.append(f'SEQ={data["tcp_seq"]} ACK={data["tcp_ack"]}')
        if "tcp_window" in data:
            info_parts.append(f'WIN={data["tcp_window"]}')
        if "tcp_flags" in data:
            info_parts.append(f'FLAGS={data["tcp_flags"]}')
        if "tcp_mss" in data:
            info_parts.append(f'MSS={data["tcp_mss"]}')

        return " | ".join(info_parts)