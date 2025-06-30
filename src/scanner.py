from scapy.all import PcapReader, rdpcap
from src.analyzer import PacketAnalyzer


def load_packups(file_path, stream_mode=False):
    file_path = str(file_path)
    if stream_mode:
        return PcapReader(file_path)
    else:
        return rdpcap(file_path)

def scan(file_path, stream_mode=False):
#tradução dos pacotes para dict
    packets = load_packups(file_path, stream_mode)
    analyzer = PacketAnalyzer()
    extracted_packets = []
    for packet in packets:
        extracted_packets.append(analyzer.extract_info(packet))

    return extracted_packets