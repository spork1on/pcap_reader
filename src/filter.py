from typing import Iterable

def matches_filters(packets: dict, **filters):
    for key, expected_value in filters.items():
        if packets.get(key) != expected_value:
            return False
    return True

def apply(packets: Iterable[dict], **filters):
    filtered_packets = []
    for packet in packets:
        if matches_filters(packet, **filters):
            filtered_packets.append(packet)
        else:
            continue

    return filtered_packets
