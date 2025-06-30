import csv, sys

def export_txt(packets, output_path):
    with open(output_path, 'w') as f:
        for pack in packets:
            f.write(str(pack) + '\n')

def export_csv(packets, output_path, newline=''):
    if not packets:
        return

    fields = sorted({key for packet in packets for key in packet.keys()})

    with open(output_path, 'w', newline=newline, encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fields, extrasaction='ignore')
        writer.writeheader()
        for pack in packets:
            writer.writerow(pack)

def to_file(protocol, packets, output_path):
    if output_path.suffix == ".csv":
        if not protocol:
            print("Error: a protocol filter is needed for .csv")
            sys.exit(1)
        export_csv(packets, output_path)
    else:
        export_txt(packets, output_path)