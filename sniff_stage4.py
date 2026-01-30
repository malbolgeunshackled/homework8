from scapy.all import *

def handle(pkt):
    if pkt.haslayer(Raw):
        data = pkt[Raw].load
        if b"POST" in data:
            print("\n===== HTTP POST PACKET =====")
            print(data.decode(errors="ignore"))

sniff(iface="lo0", filter="tcp port 8080", prn=handle, store=False)

