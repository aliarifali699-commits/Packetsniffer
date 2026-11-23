from scapy.all import sniff, IP, TCP, UDP

def packet_callback(packet):
    # Sirf un packets ko process karein jisme IP layer maujood ho
    if IP in packet:
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        
        # Sirf TCP ya UDP traffic dikhayein (baaki noise hata dein)
        if TCP in packet:
            print(f"[TCP] {src_ip} -> {dst_ip} | Src Port: {packet[TCP].sport} | Dst Port: {packet[TCP].dport}")
        elif UDP in packet:
            print(f"[UDP] {src_ip} -> {dst_ip} | Src Port: {packet[UDP].sport} | Dst Port: {packet[UDP].dport}")

def main():
    print("[*] Sniffer Started... (Press Ctrl+C to stop)")
    print("[*] Capturing only TCP/UDP IP Traffic...")
    # store=False memory bachata hai, aur count=20 sirf 20 packets capture karega
    # Aap count hata sakte hain agar lagataar chalana hai
    sniff(prn=packet_callback, store=False)

if __name__ == "__main__":
    main()