#!/usr/bin/env python3
"""
============================================================
   NETWORK PACKET ANALYZER
   Built with Scapy 
============================================================
   Captures and analyzes live network traffic.
   Displays Source/Destination IPs, Protocols, Payloads.
   Run with: sudo python3 network_packet_analyzer.py
============================================================
"""

from scapy.all import sniff, conf
from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.layers.dns import DNS, DNSQR, DNSRR
from scapy.layers.http import HTTP, HTTPRequest, HTTPResponse
from datetime import datetime
import sys
import os



class Color:
    RED     = "\033[91m"
    GREEN   = "\033[92m"
    YELLOW  = "\033[93m"
    BLUE    = "\033[94m"
    MAGENTA = "\033[95m"
    CYAN    = "\033[96m"
    WHITE   = "\033[97m"
    BOLD    = "\033[1m"
    RESET   = "\033[0m"


# ──────────────────────────────────────────────
#  PACKET COUNTER
# ──────────────────────────────────────────────
packet_count = 0
stats = {
    "TCP": 0,
    "UDP": 0,
    "ICMP": 0,
    "DNS": 0,
    "HTTP": 0,
    "Other": 0,
}


def print_banner():
    """Print startup banner."""
    print(f"""
{Color.CYAN}{Color.BOLD}
╔══════════════════════════════════════════════════════╗
║         NETWORK PACKET ANALYZER v1.0                ║
║         Code Alpha Internship - Task 2              ║
║         Built with Scapy (Python)                   ║
╚══════════════════════════════════════════════════════╝
{Color.RESET}
{Color.YELLOW}[INFO] Capturing live network packets...
[INFO] Press Ctrl+C to stop and view summary.
{Color.RESET}
{"─" * 60}
""")


def print_separator(color=Color.WHITE):
    print(f"{color}{'─' * 60}{Color.RESET}")


def get_protocol_name(packet):
    """Identify the protocol of a packet."""
    if packet.haslayer(DNS):
        return "DNS"
    elif packet.haslayer(HTTPRequest) or packet.haslayer(HTTPResponse):
        return "HTTP"
    elif packet.haslayer(TCP):
        return "TCP"
    elif packet.haslayer(UDP):
        return "UDP"
    elif packet.haslayer(ICMP):
        return "ICMP"
    else:
        return "Other"


def get_protocol_color(protocol):
    """Return color based on protocol."""
    colors = {
        "TCP":   Color.GREEN,
        "UDP":   Color.BLUE,
        "ICMP":  Color.YELLOW,
        "DNS":   Color.MAGENTA,
        "HTTP":  Color.CYAN,
        "Other": Color.WHITE,
    }
    return colors.get(protocol, Color.WHITE)


def analyze_tcp(packet):
    """Extract and display TCP layer details."""
    tcp = packet[TCP]
    flags = []
    if tcp.flags & 0x02: flags.append("SYN")
    if tcp.flags & 0x10: flags.append("ACK")
    if tcp.flags & 0x01: flags.append("FIN")
    if tcp.flags & 0x04: flags.append("RST")
    if tcp.flags & 0x08: flags.append("PSH")
    flag_str = ", ".join(flags) if flags else "None"

    print(f"  {Color.GREEN}[TCP]{Color.RESET}")
    print(f"    Src Port  : {tcp.sport}")
    print(f"    Dst Port  : {tcp.dport}")
    print(f"    Flags     : {flag_str}")
    print(f"    Seq No    : {tcp.seq}")
    print(f"    Ack No    : {tcp.ack}")
    print(f"    Window    : {tcp.window}")


def analyze_udp(packet):
    """Extract and display UDP layer details."""
    udp = packet[UDP]
    print(f"  {Color.BLUE}[UDP]{Color.RESET}")
    print(f"    Src Port  : {udp.sport}")
    print(f"    Dst Port  : {udp.dport}")
    print(f"    Length    : {udp.len} bytes")


def analyze_icmp(packet):
    """Extract and display ICMP layer details."""
    icmp = packet[ICMP]
    icmp_types = {0: "Echo Reply", 8: "Echo Request", 3: "Dest Unreachable", 11: "Time Exceeded"}
    icmp_type_name = icmp_types.get(icmp.type, f"Type {icmp.type}")
    print(f"  {Color.YELLOW}[ICMP]{Color.RESET}")
    print(f"    Type      : {icmp_type_name}")
    print(f"    Code      : {icmp.code}")


def analyze_dns(packet):
    """Extract and display DNS query/response details."""
    dns = packet[DNS]
    print(f"  {Color.MAGENTA}[DNS]{Color.RESET}")
    if dns.qr == 0:  # Query
        print(f"    Type      : Query")
        if packet.haslayer(DNSQR):
            print(f"    Question  : {packet[DNSQR].qname.decode()}")
    else:  # Response
        print(f"    Type      : Response")
        if packet.haslayer(DNSRR):
            print(f"    Answer    : {packet[DNSRR].rdata}")


def analyze_http(packet):
    """Extract and display HTTP request/response details."""
    print(f"  {Color.CYAN}[HTTP]{Color.RESET}")
    if packet.haslayer(HTTPRequest):
        http = packet[HTTPRequest]
        method = http.Method.decode() if http.Method else "N/A"
        host   = http.Host.decode() if http.Host else "N/A"
        path   = http.Path.decode() if http.Path else "N/A"
        print(f"    Type      : Request")
        print(f"    Method    : {method}")
        print(f"    Host      : {host}")
        print(f"    Path      : {path}")
    elif packet.haslayer(HTTPResponse):
        http = packet[HTTPResponse]
        status = http.Status_Code.decode() if http.Status_Code else "N/A"
        print(f"    Type      : Response")
        print(f"    Status    : {status}")


def analyze_payload(packet):
    """Extract and display raw payload if present."""
    try:
        # Get the topmost payload layer
        if packet.haslayer(TCP) and bytes(packet[TCP].payload):
            raw = bytes(packet[TCP].payload)
        elif packet.haslayer(UDP) and bytes(packet[UDP].payload):
            raw = bytes(packet[UDP].payload)
        else:
            return

        # Only show printable ASCII payloads
        printable = ''.join(chr(b) if 32 <= b < 127 else '.' for b in raw[:80])
        if printable.strip('.'):
            print(f"  {Color.WHITE}[Payload]{Color.RESET}")
            print(f"    Size      : {len(raw)} bytes")
            print(f"    Preview   : {printable[:80]}")
    except Exception:
        pass


def packet_callback(packet):
    """Main callback — called for every captured packet."""
    global packet_count, stats

    # Only process IP packets
    if not packet.haslayer(IP):
        return

    packet_count += 1
    protocol = get_protocol_name(packet)
    stats[protocol] = stats.get(protocol, 0) + 1
    color = get_protocol_color(protocol)

    timestamp = datetime.now().strftime("%H:%M:%S.%f")[:-3]
    ip = packet[IP]

    print_separator(color)
    print(f"{color}{Color.BOLD}  Packet #{packet_count:<5}  [{protocol}]  {timestamp}{Color.RESET}")
    print_separator(color)

    # IP Layer
    print(f"  {Color.WHITE}[IP Layer]{Color.RESET}")
    print(f"    Src IP    : {Color.RED}{ip.src}{Color.RESET}")
    print(f"    Dst IP    : {Color.GREEN}{ip.dst}{Color.RESET}")
    print(f"    Version   : IPv{ip.version}")
    print(f"    TTL       : {ip.ttl}")
    print(f"    Length    : {ip.len} bytes")
    print(f"    Protocol  : {ip.proto}")

    # Transport / Application Layer
    if protocol == "HTTP":
        analyze_http(packet)
    elif protocol == "DNS":
        analyze_dns(packet)
    elif protocol == "TCP":
        analyze_tcp(packet)
    elif protocol == "UDP":
        analyze_udp(packet)
    elif protocol == "ICMP":
        analyze_icmp(packet)

    # Payload
    analyze_payload(packet)
    print()


def print_summary():
    """Print statistics summary at the end."""
    print(f"\n{Color.CYAN}{Color.BOLD}")
    print("╔══════════════════════════════════════════════════════╗")
    print("║                  CAPTURE SUMMARY                   ║")
    print("╚══════════════════════════════════════════════════════╝")
    print(f"{Color.RESET}")
    print(f"  Total Packets Captured : {Color.BOLD}{packet_count}{Color.RESET}")
    print()
    print(f"  Protocol Breakdown:")
    for proto, count in stats.items():
        if count > 0:
            bar = "█" * min(count, 40)
            color = get_protocol_color(proto)
            print(f"    {color}{proto:<8}{Color.RESET}  {count:>4}  {color}{bar}{Color.RESET}")
    print()
    print(f"  {Color.YELLOW}Capture ended at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}{Color.RESET}")
    print()


# ──────────────────────────────────────────────
#  MAIN
# ──────────────────────────────────────────────
def main():
    # Check for root/admin privileges
    if os.geteuid() != 0:
        print(f"{Color.RED}[ERROR] Root privileges required.")
        print(f"        Run with: sudo python3 network_packet_analyzer.py{Color.RESET}")
        sys.exit(1)

    print_banner()

    # Configuration
    PACKET_COUNT =50       # 0 = capture indefinitely until Ctrl+C
    INTERFACE    = None    # None = default interface (auto-detected)
    FILTER       = "ip"    # BPF filter — capture only IP packets

    try:
        sniff(
            iface=INTERFACE,
            filter=FILTER,
            prn=packet_callback,
            count=PACKET_COUNT,
            store=False        # Don't store packets in memory
        )
    except KeyboardInterrupt:
        print(f"\n{Color.YELLOW}[INFO] Capture stopped by user.{Color.RESET}")
    except PermissionError:
        print(f"{Color.RED}[ERROR] Permission denied. Run with sudo.{Color.RESET}")
        sys.exit(1)
    except Exception as e:
        print(f"{Color.RED}[ERROR] {e}{Color.RESET}")
        sys.exit(1)
    finally:
        print_summary()


if __name__ == "__main__":
    main()
