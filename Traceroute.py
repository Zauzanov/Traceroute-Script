import argparse
import ipaddress
import sys
import time
import scapy.all as scapy

# Create an argument parser:
def parse_args():
    parser = argparse.ArgumentParser(description="Python Traceroute - ICMP")
    parser.add_argument(
        "-t", "--target", 
        required = True,
        help="Target IP or Hostname"
    )

    parser.add_argument(
        "-m", "--max_hops", 
        type=int,
        default = 30, 
        help='Maximum hop limit (default: 30)'
    )
    return parser.parse_args()

# check IP address:
def valid_ip(address: str) -> bool:
    try:
        ipaddress.ip_address(address)
        return True
    except ValueError:
        return False

# performing traceroute:
def traceroute_icmp(target: str, max_hops: int = 30, timeout: int = 2):
    ttl = 1
    print(f"[*] Starting traceroute to {target}, max {max_hops} hops")

    start = time.time()
    while ttl <= max_hops:
        pkt = scapy.IP(dst=target, ttl=ttl) / scapy.ICMP()              # Create a Scapy packet: IP Header + ICMP Echo Request;
        ans = scapy.sr1(pkt, timeout=timeout, verbose=False)            # Send the packet; 

        if ans:
            rtt = (time.time() - start) * 1000
            if ans.haslayer(scapy.ICMP):                                # make sure the reply has an ICMP layer, then extract it;
                icmp = ans.getlayer(scapy.ICMP)
                if icmp.type == 11 and icmp.code == 0:              
                    print(f"{ttl:2} {ans.src:15} (RTT {rtt:.2f} ms)")
                elif icmp.type == 0:    # Echo Reply;
                    print(f"{ttl:2} {ans.src:15} Destination reached (RTT {rtt:.2f} ms)")
                    break
        else:
            print(f"{ttl:2} *** Request timed out")
        ttl +=1

    end = time.time()
    print(f"[*] Trace completed in {end - start:.2f} seconds")


if __name__ == "__main__":
    args = parse_args()

    # Resolve target as a hostname, if target is not a valid IP:
    target = args.target
    if not valid_ip(target):
        try:
            target = scapy.socket.gethostbyname(target)     # resolve hostname
        except Exception:
            print(f"Invalid target: {args.target}")
            sys.exit(1)

    traceroute_icmp(target, args.max_hops)
