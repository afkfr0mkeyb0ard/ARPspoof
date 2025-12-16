# ARPspoof
A Python script to perform ARP spoofing

```
usage: ARPspoof.py -sourceIP [IPADDRESS] -sourceMAC [MACADDRESS] -dstIP [IPADDRESS] -dstMAC [MACADDRESS]
  -sourceIP			spoofed IP of the target (web app, router, ...)
  -sourceMAC		attacker MAC where to redirect trafic
  -dstIP			IP address of destination
  -dstMAC			the MAC of targeted device that you want to Mitm (or ff:ff:ff:ff:ff:ff)
```
```
python3 ARPspoof.py -sourceIP 192.168.1.9 -sourceMAC 00:11:22:33:44:55 -dstIP 192.168.1.1 -dstMAC ff:ff:ff:ff:ff:ff
```
