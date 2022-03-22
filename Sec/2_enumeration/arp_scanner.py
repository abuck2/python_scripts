import scapy.all as scapy

def arp_scanner(ip):
    scapy.arping(ip)

def scan(ip):
    arp_request = scapy.ARP(pdst = ip)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    broadcast_arp = broadcast/arp_request
    ans, unans = scapy.spr(broadcast_arp, timeout = 1)
    print(ans.summary)

if __name__ == "__main__":
    
    scan("192.168.0.1/24")