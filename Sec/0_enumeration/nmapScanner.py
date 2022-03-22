import nmap

class Scanner:
    def __init__(self):
        self.nmap_instance = nmap.PortScanner()

    def run(self, ip:str="192.168.0.1/24", level:int=0):
        self.nmap_instance.scan(ip)

        for host in self.nmap_instance.all_hosts():
            print('Host : %s (%s)' % (host, self.nmap_instance[host].hostname()))
            print('State : %s' % self.nmap_instance[host].state())
            for proto in self.nmap_instance[host].all_protocols():
                print('----------')
                print('Protocol : %s' % proto)
        
                lport = self.nmap_instance[host][proto].keys()
                lport.sort()
                for port in lport:
                    print ('port : %s\tstate : %s' % (port, self.nmap_instance[host][proto][port]['state']))

if __name__=="__main__":
    scanner= Scanner()
    scanner.run()
