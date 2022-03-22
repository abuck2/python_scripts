from numbers import Integral
import subprocess
import argparse
#from dbus import Interface
import netifaces as ni
import os
from uuid import getnode as get_mac
import fcntl
import socket
import struct
import random


"""
Execute as root

"""


class MacHandling:
    def __init__(self, interface:str, change:bool, auto:bool):
        """
        Interface (example wlps4o)
        Change : bool. Should we change mac address
        Auto : Automatic, will try to change mac address
        """
        self.interface = interface
        list_of_interfaces = os.listdir('/sys/class/net/')
        if interface not in list_of_interfaces:
            if "wlp4s0" not in list_of_interfaces:
                raise ValueError("Choose a valid interface : {}".format(list_of_interfaces))
            else : 
                print("Wring interface, switching to wlp4s0")
                self.interface = "wlp4s0"

        self.change = change
        self.auto = auto

    def main(self):
        self.print_ip()
        if self.change:
            self.changer()
        self.print_ip()

    def changer(self):
        subprocess.call(["ifconfig", self.interface, "down"])
        if self.auto:
            self.mac = self.random_address()
            print(type(self.mac))
        else : 
            self.mac = input("Change to : ")
        subprocess.call(["ifconfig", self.interface, "hw", "ether", self.mac])
        subprocess.call(["ifconfig", self.interface, "up"])
        return self.mac

    def print_ip(self):
        list_interfaces = os.listdir('/sys/class/net/')
        print("List of interfaces : {}".format(list_interfaces))
        if not self.auto : 
            interface_idx = int(input("Which one do you want : "))
            interface = list_interfaces[interface_idx]
        else :
            interface = "wlp4s0"
        ni.ifaddresses(interface)
        ip = ni.ifaddresses(interface)[ni.AF_INET][0]['addr']
        print("IP address is : {}".format(ip))  
        mac = self.getHwAddr(interface)
        print("MAC address is : {}".format(mac))  

    def getHwAddr(self, ifname):
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        info = fcntl.ioctl(s.fileno(), 0x8927,  struct.pack('256s', bytes(ifname, 'utf-8')[:15]))
        return ':'.join('%02x' % b for b in info[18:24])

    def random_address(self):
        """
        Generate a random mac address
        """
        Maclist = []
        for i in range(1,7):
            RANDSTR = "".join(random.sample("0123456789abcdef",2))
            Maclist.append(RANDSTR)
        RANDMAC = ":".join(Maclist)
        return RANDMAC






if __name__=="__main__":

    #Argument parsing
    parser = argparse.ArgumentParser(description='MacChanger')
    parser.add_argument('-i', action="store", dest="interface", help="Interface chosen to change mac address")
    parser.add_argument('-c', action='store_true', dest="change", help = "Change mac address")
    parser.add_argument('-a', action="store_true", dest="auto", help="defaults to wlp4s0")
    
    arguments = parser.parse_args()

    mh = MacHandling(arguments.interface, arguments.change, arguments.auto)
    mh.main()