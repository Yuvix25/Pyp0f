import json
import logging
import statistics
import threading

import requests
from scapy import layers
from scapy.all import *

logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

class p0f:
    def __init__(self):

        print("""
            syntax:
                OR keyword1, keyword2, keyword3... # prints packets with one or more of these keywords
                AND keyword1, keyword2, keyword3... # prints packets with all of these keywords
                keyword # entering one keyword

                Example input:    OR http, os
        """)
        # filtering
        self.filter_keywords = input("Enter filter keywords, seperated with `, ` (just press enter for no filter): ")
        self.ignore_filtered = input("Do you want to completly ignore filtered packets? (y/n) ").lower() == 'y'


        # get local IP of computer
        self.local_ip = get_if_addr(conf.iface)

        # self.global_ip = publicip.get()
        url = f"https://api.ipify.org?format=json"

        headers = {
            'accept': "application/json",
            'content-type': "application/json"
        }

        response = json.loads(requests.request("GET", url, headers=headers).text)
        self.global_ip = response['ip']


        # flag hex to name
        self.flags_dict={
            0x01 : 'FIN',
            0x02 : 'SYN',
            0x04 : 'RST',
            0x08 : 'PSH',
            0x10 : 'ACK',
            0x20 : 'URG',
            0x40 : 'ECE',
            0x80 : 'CWR',
        }

        # os fingerprinting table
        self.os_table = {
            (64, 5840)  : "Linux (kernel 2.4 and 2.6)",
            (64, 64240) : "Linux",
            (64, 5720)  : "Google's customized Linux",
            (64, 65535) : "FreeBSD or Mac OS",
            (128, 65535): "Windows XP or Windows 10",
            (128, 8192) : "Windows 7, Vista and Server 2008",
            (128, 64240): "Windows 10",
            (255, 4128) : "Cisco Router (IOS 12.4)",
        }

        self.browser_table = {
            2 : {
                ("Version", "Safari")   : ("Safari", 0),
                ("Gecko", "Firefox")    : ("Firefox", 1),
                ("Chrome", "Safari")    : ("Chrome", 0),
                ("like", "Gecko")       : ("Internet Explorer"),
            },
            3 : {
                ("Chrome", "Mobile", "Safari")  : ("Chrome (on mobile)", 0),
                ("Version", "Mobile", "Safari") : ("Safari (on mobile)", 0),
                ("Chrome", "Safari", "Edg")     : ("Edge", 2),
            },
            4 : {
                ("Chrome", "Mobile", "Safari", "Edg")  : ("Edge (on mobile)", 3),
            },
            5 : {
                ("Version", "Chrome", "Mobile", "DuckDuckGo", "Safari") : ("DuckDuckGo (on mobile)", 3),
            },
        }

        self.geoip_table = {}

        # detected OSs
        self.ip_os = {}

        # common ttls (to find out the initial ttl)
        self.ttl_options = (32,64,128,255)

    def start_sniffing(self):
        # start sniffing only the tcp packets, evey packet captured is being sent to the packet_callback function 
        print("started")
        sniff(filter="tcp",prn=self.packet_callback)
    
    def get_browser(self, agents):
        self.agents = agents
        self.agent_dict = self.browser_table.get(len(self.agents))
        if self.agent_dict != None:
            for key in list(self.agent_dict.keys()):
                if all([key[i] in self.agents[i] for i in range(len(self.agents))]):
                    out = self.agent_dict[key][0] + ", Version: " + self.agents[self.agent_dict[key][1]].split("/")[1]
                    break
        else:
            if "/" in agents[0]:
                out = f'{agents[0].split("/")[0]}, Version {agents[0].split("/")[1]}'
            else:
                out = agents[0]

        try:
            return out
        except:
            return ""

    # returns a formatted p0f like text
    def cool_print(self, a, b):
        if b == None or b == "":
            return ""
        return f"| {a}\t= {b}"

    # try to parse the packet
    def packet_callback(self, packet:Packet):
        try:
            self.parse_packet(packet)
        except Exception as e:
            print(f"An error occured while analising a packet.")

    def find_geoip(self, src):
        if src == self.local_ip:
            url = f"https://freegeoip.app/json/"

            headers = {
                'accept': "application/json",
                'content-type': "application/json"
                }

            response = json.loads(requests.request("GET", url, headers=headers).text)
        else:
            url = f"https://freegeoip.app/json/{src}"

            headers = {
                'accept': "application/json",
                'content-type': "application/json"
                }

            response = json.loads(requests.request("GET", url, headers=headers).text)
        
        geo = {}
        if response["country_name"] != '':
            geo['country'] = response["country_name"]
        if response["region_name"] != '':
            geo['region'] = response["region_name"]
        if response["city"] != '':
            geo["city\t"] = response["city"]

        self.geoip_table[src] = geo


    # parse the sniffed packet
    def parse_packet(self, packet:Packet):
        self.ip_os
        # check if packet has the IP layer
        if IP not in packet:
            return

        # declare the self.output list
        self.output = []
        if self.ignore_filtered:
            TMP_ip_os = self.ip_os.copy()
        
        # get source and dest
        src = packet[IP].src
        dst = packet[IP].dst            

        # src + source_port and dest + dest_port
        src_p = src + "/" + str(packet[TCP].sport)
        dst_p = dst + "/" + str(packet[TCP].dport)

        # get window size and ttl and find nearest (but higher) initial ttl from the tuple at the start
        ttl = packet[IP].ttl
        ottl = ttl
        ttl = min([t for t in self.ttl_options if t >= ttl])
        wsize = packet[TCP].window

        
        # find flags and convert them from hex to text
        flags = packet[TCP].flags
        flags = [self.flags_dict[key] for key in list(self.flags_dict.keys()) if key & flags]
            
        self.output.append(f".-[ {src_p} -> {dst_p} ({', '.join(flags)}) ]-")
        # check if is server or client
        self.output.append(self.cool_print(['server', 'client'][src==self.local_ip], src_p))
        self.output.append(self.cool_print("window size", wsize))

        if src in list(self.geoip_table.keys()):
            for key in list(self.geoip_table[src].keys()):
                self.output.append(self.cool_print(key, self.geoip_table[src][key]))
        else:
            find_geo_thread = threading.Thread(target=self.find_geoip, args=(src,))
            find_geo_thread.start()


        if type(packet) != layers.l2.Ether:
            print(type(packet))
            time.sleep(10)


        #self.output.append(self.cool_print('original ttl', ottl))
        self.output.append(self.cool_print('initial ttl', str(ttl)+" (guessed)"))
        self.output.append(self.cool_print('hops\t', ttl-ottl))

        # if the src is already in the detected os table, print it.
        if src in self.ip_os.keys() and self.ip_os.get(src) != None:
            self.output.append(self.cool_print("os\t", self.ip_os.get(src)))
        # else if the SYN flag is on we can put the ttl and window size which we have found earlier, and try to guess the OS.
        elif "SYN" in flags:

            options = packet[TCP].options
            formatted_options = []
            for i in options:
                if i[1] == None or i[1] == b'':
                    continue
                formatted_options.append(str(i[0]) + ": " + str(i[1]))
            #self.output.append(self.cool_print("options", ', '.join(formatted_options)))
            time.sleep(1)
            if self.os_table.get((ttl, wsize)) != None:
                self.ip_os[src] = self.os_table.get((ttl, wsize))
                self.output.append(self.cool_print("os\t", self.os_table.get((ttl, wsize))))

        # if the packet is sent to an http server we can extract the metadata from the header
        if packet[TCP].dport == 80 or packet[TCP].sport == 80:
            payload = str(bytes(packet[TCP].payload))
            # extracting the "user agent" argument from the header if exist
            user_agent_unsplitted = payload[payload.find("User-Agent"):payload.find("\\r\\n", payload.find("User-Agent"))]
            user_agent = user_agent_unsplitted.split()[1:]
            # add to self.output the browser based on the user agent 
            if user_agent != []:
                self.output.append("| <--------------> Data From HTTP <-------------->")
                if len(user_agent) >= 2:
                    browsers = user_agent_unsplitted.split(")")[-1].split()

                    self.output.append(self.cool_print("Browser", str(self.get_browser(browsers))))

                    # add system info to self.output based on the user agent
                    system_info = user_agent_unsplitted.split("(")[1].split(")")[0].replace("Windows NT 10.0", "Windows 10").replace("Win64", "64 bit platform").replace("Win32", "32 bit platform").replace("X11; Ubuntu; Linux x86_64", "Ubuntu")
                    self.output.append(self.cool_print('System Info', system_info))

        self.output.append("`....\n")
        self.output = [line for line in self.output if line != "" and line != None]
        
        self.output = '\n'.join(self.output)
        print_output = False

        # apply filtering roles
        if self.filter_keywords.startswith("OR"):
            if any([key.lower() in self.output.lower() for key in self.filter_keywords[3:].split(', ')]):
                print_output = True
        elif self.filter_keywords.startswith("AND"):
            if all([key.lower() in self.output.lower() for key in self.filter_keywords[3:].split(', ')]):
                print_output = True
        else:
            if self.filter_keywords.lower() in self.output.lower():
                print_output = True

        if print_output:
            print(self.output)
        elif self.ignore_filtered:
            self.ip_os = TMP_ip_os.copy()
    
if __name__ ==  "__main__":
    _p0f = p0f()
    _p0f.start_sniffing()
