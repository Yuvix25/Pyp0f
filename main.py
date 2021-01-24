from scapy.all import *
import time
import requests
import json

import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

print("""
    syntax:
        OR keyword1, keyword2, keyword3... # prints packets with one or more of these keywords
        AND keyword1, keyword2, keyword3... # prints packets with all of these keywords
        keyword # entering one keyword

        Example input:    OR http, os
""")
# filtering
FILTER_KEYWORD = input("Enter filter keywords, seperated with `, ` (just press enter for no filter): ")

# get local IP of computer
LOCAL_IP = get_if_addr(conf.iface)
# GLOBAL_IP = publicip.get()
url = f"https://api.ipify.org?format=json"

headers = {
    'accept': "application/json",
    'content-type': "application/json"
}

response = json.loads(requests.request("GET", url, headers=headers).text)
GLOBAL_IP = response['ip']


# flag hex to name
flags_dict={
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
OS_TABLE = {
    (64, 5840)  : "Linux (kernel 2.4 and 2.6)",
    (64, 64240) : "Linux",
    (64, 5720)  : "Google's customized Linux",
    (64, 65535) : "FreeBSD or Mac OS",
    (128, 65535): "Windows XP",
    (128, 8192) : "Windows 7, Vista and Server 2008",
    (128, 64240): "Windows 10",
    (255, 4128) : "Cisco Router (IOS 12.4)",
}

# detected OSs
IP_OS = {}

# common ttls (to find out the initial ttl)
TTL_OPTIONS = (32,64,128,255)

# example:  expand([1, 2, [3, [5]]]) -> [1, 2, 3, 5]
def expand(x):
    yield x
    while x.payload:
        x = x.payload
        yield x

# returns a formatted p0f like text
def cool_print(a, b):
    if b == None:
        return
    return f"| {a}\t= {b}"

# try to parse the packet
def packet_callback(packet:Packet):
    try:
        parse_packet(packet)
    except Exception as e:
        print(f"you got an e\n\n{e}\n\nrror")

# parse the sniffed packet
def parse_packet(packet:Packet):
    # check if packet has the IP layer
    if IP not in packet:
        return

    # declare the output list
    output = []
    
    # get source and dest
    src = packet[IP].src
    dst = packet[IP].dst            

    # src + source_port and dest + dest_port
    src_p = src + "/" + str(packet[TCP].sport)
    dst_p = dst + "/" + str(packet[TCP].dport)

    # get window size and ttl and find nearest (but higher) initial ttl from the tuple at the start
    ttl = packet[IP].ttl
    ottl = ttl
    ttl = min([t for t in TTL_OPTIONS if t >= ttl])
    wsize = packet[TCP].window

    
    # find flags and convert them from hex to text
    flags = packet[TCP].flags
    flags = [flags_dict[key] for key in list(flags_dict.keys()) if key & flags]
        
    output.append(f".-[ {src_p} -> {dst_p} ({', '.join(flags)}) ]-")
    # check if is server or client
    output.append(cool_print(['server', 'client'][src==LOCAL_IP], src_p))

    if src == LOCAL_IP:
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
    
    output.append(cool_print('country', response["country_name"]))
    if response["region_name"] != '':
        output.append(cool_print('region', response["region_name"]))
    if response["city"] != '':
        output.append(cool_print('city\t', response["city"]))
    


    #output.append(cool_print('original ttl', ottl))
    output.append(cool_print('initial ttl', str(ttl)+" (guessed)"))
    output.append(cool_print('hops\t', ttl-ottl))

    # if the src is already in the detected os table, print it.
    if src in IP_OS.keys() and IP_OS.get(src) != None:
        output.append(cool_print("os\t", IP_OS.get(src)))
    # else if the SYN flag is on we can put the ttl and window size which we have found earlier, and try to guess the OS.
    elif "SYN" in flags:
        options = packet[TCP].options
        formatted_options = []
        for i in options:
            if i[1] == None or i[1] == b'':
                continue
            formatted_options.append(str(i[0]) + ": " + str(i[1]))
        #output.append(cool_print("options", ', '.join(formatted_options)))
        time.sleep(1)
        if OS_TABLE.get((ttl, wsize)) != None:
            IP_OS[src] = OS_TABLE.get((ttl, wsize))
            output.append(cool_print("os\t", OS_TABLE.get((ttl, wsize))))

    # if the packet is sent to an http server we can extract the metadata from the header
    if packet[TCP].dport == 80:
        payload = str(bytes(packet[TCP].payload))
        # extracting the "user agent" argument from the header if exist
        user_agent_unsplitted = payload[payload.find("User-Agent"):payload.find("\\r\\n", payload.find("User-Agent"))]
        user_agent = user_agent_unsplitted.split()[1:]
        # add to output the browser based on the user agent 
        if user_agent != []:
            output.append("| <--------------> Data From HTTP <-------------->")
            if len(user_agent) >= 2:
                browsers = user_agent_unsplitted.split(")")[-1].split()
                if len(browsers) == 2:
                    # Safari
                    if "Version" in browsers[0]:
                        output.append(cool_print('Browser', f'{browsers[1].split("/")[0]}, Version {browsers[0].split("/")[1]}'))
                    #Firefox
                    if "Gecko" in browsers[0]:
                        output.append(cool_print('Browser', f'{browsers[1].split("/")[0]}, Version {browsers[1].split("/")[1]}'))
                    # Chrome
                    if "Chrome" in browsers[0] and "Safari" in browsers[1]:
                        output.append(cool_print('Browser', f'{browsers[0].split("/")[0]}, Version {browsers[0].split("/")[1]}'))
                    # Internet Explorer (yikes)
                    if browsers == ["like", "Gecko"]:
                        output.append(cool_print("Browser", "Internet Explorer, Version: 11"))
                elif len(browsers) == 3:
                    if "Version" in browsers[0]:
                        # Safari on mobile
                        output.append(cool_print('Browser', f'{browsers[2].split("/")[0]} on Mobile, Version {browsers[0].split("/")[1]}'))
                    else:
                        # most probably Edge or something else...
                        output.append(cool_print('Browser', f'{browsers[2].split("/")[0]}, Version {browsers[2].split("/")[1]}'.replace("Edg", "Edge")))

                # add system info to output based on the user agent
                system_info = user_agent_unsplitted.split("(")[1].split(")")[0].replace("Windows NT 10.0", "Windows 10").replace("Win64", "64 bit platform").replace("X11; Ubuntu; Linux x86_64", "Ubuntu")
                output.append(cool_print('System Info', system_info))
            # We cant find browser that fits so we print it generaly
            else:
                # if there is only one field in the User Agent, print it nicely
                if "/" in user_agent[0]:
                    output.append(cool_print('Client Agent', f'{user_agent[0].split("/")[0]}, Version {user_agent[0].split("/")[1]}'))
                else:
                    output.append(cool_print('Client Agent', f'{user_agent[0]}'))

    output.append("`....\n")

    output = '\n'.join(output)

    # apply filtering roles
    if FILTER_KEYWORD.startswith("OR"):
        if any([key.lower() in output.lower() for key in FILTER_KEYWORD[3:].split(', ')]):
            print(output)
    elif FILTER_KEYWORD.startswith("AND"):
        if all([key.lower() in output.lower() for key in FILTER_KEYWORD[3:].split(', ')]):
            print(output)
    else:
        if FILTER_KEYWORD.lower() in output.lower():
            print(output)
    
# start sniffing only the tcp packets, evey packet captured is being sent to the packet_callback function 
print("started")
sniff(filter="tcp",prn=packet_callback)