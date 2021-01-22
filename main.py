from scapy.all import *
import time

import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

print("""
    syntax:
        OR keyword1, keyword2, keyword3... # prints packets with one or more of these keywords
        AND keyword1, keyword2, keyword3... # prints packets with all of these keywords
        keyword # entering one keyword

        Example input:    OR http, os
""")

FILTER_KEYWORD = input("Enter filter keywords, seperated with `, ` (just press enter for no filter): ")

LOCAL_IP = get_if_addr(conf.iface)

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

IP_OS = {}

TTL_OPTIONS = (60,30,64,128,255,32)

def expand(x):
    yield x
    while x.payload:
        x = x.payload
        yield x

def cool_print(a, b):
    if b == None:
        return
    return f"| {a}\t= {b}"

def packet_callback(packet:Packet):
    try:
        parse_packet(packet)
    except Exception as e:
        print(f"you got an e\n\n{e}\n\nrror")

def parse_packet(packet:Packet):
    if IP not in packet:
        return

    output = []
    
    src = packet[IP].src
    dst = packet[IP].dst            

    src_p = src + "/" + str(packet[TCP].sport)
    dst_p = dst + "/" + str(packet[TCP].dport)

    ttl = packet[IP].ttl
    output.append("before:" + str(ttl))
    ttl = min([t for t in TTL_OPTIONS if t >= ttl])
    output.append("after:" + str(ttl))
    wsize = packet[TCP].window

    flags = packet[TCP].flags
    flags = [flags_dict[key] for key in list(flags_dict.keys()) if key & flags]
        
    output.append(f".-[ {src_p} -> {dst_p} ({', '.join(flags)}) ]-")
    output.append(cool_print(['server', 'client'][src==LOCAL_IP], src_p))

    if src in IP_OS.keys() and IP_OS.get(src) != None:
        output.append(cool_print("os\t", IP_OS.get(src)))
    elif "SYN" in flags:
        options = packet[TCP].options
        formatted_options = []
        for i in options:
            if i[1] == None or i[1] == b'':
                continue
            formatted_options.append(str(i[0]) + ": " + str(i[1]))
        output.append(cool_print("options", ', '.join(formatted_options)))
        time.sleep(1)
        if OS_TABLE.get((ttl, wsize)) != None:
            IP_OS[src] = OS_TABLE.get((ttl, wsize))
            output.append(cool_print("os\t", OS_TABLE.get((ttl, wsize))))

    
    if packet[TCP].dport == 80:
        payload = str(bytes(packet[TCP].payload))
        user_agent_unsplitted = payload[payload.find("User-Agent"):payload.find("\\r\\n", payload.find("User-Agent"))]
        user_agent = user_agent_unsplitted.split()[1:]
        if user_agent != []:
            output.append("| <--------------> Data From HTTP <-------------->")
            if len(user_agent) >= 2:
                browsers = user_agent_unsplitted.split(")")[-1].split()
                if len(browsers) == 2:
                    if "Version" in browsers[0]:
                        output.append(cool_print('Browser', f'{browsers[1].split("/")[0]}, Version {browsers[0].split("/")[1]}'))
                    if "Gecko" in browsers[0]:
                        output.append(cool_print('Browser', f'{browsers[1].split("/")[0]}, Version {browsers[1].split("/")[1]}'))
                    if "Chrome" in browsers[0] and "Safari" in browsers[1]:
                        output.append(cool_print('Browser', f'{browsers[0].split("/")[0]}, Version {browsers[0].split("/")[1]}'))
                    if browsers == ["like", "Gecko"]:
                        output.append(cool_print("Browser", "Internet Explorer, Version: 11"))
                elif len(browsers) == 3:
                    if "Version" in browsers[0]:
                        output.append(cool_print('Browser', f'{browsers[2].split("/")[0]} on Mobile, Version {browsers[0].split("/")[1]}'))
                    else:
                        output.append(cool_print('Browser', f'{browsers[2].split("/")[0]}, Version {browsers[2].split("/")[1]}'.replace("Edg", "Edge")))

                # system info
                system_info = user_agent_unsplitted.split("(")[1].split(")")[0].replace("Windows NT 10.0", "Windows 10").replace("Win64", "64 bit platform").replace("X11; Ubuntu; Linux x86_64", "Ubuntu")
                output.append(cool_print('System Info', system_info))
            else:
                if "/" in user_agent[0]:
                    output.append(cool_print('Client Agent', f'{user_agent[0].split("/")[0]}, Version {user_agent[0].split("/")[1]}'))
                else:
                    output.append(cool_print('Client Agent', f'{user_agent[0]}'))

    output.append("`....\n")

    output = '\n'.join(output)

    if FILTER_KEYWORD.startswith("OR"):
        if any([key.lower() in output.lower() for key in FILTER_KEYWORD[3:].split(', ')]):
            print(output)
    elif FILTER_KEYWORD.startswith("AND"):
        if all([key.lower() in output.lower() for key in FILTER_KEYWORD[3:].split(', ')]):
            print(output)
    else:
        if FILTER_KEYWORD.lower() in output.lower():
            print(output)
    
    
print("started")
sniff(filter="tcp",prn=packet_callback)