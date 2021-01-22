from scapy.all import *
import time

import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

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


def expand(x):
    yield x
    while x.payload:
        x = x.payload
        yield x

def cool_print(a, b):
    if b == None:
        return
    print(f"| {a}\t= {b}")

def packet_callback(packet:Packet):
    try:
        parse_packet(packet)
    except Exception as e:
        print(f"you got an e\n\n{e}\n\nrror")

def parse_packet(packet:Packet):
    if IP not in packet:
        return
    src = packet[IP].src
    dst = packet[IP].dst


    if packet[TCP].dport == 80:
        payload = str(bytes(packet[TCP].payload))
        user_agent_unsplitted = payload[payload.find("User-Agent"):payload.find("\\r\\n", payload.find("User-Agent"))]
        user_agent = user_agent_unsplitted.split()[1:]
        if user_agent != []:
            #print(user_agent)
            #browser detection
            if len(user_agent) >= 2:
                browsers = user_agent_unsplitted.split(")")[-1].split()
                #print(browsers)
                if len(browsers) == 2:
                    if "Version" in browsers[0]:
                        print(f'Browser: {browsers[1].split("/")[0]}, Version {browsers[0].split("/")[1]}')
                    if "Gecko" in browsers[0]:
                        print(f'Browser: {browsers[1].split("/")[0]}, Version {browsers[1].split("/")[1]}')
                    if "Chrome" in browsers[0] and "Safari" in browsers[1]:
                        print(f'Browser: {browsers[0].split("/")[0]}, Version {browsers[0].split("/")[1]}')
                    if browsers == ["like", "Gecko"]:
                        print("Browser: Internet Explorer, Version: 11")
                elif len(browsers) == 3:
                    if "Version" in browsers[0]:
                        print(f'Browser: {browsers[2].split("/")[0]} on Mobile, Version {browsers[0].split("/")[1]}')
                    else:
                        print(f'Browser: {browsers[2].split("/")[0]}, Version {browsers[2].split("/")[1]}'.replace("Edg", "Edge"))
            else:
                print(f'Client Agent: {user_agent[0]}')


            # "system info" ~Yuval "I wrote that comment too" ~Omri
            system_info = user_agent_unsplitted.split("(")[1].split(")")[0].replace("Windows NT 10.0", "Windows 10").replace("Win64", "64 bit platform")
            print(system_info)

    # src_p = src + "/" + str(packet[TCP].sport)
    # dst_p = dst + "/" + str(packet[TCP].dport)

    # ttl = packet[IP].ttl
    # wsize = packet[TCP].window

    # flags = packet[TCP].flags
    # flags = [flags_dict[key] for key in list(flags_dict.keys()) if key & flags]
    # #if "SYN" in flags:
        
    # print(f".-[ {src_p} -> {dst_p} ({', '.join(flags)}) ]-")
    # cool_print(['server', 'client'][src==LOCAL_IP], src_p)
    # cool_print("ttl\t", ttl)
    # cool_print("window size", wsize)

    # #print(dir(packet[TCP]))
    # if src in IP_OS.keys() and IP_OS.get(src) != None:
    #     cool_print("os\t", IP_OS.get(src))
    # elif "SYN" in flags:
    #     options = packet[TCP].options
    #     formatted_options = []
    #     for i in options:
    #         if i[1] == None or i[1] == b'':
    #             continue
    #         formatted_options.append(str(i[0]) + ": " + str(i[1]))
    #     cool_print("options", ', '.join(formatted_options))
    #     time.sleep(1)
    #     if OS_TABLE.get((ttl, wsize)) != None:
    #         IP_OS[src] = OS_TABLE.get((ttl, wsize))
    #         cool_print("os\t", OS_TABLE.get((ttl, wsize)))

    # #print(dir(packet[TCP]))
    # #print(list(expand(packet)))
    # #print(packet[INET])
    # #packet.show()

    # print("`....\n")
    
print("started")
sniff(filter="tcp",prn=packet_callback)