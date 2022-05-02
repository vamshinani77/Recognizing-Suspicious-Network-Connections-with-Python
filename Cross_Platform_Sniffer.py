from scapy.all import *
from scapy.utils import PcapWriter
from datetime import *#datetime, timedelta
import os, sys, signal
#Defines then runs a signal handler because the 'while' loop can get
#sticky in the console. This helps ctrl-c out nicely.
def signal_handler(signal, frame):
    print("\nprogram exiting gracefully")
    sys.exit(0)
signal.signal(signal.SIGINT, signal_handler)
winplat = ["win32", "win64"]
linux = ["linux","linux2","linux3"]
platform = sys.platform
if platform in winplat:
    print("Windows")
    now = datetime.now()
    stop = now + timedelta(seconds=120) #amount of time the script will run for. Can do minutes=x or hours=x
    flushdns = os.system("ipconfig /flushdns") # flush out the windows DNS cache : ipconfig /displaydns to see
    #os.system("pythonw.exe firewallrules.py")
    try:
        while datetime.now() < stop:
            #TCP Syn + SynAck packet capture and DNS port 53 packet capture.
            packets = sniff(filter="tcp[tcpflags] & (tcp-syn)!=0 or port 53",
            session=IPSession, # defragment on-the-flow
            count=2,# 2 packets before the script continues
            prn=lambda x: x.summary()) #prints out the tcp syn/synack and DNS req/resp
            #Append to 'sniffed.pcap' all Syn/Ack traffic or port 53 request/responses.
            # Will create the file if it doesn't already exist
            pktdump1 = PcapWriter("sniffed.pcap", append=True,sync=True)
            pktdump1.write(packets)
            pcap = 'sniffed.pcap'
            pkts = rdpcap(pcap)
            UDPipS = []
            TCPipS = []
            #Add TCP destination packets to a temp list for follow on comparison
            for packet in pkts:
                if packet.haslayer(TCP):
                    TCPipS.append(packet[IP].dst)
                    # DNS parsing for to record multiple DNS entries and extract/normalize PTR requests
                    ## Without this loop only the first DNS entry will be returned and the PTR records will be missed.
                if packet.haslayer(UDP): # Triggers if a UDP packet
                    UDPipS.append(packet.dst) #Adds the packet to ta temp list for PCAP incl
                    if packet.haslayer(DNSRR): # If there is a DNS Response
                        a_count = packet[DNS].ancount
                        #Find how many answers returned
                        i = a_count + 4
                        arp = "arpa"
                        while i > 4:
                            if str(packet[0][i].rdata)[0].isnumeric():
                                #print(packet[0][i].rdata)
                                UDPipS.append(packet[0][i].rdata)
                                #Using 'count' to see if the telltale PTR lookup string is in the rrname field
                            elif packet[0][i].rrname.decode().count("in-addr.arpa")>0:
                                #print(packet[0][i].rrname.decode())
                                base =(packet[0][i].rrname.decode())
                                chop = base[:-14]
                                work = chop.split('.')
                                final = work[3]+"."+work[2]+"."+work[1]+"."+work[0]
                                UDPipS.append(final)
                            i -= 1
                inTnotU = list(set(TCPipS)-set(UDPipS))
            with open('suspicious.txt','w+') as f:
                for i in inTnotU:
                    f.write(str(i))
                    f.write("\n") #Added because the above line does not allow for iteration. This was a work around.
                f.close()
    except KeyboardInterrupt:
        print('Sniffer turned off!')
elif platform in linux:
    print("Linux")
    now = datetime.now()
    stop = now + timedelta(seconds=120) #amount of time the script will run for. Can do minutes=x or hours=x
    try:
        while datetime.now() < stop:
            #TCP Syn + SynAck packet capture and DNS port 53 packet capture.
            packets = sniff(filter="tcp[tcpflags] & (tcp-syn)!=0 or port 53",
            session=IPSession, # defragment on-the-flow
            count=2,# 2 packets before the script continues
            prn=lambda x: x.summary()) #prints out the tcp syn/synack and DNS req/resp
            #Append to 'sniffed.pcap' all Syn/Ack traffic or port 53 request/responses.
            # Will create the file if it doesn't already exist
            pktdump1 = PcapWriter("sniffed.pcap", append=True,sync=True)
            pktdump1.write(packets)
            pcap = 'sniffed.pcap'
            pkts = rdpcap(pcap)
            UDPipS = []
            TCPipS = []
            #Add TCP destination packets to a temp list for follow on comparison
            for packet in pkts:
                if packet.haslayer(TCP):
                    TCPipS.append(packet[IP].dst)
                    # DNS parsing for to record multiple DNS entries and extract/normalize PTR requests
                    ## Without this loop only the first DNS entry will be returned and the PTR records will be missed.
                if packet.haslayer(UDP): # Triggers if a UDP packet
                    UDPipS.append(packet[IP].dst) #Adds the packet to ta temp list for PCAP incl
                if packet.haslayer(DNSRR): # If there is a DNS Response
                    a_count = packet[DNS].ancount
                    #Find how many answers returned
                    i = a_count + 4
                    arp = "arpa"
                    while i > 4:
                        if str(packet[0][i].rdata)[0].isdigit():
                            #print(packet[0][i].rdata)
                            UDPipS.append(packet[0][i].rdata)
                            #Using 'count' to see if the telltale PTR lookup string is in the rrname field
                        elif packet[0][i].rrname.decode().count("in-addr.arpa")>0:
                            #print(packet[0][i].rrname.decode())
                            base = (packet[0][i].rrname.decode())
                            chop = base[:-14]
                            work = chop.split('.')
                            final = work[3]+"."+work[2]+"."+work[1]+"."+work[0]
                            UDPipS.append(final)
                        i -= 1
            inTnotU = list(set(TCPipS)-set(UDPipS))
        with open('suspicious.txt','w+') as f:
            for i in inTnotU:
                f.write(str(i))
                f.write("\n") #Added because the above line does not allow for iteration. This was a work around.
                f.close()
    except KeyboardInterrupt:
        print('Sniffer turned off!')
elif platform == "darwin":
    print("MacOS")
    now = datetime.now()
    stop = now + timedelta(seconds=120) #amount of time the script will run for. Can do minutes=x or hours=x
    try:
        while datetime.now() < stop:
            #TCP Syn + SynAck packet capture and DNS port 53 packet capture
            packets = sniff(filter="tcp[tcpflags] & (tcp-syn)!=0 or port 53",session=IPSession, # defragment on-the-flow
            count=2,# 2 packets before the script continues
            prn=lambda x: x.summary()) #prints out the tcp syn/synack and DNS req/resp
            #Append to 'sniffed.pcap' all Syn/Ack traffic or
            #port 53 request/responses.
            # Will create the file if it doesn't already
            #exist
            pktdump1 = PcapWriter("sniffed.pcap", append=True,sync=True)
            pktdump1.write(packets)
            pcap = 'sniffed.pcap'
            pkts = rdpcap(pcap)
            UDPipS = []
            TCPipS = []
            #Add TCP destination packets to a temp list for follow on comparison
            for packet in pkts:
                if packet.haslayer(TCP):
                    TCPipS.append(packet[IP].dst)
                    # DNS parsing for to record multiple DNS entries and extract/normalize
                    # PTR requests
                    ## Without this loop only the first DNS entry will be returned and the
                    #PTR records will be missed.
                if packet.haslayer(UDP): # Triggers if a UDP packet
                    UDPipS.append(packet[IP].dst) #Adds the packet to ta temp list for PCAP incl
                    if packet.haslayer(DNSRR): # If there is a DNS Response
                        a_count = packet[DNS].ancount
                        #Find how many answers returned
                        i = a_count + 4
                        arp = "arpa"
                        while i > 4:
                            if str(packet[0][i].rdata)[0].isdigit():
                                #print(packet[0][i].rdata)
                                UDPipS.append(packet[0][i].rdata)
                                #Useing 'count' to see ifthe telltale PTR lookup string is in the rrname field                                
                            elif packet[0][i].rrname.decode().count("in-addr.arpa")>0:
                                #print(packet[0][i].rrname.decode())
                                base =(packet[0][i].rrname.decode())
                                chop = base[:-14]
                                work =chop.split('.')
                                final = work[3]+"."+work[2]+"."+work[1]+"."+work[0]
                                UDPipS.append(final)
                            i -= 1
                inTnotU = list(set(TCPipS)-set(UDPipS))
            with open('suspicious.txt','w+') as f:
                for i in inTnotU:
                    f.write(str(i))
                    f.write("\n") #Added because the above line does not allow for iteration. This was a work around.
                f.close()
    except KeyboardInterrupt:
        print('Sniffer turned off!')
else:
    print("whoknowsman")
