import sys
import socket
import random, math
import fcntl
import struct
import tcp
import ip
import eth
import os
import arp
import select

VERBOSE = True
MAX_BUF_SIZE = 4096
SIOCGIFADDR = 0x8915
SIOCSIFHWADDR = 0x8927
ETH_P_IP = 0x800
ETH_P_ARP = 0x806

if VERBOSE:
    def verbose_print(*args):
        for arg in args:
           print arg,
        print
else:   
    verbose_print = lambda *a: None      # do-nothing

class RawSocket:
    def __init__(self):
        self.sockfd = RawTCPSocket("wlan0")

    def connect(self, (hostname, port)):
        self.sockfd.connect((hostname, port))

    def close(self):
        self.sockfd.close()

    def send(self, data):
        self.sockfd.send(data)

    def recv(self, length):
        return self.sockfd.recv(length) 

class RawTCPSocket:
    def __init__(self, ifname):
        self.sockfd = socket.socket(socket.AF_PACKET, socket.SOCK_RAW)
        self.sockfd.bind((ifname,socket.SOCK_RAW))
        self.src_port = random.randint(49152, 65535)
        self.ifname = ifname
        self.dst_port = 80
        self.src_ip = self._getip()
        self.dst_ip = ""
        self.seq = 0
        self.ack_seq = 0
        self.awnd = 40960 
        self.rtt = 1
        self.state = 0
        self.mss = 40960 
        self.prev = None
        self.gateway_mac = None

    def _getip(self):
       return fcntl.ioctl(self.sockfd.fileno(), \
                               SIOCGIFADDR, struct.pack('256s', self.ifname[:15]))[20:24]

    def _get_gateway_ip(self):
        fh = open("/proc/net/route")
        for line in fh:
            fields = line.strip().split()
            if fields[0] == self.ifname and fields[1] == '00000000':
                return struct.pack("<L", int(fields[2], 16))
        return None

    def _get_hw_addr(self):
        ifname = self.ifname
        info = fcntl.ioctl(self.sockfd.fileno(), SIOCSIFHWADDR, struct.pack('256s', ifname[:15]))
        return info[18:24]

    def probe_gateway_mac(self):
        if self.gateway_mac  != None:
            return self.gateway_mac
        sender_addr = self._get_hw_addr() 
        sender_ip = self._getip()
        target_addr = "\xff\xff\xff\xff\xff\xff" #Boardcast addr
        target_ip = self._get_gateway_ip()
        etherframe = eth.EthernetFrame(target_addr, sender_addr, ETH_P_ARP) 
        arppkt = arp.ARPPacket(sender_addr, sender_ip, target_addr, target_ip)
        verbose_print(arppkt)
        etherframe.payload = arppkt.assemble()
        verbose_print(etherframe)
        self.sockfd.send(etherframe.assemble())
        while True:
            buf = self.sockfd.recvfrom(MAX_BUF_SIZE)
            etherframe.disassemble(buf)
            if etherframe.ether_type  == 1544:
                break
        arppkt.disassemble(etherframe.payload)
        verbose_print(arppkt)
        self.gateway_mac = arppkt.sender_mac
        return arppkt.sender_mac

    def _send(self, resend=0, data="", fin=0, syn=0, rst=0, psh=0, ack=0, urg=0):
        if resend == 0:
            # assemble tcp packet
            tcppkt = tcp.TCPPacket(src_ip=self.src_ip, dst_ip=self.dst_ip, \
                                   src_port=self.src_port, dst_port=self.dst_port, \
                                   payload=data, win=self.awnd, \
                                   seq=self.seq, ack_seq=self.ack_seq, \
                                   fin=fin, syn=syn, rst=rst, psh=psh, ack=ack, urg=urg)
            ip_payload = tcppkt.assemble()
            verbose_print("\n>>>>>>>>>>>> Sending Packet")
            verbose_print(tcppkt)
            # assemble ip packet
            ippkt = ip.IPPacket(self.src_ip, self.dst_ip)
            ippkt.set_payload(ip_payload)
            verbose_print(ippkt)
            # assemble etherframe 
            ether_payload = ippkt.assemble()
            self.prev = ether_payload
            target_mac = self.probe_gateway_mac()
            etherframe = eth.EthernetFrame(target_mac,self._get_hw_addr(), ETH_P_IP)
            etherframe.payload = ether_payload
            verbose_print(etherframe)
            self.sockfd.send(etherframe.assemble())
        else:
            target_mac = self.probe_gateway_mac()
            etherframe = eth.EthernetFrame(target_mac,self._get_hw_addr(), ETH_P_IP)
            etherframe.payload = self.prev
            verbose_print(etherframe)
            self.sockfd.send(etherframe.assemble())

    def _recvpacket(self, byte):
        maxtry = 5
        while maxtry >= 0:
            maxtry -= 1
            in_sockfd, out_sockfd, x_sockfd = select.select([self.sockfd], [], [], 0.1)
            if self.sockfd not in in_sockfd:
                continue
            verbose_print("\n<<<<<<<<<<<<<<<< Receving Packet")
            buf = in_sockfd[0].recvfrom(byte)
            etherframe = eth.EthernetFrame()
            etherframe.disassemble(buf)
            verbose_print(etherframe)
            if etherframe.ether_type  != 8:
                continue
            ippkt = ip.IPPacket(self.src_ip, self.dst_ip)
            ippkt.dissemble(etherframe.payload)
            verbose_print(ippkt)
            if ippkt.protocol != 6:
                continue
            tcppkt = tcp.TCPPacket(src_ip=self.src_ip, dst_ip=self.dst_ip)
            tcppkt.dissemble(ippkt.payload)
            verbose_print(tcppkt)
            if tcppkt.dst_port != self.src_port:
                continue
            return tcppkt
        return None

    def _recv(self, byte):
        tcppkt = self._recvpacket(byte)
        if tcppkt == None:
            return None
        # update sequence number
        if tcppkt.syn:
            self.ack_seq = tcppkt.seq + 1
        elif tcppkt.fin:
            self.ack_seq = tcppkt.seq + 1
        else:
            self.ack_seq += len(tcppkt.payload)
        # update acknowledge number
        self.seq = tcppkt.ack_seq 
        return tcppkt.payload

    def connect(self, (hostname, port)):
        self.dst_ip = socket.inet_aton(socket.gethostbyname(hostname))
        self.dst_port = port

        self.seq = random.randint(math.pow(2,1), math.pow(2, 10))
        self.ack_seq = 0

        self._send(syn=1)
        self._recv(MAX_BUF_SIZE)
        self._send(ack=1)

    def send(self, data):
        self._send(data=data, ack=1)
        self._recv(MAX_BUF_SIZE)

    def recv(self, max_size):
        recv_data = self._recv(max_size)
        if recv_data == None:
            self._send(rst=1)
        else:
            self._send(ack=1)
        return recv_data

    def close(self):
        self._send(fin=1)
        self._recv(MAX_BUF_SIZE)
        self._send(ack=1)
        self.sockfd.close()
