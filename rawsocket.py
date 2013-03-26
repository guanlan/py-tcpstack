import sys
import socket
import random
import fcntl
import struct
import tcp
import ip
import eth
import os
import arp
import select

VERBOSE = False
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
    """ RawSocket is the bridge class which provides the same interface as socket.socket"""
    def __init__(self):
        self.sockfd = RawSocketConnection("wlan0")

    def connect(self, (hostname, port)):
        self.sockfd.connect((hostname, port))

    def close(self):
        self.sockfd.close()

    def send(self, data):
        self.sockfd.send(data)

    def recv(self, length):
        return self.sockfd.recv(length) 

class RawSocketConnection:
    """ RawSocketConnection provides raw socket connection to a network interface """
    def __init__(self, ifname):
        self.sockfd = socket.socket(socket.AF_PACKET, socket.SOCK_RAW)
        self.sockfd.bind((ifname,socket.SOCK_RAW))
        self.ifname = ifname
        self.src_port = random.randint(49152, 65535)
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
        try:
            ip = fcntl.ioctl(self.sockfd.fileno(), \
                              SIOCGIFADDR, struct.pack('256s', self.ifname[:15]))[20:24]
            return ip
        except IOError:
            print "Ethernet : Couldn't get IP on %s" % self.ifname
            sys.exit(1)

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
        if self.gateway_mac != None:
            return self.gateway_mac
        sender_addr = self._get_hw_addr() 
        sender_ip = self._getip()
        target_addr = "\xff\xff\xff\xff\xff\xff" #Boardcast address
        target_ip = self._get_gateway_ip()
        if target_ip  == None:
            print "Ethernet : Can't get gateway IP!"
            sys.exit(1)
        ether_frame = eth.EthernetFrame(target_addr, sender_addr, ETH_P_ARP) 
        arppkt = arp.ARPPacket(sender_addr, sender_ip, target_addr, target_ip)
        verbose_print(arppkt)
        ether_frame.payload = arppkt.assemble()
        verbose_print(ether_frame)
        self.sockfd.send(ether_frame.assemble())
        while True:
            buf = self.sockfd.recvfrom(MAX_BUF_SIZE)
            ether_frame.disassemble(buf)
            if ether_frame.ether_type  == 1544:
                break
        arppkt.disassemble(ether_frame.payload)
        verbose_print(arppkt)
        self.gateway_mac = arppkt.sender_mac
        return arppkt.sender_mac

    def _send(self, resend=0, data="", fin=0, syn=0, rst=0, psh=0, ack=0, urg=0):
        if resend == 0:
            # assemble tcp packet
            tcp_pkt = tcp.TCPPacket(src_ip=self.src_ip, dst_ip=self.dst_ip, \
                                   src_port=self.src_port, dst_port=self.dst_port, \
                                   payload=data, win=self.awnd, \
                                   seq=self.seq, ack_seq=self.ack_seq, \
                                   fin=fin, syn=syn, rst=rst, psh=psh, ack=ack, urg=urg)
            ip_payload = tcp_pkt.assemble()
            verbose_print("\n>>>>>>>>>>>> Sending Packet")
            verbose_print(tcp_pkt)
            # assemble ip packet
            ip_pkt = ip.IPPacket(self.src_ip, self.dst_ip)
            ip_pkt.set_payload(ip_payload)
            verbose_print(ip_pkt)
            # assemble ether_frame 
            ether_payload = ip_pkt.assemble()
            self.prev = ether_payload
            target_mac = self.probe_gateway_mac()
            ether_frame = eth.EthernetFrame(target_mac,self._get_hw_addr(), ETH_P_IP)
            ether_frame.payload = ether_payload
            verbose_print(ether_frame)
            # send data
            self.sockfd.send(ether_frame.assemble())
        else:
            # resend the previous ethernet frame
            target_mac = self.probe_gateway_mac()
            ether_frame = eth.EthernetFrame(target_mac,self._get_hw_addr(), ETH_P_IP)
            ether_frame.payload = self.prev
            verbose_print(ether_frame)
            self.sockfd.send(ether_frame.assemble())
    
    def _parse_packet(self, byte):
        """ Parse the received packet before actually receive the correct packet """
        maxtry = 10
        timeout = 1
        while maxtry >= 0:
            maxtry -= 1
            in_sockfd, out_sockfd, x_sockfd = select.select([self.sockfd], [], [], timeout)
            # No packet received for the given time
            if self.sockfd not in in_sockfd:
                continue
            verbose_print("\n<<<<<<<<<<<<<<<< Receving Packet")
            buf = in_sockfd[0].recvfrom(byte)
            ether_frame = eth.EthernetFrame()
            ether_frame.disassemble(buf)
            verbose_print(ether_frame)
            # Ethernet frame is not hold IP Packet
            if ether_frame.ether_type  != 8:
                continue
            ip_pkt = ip.IPPacket(self.src_ip, self.dst_ip)
            ip_pkt.dissemble(ether_frame.payload)
            verbose_print(ip_pkt)
            # IP header is not hold TCP Packet or the checksum is incorrect
            if ip_pkt.protocol != 6 or ip_pkt.check_csum() == False or \
               socket.inet_ntoa(ip_pkt.src_ip) != socket.inet_ntoa(self.dst_ip) or \
               socket.inet_ntoa(ip_pkt.dst_ip) != socket.inet_ntoa(self.src_ip):
                continue
            tcp_pkt = tcp.TCPPacket(src_ip=self.src_ip, dst_ip=self.dst_ip)
            tcp_pkt.dissemble(ip_pkt.payload)
            verbose_print(tcp_pkt)
            # TCP Packet is not forward to my port
            if tcp_pkt.dst_port != self.src_port or tcp_pkt.src_port != self.dst_port:
                continue
            if tcp_pkt.rst:
                self._send(rst=1)
                sys.exit("TCP Error: RST received")
            # duplicate ack
            if tcp_pkt.flags == 0x10 and tcp_pkt.ack_seq == self.seq and len(tcp_pkt.payload) == 0:
                self._send(rst=1)
                sys.exit("TCP Error: Duplicate Acks received")
            return tcp_pkt
        return None

    def _recv(self, byte):
        """ Receive TCP packet and return the payload """
        maxtry = 3
        tcp_pkt = self._parse_packet(byte)
        # resend the packet for 3 times 
        while tcp_pkt == None and maxtry > 0:
            self._send(resend=1)
            tcp_pkt = self._parse_packet(byte)
            maxtry -= 1
        # still no data after 3 times retransmission, return nothing
        if tcp_pkt == None:
            return -1
        # update sequence number and acknowledge number
        if tcp_pkt.syn or tcp_pkt.fin:
            self.ack_seq = tcp_pkt.seq + 1
            self.seq = tcp_pkt.ack_seq 
        else:
            # eliminate illegal payload
            if not tcp_pkt.payload == '\x00\x00\x00\x00\x00\x00':
                self.ack_seq += len(tcp_pkt.payload)
                self.seq = tcp_pkt.ack_seq 
        return tcp_pkt.payload

    def connect(self, (hostname, port)):
        """ connect to the given hostname and port """
        self.dst_ip = socket.inet_aton(socket.gethostbyname(hostname))
        self.dst_port = port

        self.seq = random.randint(1, 65535)
        self.ack_seq = 0
        self._send(syn=1)
        payload = self._recv(MAX_BUF_SIZE)
        # if failed to receive ack, terminate transmission
        if payload == -1:
            self._send(rst=1)
            sys.exit("TCP Error: connection buildup failed")
        self._send(ack=1)

    def send(self, data):
        """ send packet and receive the acknowledgement from server """
        self._send(data=data, ack=1)
        self._recv(MAX_BUF_SIZE)

    def recv(self, max_size):
        """ Receive data from server """
        recv_data = self._recv(max_size)
        # if failed to receive ack, terminate transmission
        if recv_data == -1:
            self._send(rst=1)
            sys.exit("TCP Error: data transmission terminates")
        else:
            self._send(ack=1)
        return recv_data

    def close(self):
        """ Close connection """
        self._send(fin=1, ack=1)
        payload = self._recv(MAX_BUF_SIZE)
        # if failed to receive ack, terminate transmission
        if payload == -1:
            self._send(rst=1)
            sys.exit("TCP Error: connection shutdown failed")
        self._send(ack=1)
        self.sockfd.close()
