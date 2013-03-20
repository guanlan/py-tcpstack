import socket
from struct import *
class EthernetFrame():
    def __init__(self, ifname = 'eth0', des_mac='', src_mac='', ether_type = 4, payload = ''):
        self.eth_length = 14
        self.ifname = ifname
        self.des_mac = des_mac
        self.src_mac = src_mac
        self.ether_type = ether_type
        self.payload = payload 

    def __repr__(self):
        rep = "<*Eth Frame* Dest MAC: %s  Src MAC: %s Protocol:%d>" % (self.eth_addr_repr(self.des_mac),self.eth_addr_repr(self.src_mac), self.ether_type)
        return rep

    def disassemble(self, packet):
        packet = packet[0]
        #parse ethernet header
        eth_header = packet[:self.eth_length]
        eth = unpack('!6s6sH' , eth_header)
        self.des_mac = eth[0]
        self.src_mac = eth[1] 
        self.ether_type = socket.ntohs(eth[2])
        self.payload = packet[self.eth_length:]

    def assemble(self):
        packet = pack('!6s6sH', self.des_mac, self.src_mac, self.ether_type)
        packet += self.payload
        return packet

    def eth_addr_repr(self, a) :
        b = "%.2x:%.2x:%.2x:%.2x:%.2x:%.2x" % (ord(a[0]) , ord(a[1]) , ord(a[2]), ord(a[3]), ord(a[4]) , ord(a[5]))
        return b

