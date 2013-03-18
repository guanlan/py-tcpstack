import socket
from struct import *
class EthernetFrame(object):
    def __init__(self):
        self.eth_length = 14

    def __repr__(self):
        rep = "<Eth Dest MAC: %s  Src MAC: %s Protocol:%d>" % (self.eth_addr_repr(self.des_mac),self.eth_addr_repr(self.src_mac), self.ether_type)
        return rep

    def disassemble(self, packet):
        packet = packet[0]
        #parse ethernet header
        eth_header = packet[:self.eth_length]
        eth = unpack('!6s6sH' , eth_header)
        self.des_mac = eth[0]
        self.src_mac = eth[1] 
        self.ether_type = socket.ntohs(eth[2])
        self.payload = packet[self.eth_length:-1]

    def assemble(self, payload):
        packet = pack('!6s6sH', self.des_mac, self.src_mac, self.ether_type)
        packet += payload
        return packet

    def eth_addr_repr(self, a) :
        b = "%.2x:%.2x:%.2x:%.2x:%.2x:%.2x" % (ord(a[0]) , ord(a[1]) , ord(a[2]), ord(a[3]), ord(a[4]) , ord(a[5]))
        return b

