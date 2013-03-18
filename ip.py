import sys
import socket
import random, math
import fcntl
import struct

class IPHeader:
    def __init__(self, src_ip, dst_ip, data=""):
        self.src_ip = src_ip
        self.dst_ip = dst_ip
        self.ver = 4
        self.ihl = 5
        self.ver_ihl = (self.ver << 4) + self.ihl
        self.tos = 0
        self.tot_len = 0
        self.id = 0
        self.frag_off = 0
        self.ttl = 64
        self.protocol = socket.IPPROTO_TCP
        self.csum = 0
        self.saddr = socket.inet_aton(self.src_ip)
        self.daddr = socket.inet_aton(self.dst_ip)

    def _header(self):
        return  struct.pack('!BBHHHBBH4s4s', self.ver_ihl, self.tos, \
                           self.tot_len, self.id, self.frag_off, \
                           self.ttl, self.protocol, self.csum, \
                           self.saddr, self.daddr)


