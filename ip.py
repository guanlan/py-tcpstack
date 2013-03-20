import sys
import socket
import random, math
import fcntl
import struct
import utils

class IPPacket:
    def __init__(self, src_ip='127.0.0.1', dst_ip='127.0.0.1'):
        self.src_ip = src_ip
        self.dst_ip = dst_ip
        self.ver = 4
        self.ihl = 5
        self.ver_ihl = (self.ver << 4) + self.ihl
        self.tos = 0
        self.tot_len = 20
        self.id = 0
        self.frag_off = 0
        self.ttl = 64
        self.protocol = socket.IPPROTO_TCP
        self.cksum = 0
        self.saddr = socket.inet_aton(self.src_ip)
        self.daddr = socket.inet_aton(self.dst_ip)
        self.payload = ""

    def __repr__(self):
        rep = "[*IP Packet* ver:%d id=%d proto=%d src=%s dst=%s datalen=%d]" % \
               (self.ver, self.id, self.protocol, socket.inet_ntoa(self.saddr), socket.inet_ntoa(self.daddr),
                self.tot_len)
        return rep  

    def _header(self):
        return  struct.pack('!BBHHHBB', self.ver_ihl, self.tos, \
                           self.tot_len, self.id, self.frag_off, \
                           self.ttl, self.protocol)
    def set_payload(self, payload):
        self.payload = payload
        self.tot_len  = 20 + len(payload)


    def assemble(self):
        header = self._header() 
        self.cksum = utils.checksum(header + '\000\000' + self.saddr +
                                  self.daddr)
        packet = [self._header(), 
                    struct.pack('H', self.cksum), 
                    self.saddr, self.daddr, 
                    self.payload]
        return ''.join(packet)

    def dissemble(self, buf):
        res = struct.unpack('!BBHHHBBH4s4s', buf[:20])
        self.ver_ihl = res[0]
        self.tos = res[1]
        self.tot_len = res[2]
        self.id = res[3]
        self.frag_off = res[4]
        self.ttl = res[5]
        self.protocol = res[6]
        self.csum = res[7]
        self.saddr = res[8]
        self.daddr = res[9]
        self.payload = buf[20:]

