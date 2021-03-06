import sys
import socket
import random
import fcntl
import struct
import utils

class IPPacket:
    """ IP Packet provides the IP header and payload"""
    def __init__(self, src_ip='', dst_ip=''):
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
        self.src_ip = src_ip
        self.dst_ip = dst_ip
        self.payload = ""

    def __repr__(self):
        rep = "[*IP Packet* ver:%d id=%d proto=%d src=%s dst=%s datalen=%d]" % \
               (self.ver, self.id, self.protocol, socket.inet_ntoa(self.src_ip), \
                socket.inet_ntoa(self.dst_ip), self.tot_len)
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
        self.cksum = utils.checksum(header + '\000\000' + self.src_ip +
                                  self.dst_ip)

        packet = [self._header(), 
                    struct.pack('H', self.cksum), 
                    self.src_ip, self.dst_ip, 
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
        self.src_ip = res[8]
        self.dst_ip = res[9]
        self.payload = buf[20:]

    def check_csum(self):
        acsum = socket.htons(utils.checksum(self._header() + '\000\000' + self.src_ip + self.dst_ip))
        return (acsum == self.csum)
        

