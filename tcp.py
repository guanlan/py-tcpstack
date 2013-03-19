import sys
import socket
import random, math
import fcntl
import struct

class TCPPacket:
    def __init__(self, src_ip="", dst_ip="", src_port=0, dst_port=80, data="",\
                 seq=0, ack_seq=0, offset=0, fin=0, syn=0, \
                 rst=0, psh=0, ack=0, urg=0, win=0, urp=0):
        # u 16 H
        self.src_ip = socket.inet_aton(src_ip)
        self.dst_ip = socket.inet_aton(dst_ip)
        self.src = src_port
        self.dst = dst_port
        # u 32 L
        self.seq = seq
        self.ack_seq = ack_seq
        # u 8 B Default offset is 5 (20 bits)
        self.doff = 5
        self.offset_res = (self.doff <<  4) + 0
        # u 8 B flag
        self.fin = fin
        self.syn = syn
        self.rst = rst
        self.psh = psh
        self.ack = ack
        self.urg = urg
        self.flags = fin + (syn << 1) + (rst << 2) + \
                     (psh << 3) + (ack << 4) + (urg << 5)
        # u 16 H
        self.win = win
        self.csum = 0
        self.urp = urp
        self.payload = data

    def __repr__(self):
        rep = '[*TCP Packet* Source: %s:%d  Dest: %s:%d Sequence Number:%d  Acknowledgement: %d  Flag:%d ' % (socket.inet_ntoa(self.src_ip), self.src, socket.inet_ntoa(self.dst_ip), self.dst, self.seq, self.ack_seq, self.flags)
        if len(self.payload) == 0:
            rep += "\'\'>"
        elif len(self.payload) < 100:
            rep += "%s]" % repr(self.payload)
        else:
            rep += "%s]" % repr(self.payload[:100] + '...')
        return rep

    def _header(self):
        return  struct.pack('!HHLLBBHHH', \
                            self.src, self.dst, self.seq, \
                            self.ack_seq, self.offset_res, \
                            self.flags, self.win, self.csum, \
                            self.urp)

    def _pseudo_header(self):
        placeholder = 0
        tcp_length = len(self._header()) + len(self.payload)
        psh = struct.pack('!4s4sBBH' , \
                          self.src_ip , self.dst_ip , \
                          placeholder , socket.IPPROTO_TCP , \
                          tcp_length);
        psh = psh + self._header() + self.payload;
        return psh

    def _checksum(self, msg):
        s = 0
        # loop taking 2 characters at a time
        for i in range(0, len(msg), 2):
            if i < len(msg) and i + 1 < len(msg):
                w = ord(msg[i]) + (ord(msg[i+1]) << 8 )
            elif i < len(msg) and i + 1 == len(msg):
                w = ord(msg[i])
            s = s + w
        s = (s>>16) + (s & 0xffff);
        s = s + (s >> 16);
        #complement and mask to 4 byte short
        s = ~s & 0xffff
        return s

    def header(self):
        csum = self._checksum(self._pseudo_header())
        return struct.pack('!HHLLBBH' , self.src, self.dst, self.seq, \
               self.ack_seq, self.offset_res, self.flags,  self.win) + \
               struct.pack('H' , csum) + struct.pack('!H' , self.urp)

    def assemble(self):
        return self.header() + self.payload 
    
    def dissemble(self, buf):
        # Parse the initial 20 bits
        self.src, self.dst, \
        seq, ack_seq, \
        self.offset_res, self.flags, \
        self.win, self.csum, self.urp = struct.unpack('!HHLLBBHHH', buf[:20])

        self.seq = long(seq)
        self.ack_seq = long(ack_seq)

        self.fin = self.flags & 0x01
        self.syn = self.flags & 0x02
        self.rst = self.flags & 0x04
        self.psh = self.flags & 0x08
        self.ack = self.flags & 0x10
        self.urg = self.flags & 0x20

        # Parse the Option bits
        offset=self.offset_res >> 4
        if (offset > 5):
            i = 5
            while i < offset:
                op_kind, = struct.unpack('!B', buf[i*4:i*4+1])
                if op_kind == 0:
                    break
                if op_kind == 2:
                    op_len, = struct.unpack('!B', buf[i*4+1:i*4+2])
                    op_data, = struct.unpack('!H', buf[i*4+2:i*4+4])
                    self.mss = op_data
                i += 1
        # Parse the data bits

        self.payload=buf[offset*4:]
        return self
