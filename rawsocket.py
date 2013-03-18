# choosing a valid local port, 
# managing sequence and acknowledgement numbers, 
# performing connection setup and tear-down, 
# and calculating the offset and checksum in each packet.

# Your code may manage the advertised window in any way you want. 
# As with IP, your code must be defensive: check to ensure that all 
# incoming packets have valid checksums and in-order sequence numbers. 
# If your program does not receive any data from the remote server 
# within a few minutes, your program can assume that 
# the connection has failed or timed-out.

# The endian is CCIS is little endian

import sys
import socket
import random, math
import fcntl
import struct
import time
import tcp
import ip

# This is the middle layer of RawSocket
class RawSocket:
    def __init__(self):
        self.socket = RawTCPSocket("wlan0")
        #self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    def connect(self, (hostname, port)):
        self.socket.connect((hostname, port))

    def close(self):
        self.socket.close()

    def send(self, data):
        self.socket.send(data)

    def recv(self, length):
        return self.socket.recv(length) 


# This is the TCP layer RawSocket
class RawTCPSocket:
    def __init__(self, ifname):
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
        self.src_port = random.randint(49152, 65535)
        self.src_ip = self._getip(ifname)
        self.dst_ip = ""
        self.dst_port = 80
        self.seq = 0
        self.ack_seq = 0
        self.awnd = 40960
        self.rtt = 1
        self.state = 0
        self.mss = 40960

    def _getip(self, ifname):
       return socket.inet_ntoa(fcntl.ioctl(
                               self.socket.fileno(),
                               0x8915,  # SIOCGIFADDR
                               struct.pack('256s', ifname[:15])
                               )[20:24])

    def _showbit(self, bits):
        print ":".join("{0:x}".format(ord(c)) for c in bits)

    def _send(self, data="", fin=0, syn=0, rst=0, psh=0, ack=0, urg=0):
        if ack == 0:
            self.ack_seq=0
        tcphdr = tcp.TCPHeader(src_ip=self.src_ip, dst_ip=self.dst_ip, \
                        src_port=self.src_port, dst_port=self.dst_port, data=data, \
                        win=self.awnd, seq=self.seq, ack_seq=self.ack_seq, \
                        fin=fin, syn=syn, rst=rst, psh=psh, ack=ack, urg=urg)

        packet = tcphdr.assemble(data)
        self.socket.sendto(packet, (self. dst_ip, self.src_port))
        self.seq += len(data)

    def _recv(self, byte):
        # Parse the Connection and Shutdown
        #print "recv"
        #time.sleep(0.01)
        buf = self.socket.recv(byte)
        tcphdr = tcp.TCPHeader(src_ip=self.src_ip, dst_ip=self.dst_ip)
        recv_packet = tcphdr.dissemble(buf[20:])
        #recv_packet = self._unpack_tcp(buf[20:])

        count= 3
        while not recv_packet.dst == self.src_port:
            #print recv_packet.dst, self.src_port
            tcphdr = tcp.TCPHeader(src_ip=self.src_ip, dst_ip=self.dst_ip)
            recv_packet = tcphdr.dissemble(buf[20:])
            count -= 1
            if count == 0:
                sys.exit(1)

        self.ack_seq = recv_packet.seq + 1
        self.seq = recv_packet.ack_seq 

        return recv_packet
   
    def _recv_data(self, byte):
        # Parse the Received Data
        recv_size = 0
        recv_data = ""
        #time.sleep(0.01)
        while recv_size == 0:
            buf = self.socket.recv(byte)
            tcphdr = tcp.TCPHeader(src_ip=self.src_ip, dst_ip=self.dst_ip)
            recv_pack = tcphdr.dissemble(buf[20:])
            #recv_pack = self._unpack_tcp(buf[20:])
            count = 5
            while not recv_pack.dst == self.src_port:
                #print recv_pack.dst, self.src_port
                recv_pack = tcphdr.dissemble(buf[20:])
                self._send(ack=1)
                count -= 1
                if count == 0:
                    sys.exit(1)
            recv_size += len(recv_pack.data)
            recv_data += recv_pack.data
            #print recv_pack.data

        self.ack_seq += recv_size

        return recv_data

    def connect(self, (hostname, port)):
        self.dst_ip = socket.gethostbyname(hostname)
        self.dst_port = port
        self.seq = random.randint(math.pow(2,1), math.pow(2, 10))
        self.ack_seq = 0

        self._send(data="", syn=1)
        recv_packet = self._recv(4096)
        self._send(data="", ack=1)

    def send(self, data):
        self._send(data=data, ack=1)

    def recv(self, data):
        recv_data = self._recv_data(4096)
        self._send(data="", ack=1)
        return recv_data

    def close(self):
        self._send(data="", fin=1)
        recv_packet = self._recv(4096)
        self._send(data="", ack=1)
        self.socket.close()
        
