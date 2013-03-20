import socket
from struct import unpack, pack
class ARPPacket():
    def __init__(self, sender_mac = '',sender_ip = '', 
            target_mac="\xff\xff\xff\xff\xff\xff", #default boardcast
            target_ip=''):
        self.hardware_type = 0x001 #Ethernet Type
        self.protocal = 0x0800 #IP Type
        self.hardware_size = 0x006 #Ethernet Size
        self.protocal_size = 0x004 #IP Size
        self.opcode = 1
        self.sender_mac= sender_mac
        self.sender_ip = sender_ip 
        self.target_mac= target_mac
        self.target_ip = target_ip 

    def __repr__(self):
        rep = "[*ARP Packet* opcode:%d Src MAC:%s Src IP: %s Tgt Mac:%s Tgt IP:%s]" % (self, opcode, self.eth_addr_repr(self.sender_mac), self.sender_ip, self.eth_addr_repr(self.target_mac), self.target_ip)
        return rep

    def disassemble(self, payload):
        #parse ethernet header
        print "len:"
        print len(payload)
        arp = unpack('!HHBBH6s4s6s3s' , payload[:-1])
        self.opcode = arp[4]
        self.sender_mac= arp[5] 
        self.sender_ip = arp[6] 
        self.target_mac= arp[7] 
        self.target_ip = arp[8] 

    def assemble(self):
        payload = [
            pack('!HHBB', self.hardware_type, self.protocal, self.hardware_size, self.protocal_size),
            pack('!H', self.opcode),
            self.sender_mac, 
            self.sender_ip, 
            self.target_mac,
            self.target_ip
        ]
        packet = ''.join(payload)
        return packet

    def eth_addr_repr(self, a) :
        b = "%.2x:%.2x:%.2x:%.2x:%.2x:%.2x" % (ord(a[0]) , ord(a[1]) , ord(a[2]), ord(a[3]), ord(a[4]) , ord(a[5]))
        return b

    def _addr_to_num(self, addr):
        res = pack('!4B', *[int(x) for x in addr.split('.')])

if __name__ == "__main__":
    s = socket.socket( socket.AF_PACKET , socket.SOCK_RAW)
    ifname = 'wlan0'
    target_ipaddr = '192.168.2.1'
    info = fcntl.ioctl(s.fileno(), 0x8927,  pack('256s', ifname[:15]))
    sender_addr = info[18:24]
    dst_addr = "\xff\xff\xff\xff\xff\xff"
    etherframe = EthernetFrame(ifname,dst_addr, sender_addr, 0x806) 
    print etherframe
    daddr = pack('!4B', *[int(x) for x in target_ipaddr.split('.')])
    saddr = fcntl.ioctl(s.fileno(),0x8915,  # SIOCGIFADDR
                              pack('256s', ifname[:15]))[20:24] 
    frame = [
    ### ARP ###
        pack('!HHBB', 0x0001, 0x0800, 0x0006, 0x0004),
        pack('!H', 0x0001),
        sender_addr, 
        saddr, 
        pack('!6B', *(0,) * 6),
        daddr
    ]
    etherframe.payload = ''.join(frame)
    s.bind(("wlan0", socket.SOCK_RAW))
    s.send(etherframe.assemble())
