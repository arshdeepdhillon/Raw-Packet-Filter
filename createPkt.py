
from scapy.all import *

def makePacket(usrProto,srcIP,srcPrt,dstIP,dstPrt):
    proto = usrProto.lower()
    src_ip = srcIP
    src_port = int(srcPrt)
    dst_ip = dstIP
    dst_port = int(dstPrt)
    # ip_flags = "PA"
    # seq_n = RandShort()
    # datagram = '#(`_ `)#'
    # ack_n = seq_n + len(datagram)
    # pkt = ip/UDP(sport=src_port, dport=dst_port, flags='PA', seq=seq_n, ack=ack_n)/datagram
    ip = IP(src=src_ip, dst=dst_ip)
    if proto == "udp":
        pkt = ip/UDP(sport=src_port, dport=dst_port)
    elif proto == "tcp":
        pkt = ip/TCP(sport=src_port, dport=dst_port)
    else:
        pkt = ip/ICMP()
    return(raw(IP(raw(pkt))))  # Build the packet

def main(args):
    proto, srcIP, srcPrt, dstIP, dstPrt, outF = args
    open(outF, 'wb').write(makePacket(proto, srcIP, srcPrt, dstIP, dstPrt))

if __name__ == '__main__':
    if len(sys.argv) != 7:
        print("\nEnter: [filename] [tcp|udp|other] [source IP] [source Port] [dest IP] [dest Port] [outputFileName.dat]")
        print("\teg:    ./createPkt.py tcp 100.100.100.100 10000 10.10.10.10 10 pkt1.dat\n")
        sys.exit()
    main(sys.argv[1:])
    sys.exit()
