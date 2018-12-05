import sys
import os
from scapy.all import * #to setup IP packet
import re

########Constants############
UNSPECIFIED = "unspecified"
TCP = 6
UDP = 17
MIN_IP = 0
MAX_IP = 255
MIN_PORT = 0
MAX_PORT = 65535
#############################

"""
Description:
    To compare two ip addresses

Input:
    ruleIP: contains an ip address of tpye string
    dataPacketIP: contains an ip address of tpye string

Return:
    True : if both ip addresses match or ruleIP contains a wildercard at certain
            position
    False: otherwise, ip addresses do not match
"""
def addrMatch(ruleIP, dataPacketIP):
    dataPacket_IPL = dataPacketIP.split('.')
    ruleIPL = ruleIP.split('.')

    for i in range(0, min(len(ruleIPL), len(dataPacket_IPL))):
        if ruleIPL[i] != dataPacket_IPL[i]:
            return(ruleIPL[i] == '*')
    return(True)

"""
Description:
    To compare two ports

Input:
    rulePrt: contains port of tpye int
    dataPacketPrt: contains port of tpye int

Return:
    True : if both ports match or rulePrt contains a wildercard
    False: otherwise ports do not match
"""
def portMatch(rulePrt, dataPacketPrt):
    return(True if rulePrt == '*' else int(rulePrt) == dataPacketPrt)


"""
Description:
    To compare two ports

Input:
    rulePrt: contains port of tpye int
    dataPacketPrt: contains port of tpye int

Return:
    allow: if the rules specify that the packet should be allowed or
    deny: if the rules specify that the packet should be denied  or
    unspecified: if there is no rule that applies to the packet or if the packet’s
                 IP header indicates that it is neither a TCP nor a UDP packet.
                 This means that the program processed all the rules and found
                 none that applied.
"""
def filterPacket(rulesF, packetF):
    if not os.path.exists(rulesF):
        print(rulesf + " does not exist")
        sys.exit()
    if not os.path.exists(packetF):
        print(packetf + " does not exist")
        sys.exit()

    with open(packetF,'rb') as packetF:
        dataPacket = IP(packetF.read()) # setup the filtered packet using scapy
        # print(dataPacket.show()) # to view fields of the data packet

    with open(rulesF,'r') as rulesF:
        for line in rulesF.read().splitlines():
            if line.strip():
                ruleDecision, rulePktType, ruleSrcIP, ruleSrcPrt, temp, ruleDestIP, ruleDestPrt = re.split(' |:', line.strip().lower())

                if (dataPacket.proto != TCP and dataPacket.proto != UDP) or not(MIN_PORT <= dataPacket.dport <= MAX_PORT) or not(MIN_PORT <= dataPacket.sport <= MAX_PORT):
                    return(UNSPECIFIED)
                if portMatch(ruleSrcPrt,dataPacket.sport) and portMatch(ruleDestPrt, dataPacket.dport):
                    if rulePktType == "udp":
                        rulePktType = UDP
                    elif rulePktType == "tcp":
                        rulePktType = TCP

                    if rulePktType == dataPacket.proto and addrMatch(ruleSrcIP,dataPacket.src) and addrMatch(ruleDestIP,dataPacket.dst):
                        return(ruleDecision)
    return(UNSPECIFIED)

"""
Description:
    This program monitors packets and decides whether to allow or deny them by
    taking two files from command line rules.txt and packet.txt.

    rules.txt:
        The rules file lists the rules of the packet filter.
        The rules file consists of a set of rules, each written on one line.
        The packet filter checks the packet data against the rules from the first
        to the last and the first rule that applies for the packet is the decision.

        Format of rules: [allow|deny] [tcp|udp] srcip:srcport -> dstip:dstport.
            Eg rule: allow udp 10.0.0.1:24 -> 10.0.0.5:52
                This means that if any UDP packet with source of 10.0.0.1 on port
                24 being sent to 10.0.0.5 on port 52 should be allowed to pass the
                filter.

        Wildcards are allowed, however improper wildercards are not allowed
        (10.0.*.5 and 10*). That means a wildcard in the IP will appear after a
        dot and be followed by a colon.
            Eg rule: 10.0.*:* -> 192.168.0.1:80
                This implies that this rule applies to all TCP connections from IP
                10.0.X.Y on port Z (for all valid X, Y, Z).

    packet.txt:
        The packet file is the raw packet data that is being processed by the
        filter. The packet file is a binary file that consists of the IP header,
        the TCP or UDP header (depending on the type of packet) and the payload
        of the packet. The packet file stores the data for a raw packet except for
        the link layer header and footer.

Input:
    From command line: rules.txt and packet.txt

Output:
    allow: if the rules specify that the packet should be allowed or
    deny: if the rules specify that the packet should be denied  or
    unspecified: if there is no rule that applies to the packet or if the packet’s
                 IP header indicates that it is neither a TCP nor a UDP packet.
                 This means that the program processed all the rules and found
                 none that applied.
"""
def main(args):
    rulesfName, packetsfName = args
    print(filterPacket(rulesfName, packetsfName))

if __name__ == "__main__":
    if len(sys.argv) != 3 or not sys.argv[1] or not sys.argv[2]:
        sys.exit("Enter: pfilter [rules filename] [packet filename]")
    main(sys.argv[1:])
    sys.exit()
