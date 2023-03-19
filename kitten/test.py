from scapy.config import conf
from scapy.sendrecv import sniff, sendp
from scapy.all import *

conf.use_pcap = True

# sniff(iface='en0', prn=print, monitor=True)

sendp(RadioTap()/
          Dot11(addr1="ff:ff:ff:ff:ff:ff",
                addr2="00:01:02:03:04:05",
                addr3="00:01:02:03:04:05")/
          Dot11Beacon(cap="ESS", timestamp=1)/
          Dot11Elt(ID="SSID", info='supercooleswlan')/
          Dot11EltRates(rates=[130, 132, 11, 22])/
          Dot11Elt(ID="DSset", info="\x03")/
          Dot11Elt(ID="TIM", info="\x00\x01\x00\x00"),
          iface="en0", loop=1)