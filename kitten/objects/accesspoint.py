from scapy.layers.dot11 import Dot11, Dot11Beacon, RadioTap, Dot11Elt, sendp
from scapy.volatile import RandMAC

from objects.interfaces import Interface
from objects.network import Network

class AccessPoint(Network):

    def __init__(
        self,
        ssid: str,
        bssid: str = str(RandMAC()),
        interface: Interface,
    ) -> None:

        Network.__init__(
            self,
            bssid = bssid,
            ssid = ssid,
        )

        self._interface = interface

        # 802.11 frame
        self._dot11 = Dot11(
            type=0,
            subtype=8,
            addr1='ff:ff:ff:ff:ff:ff',
            addr2=mac_address,
            addr3=mac_address,
        )
        # beacon layer
        # ESS+privacy to appear as secured on some devices
        self._beacon = Dot11Beacon(cap='ESS+privacy')
        self._essid = Dot11Elt(ID='SSID', info=ssid, len=len(ssid))
        # stack all the layers and add a RadioTap
        self._frame = RadioTap()/self._dot11/self._beacon/self._essid

    def get_interface(self) -> Interface:
        return self._interface
    
    def set_interface(self, interface: Interface) -> None:
        self._interface = interface

    def appear(
        self,
        interval: float = .1,
    ) -> None:

        sendp(
            x = self._frame,
            iface = self._interface.get_name(),
            inter = interval,
            loop = True,
            verbose = False,
        )