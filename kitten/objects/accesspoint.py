from scapy.layers.dot11 import Dot11, Dot11Beacon, RadioTap, Dot11Elt, sendp

from objects.interface import Interface

class AccessPoint:

    _ssid = ''
    _mac_address = ''
    _interface = None
    _interval = 0.1
    
    __dot11 = None
    __essid = None
    __beacon = None
    __frame = None

    def __init__(
        self,
        ssid: str,
        mac_address: str,
        interface: Interface,
        interval: float=.1,
    ) -> None:
        self._interface = interface
        self._interval = interval

        # 802.11 frame
        self.__dot11 = Dot11(
            type=0,
            subtype=8,
            addr1='ff:ff:ff:ff:ff:ff',
            addr2=mac_address,
            addr3=mac_address,
        )
        # beacon layer
        # ESS+privacy to appear as secured on some devices
        self.__beacon = Dot11Beacon(cap='ESS+privacy')
        self.__essid = Dot11Elt(ID='SSID', info=ssid, len=len(ssid))
        # stack all the layers and add a RadioTap
        self.__frame = RadioTap()/self.__dot11/self.__beacon/self.__essid

    def appear(self) -> None:
        sendp(
            x=self.__frame,
            iface=self._interface.get_name(),
            inter=self._interval,
            loop=True,
            verbose=False,
        )