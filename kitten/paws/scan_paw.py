from multiprocessing.dummy import Pool
import threading
import socket
from time import sleep
from scapy.layers.dot11 import Dot11, Dot11Beacon, Dot11Elt, sniff, Packet

from objects.network import Network

from paws.iface_paw import IfacePaw
from paws.util_paw import UtilPaw

class ScanPaw(IfacePaw):

    _util_paw = None

    # port scanning
    _target = None
    _maxprocesses = None
    _maxthreads = None

    # scanning for networks
    __networks_found = {}

    def __init__(self, options, util_paw: UtilPaw) -> None:
        self._util_paw = util_paw
        super().__init__(options, self._util_paw)

    def set_target(self, target: str) -> None:
        try:
            self._target = socket.gethostbyname(target)
        except socket.gaierror:
            self._util_paw.print_text('Hostname could not be resolved.', color='red')
            exit()

    def set_maxthreads(self, maxthreads: int) -> None:
        self._maxthreads = maxthreads

    def set_maxprocesses(self, maxprocesses: int) -> None:
        self._maxprocesses = maxprocesses
    
    def set_interface(self, interface: str) -> None:
        return super().set_interface(interface)

    def set_automode(self, automode: bool) -> None:
        return super().set_automode(automode)

    def is_open_port(self, port: int) -> bool:

        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        socket.setdefaulttimeout(1)
        
        result = s.connect_ex((self._target, port))
        if result == 0:
            self._util_paw.print_text(f'Found open port: ', end='', verbose=True)
            self._util_paw.print_text(port, color='cyan', verbose=True)

            return port
        
        s.close()
        return None


    def get_services(self, ports: list) -> dict:
        services = dict.fromkeys(ports, 'unknown')
        for port in ports:
            try:
                services[port] = socket.getservbyport(port, 'tcp')
            except socket.error:
                pass
        
        return services

    def get_open_ports_multiprocessing(self) -> list:
        try:
            with Pool(self._maxprocesses) as p:
                return list(filter(None, p.map(self.is_open_port, self._util_paw.get_most_common_ports())))

        except socket.error:
            self._util_paw.print_text('Server does not respond.', color='red', attrs=['bold'])
            exit()

    def get_open_ports_threading(self) -> list:

        open_ports = []
        most_common_ports = self._util_paw.get_most_common_ports()

        try:
            def append_port_if_open(port: int) -> None:
                if self.is_open_port(port) != None: open_ports.append(port)

            while len(most_common_ports) != 0:
                port = most_common_ports[0]
                if threading.active_count() >= self._maxthreads:
                    sleep(0.1)
                else:
                    t = threading.Thread(target=append_port_if_open, args=[port])
                    t.start()
                    most_common_ports.pop(0)

            while threading.active_count() != 1:
                sleep(1)

        except socket.error:
            self._util_paw.print_text('Server does not respond.', color='red', attrs=['bold'])
            exit()

        return open_ports

    def __handle_packet(self, packet: Packet) -> None:
        if packet.haslayer(Dot11Beacon):
            
            bssid = packet[Dot11].addr2
            
            try:
                ssid = packet[Dot11Elt].info.decode()
            except UnicodeDecodeError:
                ssid = packet[Dot11Elt].info
            
            try:
                dbm_signal = packet.dBm_AntSignal
            except:
                dbm_signal = 'N/A'
            
            stats = packet[Dot11Beacon].network_stats()
            
            channel = stats.get('channel')
            
            crypto = stats.get('crypto')

            if bssid not in self.__networks_found.keys():
                self.__networks_found[bssid] = Network(
                    bssid,
                    ssid,
                    dbm_signal,
                    channel,
                    crypto,
                )
                
                self._util_paw.print_scanned_network(self.__networks_found[bssid])

    def scan_for_wireless_networks(self) -> None:
        try:
            sniff(prn=self.__handle_packet, iface=self.get_selected_interface())

        except KeyboardInterrupt:

            self.switch_interface_mode(self.__prev_mode)
            return self.__networks_found
        
        except PermissionError:
            self.switch_interface_mode(self.__prev_mode)
            self._util_paw.print_permission_error()
            exit()