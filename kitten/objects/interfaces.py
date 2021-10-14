import subprocess
from typing import Dict, List, Literal
from objects.network import Network
from scapy.layers.dot11 import sniff, Dot11, Packet, Dot11Elt, Dot11Beacon

Mode = Literal['managed', 'monitor']

class Interface:

    def __init__(self, name: str, mode: Mode) -> None:
        self._name = name
        self._mode = mode
        self._prev_mode = mode
        self.__scanned_networks: Dict[str, List[Network]] = dict()

    def __set_mode(self, mode: str) -> None:
        '''
        ### Do not use this method in your own scripts! The method is shall only be used in the Interface class It will only set the attribute of the class to the mode. It won't change the behaviour of the device.
        '''
        self._mode = mode

    def get_name(self) -> str:
        return self._name

    def get_mode(self) -> Mode:
        return self._mode
    
    def switch_mode(self, mode: Mode):
        assert mode in {'monitor', 'managed'}, f'Invalid mode "{mode}". Please choose "managed" or "monitor".'
        try:
            process = subprocess.Popen(f'ifconfig {self._name} down'.split(' '))
            code = process.wait()

            if code == 255:
                process.kill()
                raise PermissionError


            subprocess.Popen(f'iwconfig {self._name} mode {mode}'.split(' ')).wait()
            subprocess.Popen(f'ifconfig {self._name} up'.split(' ')).wait()

            self.__set_mode(mode)

        except PermissionError:
            self.__util_paw.print_permission_error()
            exit()

    def scan_for_wireless_networks(self) -> Dict[str, Network]:
        try:
            sniff(prn=self.__handle_packet, iface=self.get_name())

        except KeyboardInterrupt:
            self.switch_mode(self._prev_mode)
            return self.__scanned_networks
        
        except PermissionError as e:
            print(e)
            exit()
    
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

            if bssid not in self.__scanned_networks.keys():
                self.__scanned_networks[bssid] = Network(
                    bssid,
                    ssid,
                    dbm_signal,
                    channel,
                    crypto,
                )
                
                print(self.__scanned_networks[bssid])
    def __str__(self):
        return self.get_name()


def get_interfaces() -> List[Interface]:
    output = subprocess.getoutput('iwconfig').split('\n\n')

    interfaces = []
    
    for line in output:
        if 'no wireless' in line:
            continue

        name = ''
        mode = ''

        if '802' in line:
            name = line.split(' ')[0]
        
        if 'Managed' in line:
            mode = 'managed'

        if 'Monitor' in line:
            mode = 'monitor'

        interfaces.append(Interface(
            name = name,
            mode = mode,
        ))
    
    return interfaces
        
def get_interface_by_name(name: str) -> Interface:
    interfaces = get_interfaces()
    try:
        return next(iface for iface in interfaces if iface.get_name() == name)
    except StopIteration:
        raise InterfaceNotFoundError(name)

class InterfaceNotFoundError(Exception):
    """Exception raised for invalid interface names."""

    def __init__(self, interface_name: str):
        self.interface_name = interface_name
        self.message = f'No network interface "{self.interface_name}" with wireless extension found.'
        super().__init__(self.message)