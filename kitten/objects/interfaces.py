import subprocess
from sys import platform
import xml.etree.ElementTree as ET
from typing import Dict, List, Literal
from objects.network import Network
from scapy.layers.dot11 import sniff, Dot11, Packet, Dot11Elt, Dot11Beacon
from scapy.config import conf
from utils.output import print_permission_error, print_scanned_network

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
            print_permission_error()
            exit()

    def scan_for_wireless_networks(self) -> Dict[str, Network]:

        # check for operating system and handle command for this op

        # Windows
        if platform == 'win32':
            # windows is not supported
            raise OperatingSystemNotSupportedError(platform)
        
        # MacOS
        elif platform == 'darwin':
            # use airport command for getting networks
            output = subprocess.getoutput('/System/Library/PrivateFrameworks/Apple80211.framework/Versions/Current/Resources/airport -s')

            # skip first line because these are only headers
            raw_network_strings = output.split('\n')[1:]

            for raw_network_string in raw_network_strings:
                # split without arguments splits on whitespace
                splitted = raw_network_string.split()

                ssid = ''

                for i, info in enumerate(splitted):
                    # info with 5 colons should be the bssid, very unlikely that someone names their access point like that
                    # if reached the bssid we can move on because from now nothing contains extra whitespace
                    if info.count(':') != 5:
                        ssid += info
                    
                    # cut ssid part from splitted and break from loop
                    else:
                        splitted = splitted[i:]
                        break
                
                # add network to scanned network as instance of Network
                self.__scanned_networks[splitted[0]] = Network(
                    bssid=splitted[0],
                    ssid=ssid,
                    dbm_signal=splitted[1],
                    channel=splitted[2],
                    # pass crypto as list because it is defined as list because when scanning on linux there are multiple cryptos
                    crypto=[splitted[5]],
                )
                
                print_scanned_network(self.__scanned_networks[splitted[0]])



        
        # Linux (value can be 'linux' or 'linux2')
        elif 'linux' in platform:
            # with use_pcap = True monitor is automatically enabled on devices when monitor=True (i think)
            conf.use_pcap = True
            try:
                # only in monitor mode, 802.11 frames are captured
                sniff(prn=self.__handle_packet, iface=self.get_name(), monitor=True)

            except KeyboardInterrupt:
                self.switch_mode(self._prev_mode)
                return self.__scanned_networks
            
            except PermissionError as e:
                print(e)
                exit()

        # any other op
        else:
            raise OperatingSystemNotSupportedError(platform)

    
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
                
                print_scanned_network(self.__scanned_networks[bssid])
    def __str__(self):
        return self.get_name()


def get_interfaces() -> List[Interface]:

    interfaces = []

    # check for operating system and handle command for this op
    
    # Windows
    if platform == 'win32':
        # windows is not supported
        raise OperatingSystemNotSupportedError(platform)

    # MacOS
    elif platform == 'darwin':
        output = subprocess.getoutput('networksetup -listallhardwareports').lstrip().split('\n\n')

        for line in output:
            # unnecessary line
            if 'VLAN Configurations' in line:
                continue

            # device name is in second line after the 8 character string 'Device: '
            name = line.split('\n')[1][8:]

            interfaces.append(Interface(
                name=name,
                mode='unknown',
            ))

    # Linux (value can be 'linux' or 'linux2')
    elif 'linux' in platform:
        output = subprocess.getoutput('iwconfig').split('\n\n')
        
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
                name=name,
                mode=mode,
            ))
    
    # any other op
    else:
        raise OperatingSystemNotSupportedError(platform)
        
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

class OperatingSystemNotSupportedError(Exception):
    """Exception raised on not supported operating systems."""

    def __init__(self, os_name: str):
        self.message = f'Platform: "{os_name}" is currently not supported.'
        super().__init__(self.message)