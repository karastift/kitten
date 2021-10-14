#!/usr/bin/env python3
from ipaddress import IPv4Address
from typing import Literal
from objects.interfaces import Interface, InterfaceNotFoundError, get_interface_by_name, get_interfaces
from objects.accesspoint import AccessPoint
from objects.machine import Machine
from objects.network import Network
from paws.arg_paw import ArgPaw
from paws.attack_paw import AttackPaw
from paws.iface_paw import IfacePaw
from paws.util_paw import UtilPaw
from paws.scan_paw import ScanPaw


class Options:
    cmd = ''
    mthd = ''
    verbose = False,
    # port scan
    target = ''
    maxthreads = 75
    json = False
    # network scan
    interface = ''
    automode = False
    # deauth
    target = ''
    interval = .1
    count = 0,

    def __init__(
        self,
        command: Literal['attack', 'scan', 'iface'] = '',
        method: Literal['deauth', 'mode', 'list', 'networks', 'ports'] = '',
        verbose: bool = False,
        target_ip: str = '',
        max_threads: int = 0,
        json: bool = False,
        interface: str = '',
        automode: bool = False,
        target_mac: str = '',
        interval: float = .1,
        count: int = 0,

    ) -> None:
        self.cmd = command
        self.mthd = method
        self.verbose = verbose
        self.target = target_ip
        self.max_threads = max_threads
        self.json = json
        self.interface = interface
        self.automode = automode
        self.target = target_mac
        self.interval = interval
        self.count = count


class Kitten:

    __arg_paw = None
    __util_paw = None
    __scan_paw = None
    __iface_paw = None
    __attack_paw = None

    __command = None

    __options = {}

    def __init__(
        self,
        options: Options = Options()
    ) -> None:

        if options.cmd and options.mthd:
            self.__options = options.__dict__
            print(self.__options)
        else:
            self.__arg_paw = ArgPaw()
            self.__options = self.__arg_paw.get_options()

        self.__set_command(self.__options['cmd'])

        self.__util_paw = UtilPaw(self.__options)
        self.__scan_paw = ScanPaw(self.__util_paw)
        self.__iface_paw = IfacePaw(self.__util_paw)
        self.__attack_paw = AttackPaw(self.__util_paw)

        self.__util_paw.set_verbose(self.__options['verbose'])
        self.__util_paw.print_prolog() if not self.__options.get('json') else None

        self.__set_command(self.__options['cmd'])
        self.__set_method(self.__options['mthd'])
        self.__handle_command()

    def __set_command(self, command : str) -> None:
        self.__command = command
    
    def __set_method(self, method: str) -> None:
        self.__method = method
        
    def __handle_command(self) -> None:

        if self.__command == 'scan':

            if self.__method == 'ports':

                if not self.__options['json']: self.__util_paw.print_port_scan_info()

                m = Machine(IPv4Address(self.__options['target']))
                m.update_open_ports()

                if self.__options['json']:
                    self.__util_paw.print_port_scan_results_json(m.open_ports)
                else:
                    self.__util_paw.print_port_scan_results(m.open_ports)

            elif self.__method == 'networks':

                interface = self.get_interface_safe(self.__options['interface'])
                self.handle_automode(interface)

                self.__util_paw.print_networks_scan_info()
                
                interface.scan_for_wireless_networks()
        
        elif self.__command == 'iface':

            if self.__method == 'mode':

                interface_name = self.__options['interface']
                mode = self.__options['mode']
                
                interface = self.get_interface_safe(self.__options['interface'])

                interface.switch_mode(mode)

                self.__util_paw.print_text(f'\nPut {interface_name} into {mode} mode.', end='\n\n', color='white', attrs=['bold'])
            
            elif self.__method == 'list':
                interfaces = get_interfaces()

                if self.__options['json']:
                    self.__util_paw.print_network_interfaces_json(interfaces)
                else:
                    self.__util_paw.print_network_interfaces(interfaces)

        elif self.__command == 'attack':
            self.__attack_paw.set_verbose(self.__options['verbose'])

            if self.__method == 'deauth':
                self.__util_paw.print_attack_deauth_info()

                try:
                    interface = get_interface_by_name(self.__options['interface'])
                except InterfaceNotFoundError as e:
                    self.__util_paw.print_text(e.message, attrs=['bold'])

                self.handle_automode(interface)

                Network(bssid=self.__options['network_mac']).deauth(
                    interface = interface,
                    target_mac = self.__options['target'],
                    interval = self.__options['interval'],
                    count = self.__options['count'],
                    verbose = True,
                )
            
            if self.__method == 'fakeap':
                self.__util_paw.print_attack_fake_ap_info()
                
                interface = self.get_interface_safe(self.__options['interface'])

                self.handle_automode(interface)                

                AccessPoint(
                    ssid = self.__options['ssid'],
                    bssid = self.__options['mac_address'],
                    interface = interface,
                ).appear(interval=self.__options['interval'])
    
    def handle_automode(self, interface: Interface) -> None:
        if self.__options['automode'] and interface.get_mode() != 'monitor':
            interface.switch_mode('monitor')
    
    def get_interface_safe(self, interface_name: str) -> Interface:
        try:
            return get_interface_by_name(interface_name)
        except InterfaceNotFoundError as e:
            self.__util_paw.print_text(e.message, attrs=['bold'])


def main() -> None:
    try:
        Kitten()
    except KeyboardInterrupt:
        print('\033[1m\nmeow.\033[0m')

if __name__ == '__main__':
    main()