#!/usr/bin/env python3
from typing import Dict, Literal
from paws.arg_paw import ArgPaw
from paws.attack_paw import AttackPaw
from paws.iface_paw import IfacePaw
from paws.util_paw import UtilPaw
from paws.scan_paw import ScanPaw
from scapy import interfaces
from scapy.fields import M

# get operating system on scan
# https://www.linux.org/threads/nmap-os-detection.4564/
# https://nmap.org/man/de/man-os-detection.html
# https://nmap.org/book/nmap-os-db.html
# https://svn.nmap.org/nmap/nmap-os-db (actual db)

# basic attacking / testing
# -> if a ssh port is found, recommend to test it
# -> test most common passwords + users (maybe based on operating system)

# scan for clients on network

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
        self.__scan_paw = ScanPaw(self.__options, self.__util_paw)
        self.__iface_paw = IfacePaw(self.__options, self.__util_paw)
        self.__attack_paw = AttackPaw(self.__util_paw)

        self.__util_paw.set_verbose(self.__options['verbose'])
        self.__util_paw.print_prolog()

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

                self.__scan_paw.set_target(self.__options['target'])
                self.__scan_paw.set_maxprocesses(self.__options['maxprocesses'])
                self.__scan_paw.set_maxthreads(self.__options['maxthreads'])

                open_ports = self.__scan_paw.get_open_ports_multiprocessing()
                services = self.__scan_paw.get_services(open_ports)

                if self.__options['json']:
                    self.__util_paw.print_as_json(services)
                else:
                    self.__util_paw.print_port_scan_results(services)

            elif self.__method == 'networks':
                self.__scan_paw.set_automode(self.__options['automode'])
                self.__scan_paw.set_interface(self.__options['interface'])

                self.__util_paw.print_networks_scan_info()
                self.__scan_paw.scan_for_wireless_networks()
        
        elif self.__command == 'iface':

            if self.__method == 'mode':
                
                interface_name = self.__options['interface']
                mode = self.__options['mode']

                interface = self.__iface_paw.get_interface_by_name(interface_name)
                interface.switch_mode(mode)

                self.__util_paw.print_text(f'\nPut {interface_name} into {mode} mode.', end='\n\n', color='white', attrs=['bold'])
            
            elif self.__method == 'list':
                interfaces = self.__iface_paw.get_interfaces()

                if self.__options['json']:
                    self.__util_paw.print_as_json(interfaces)
                else:
                    self.__util_paw.print_network_interfaces(interfaces)

        elif self.__command == 'attack':
            self.__attack_paw.set_verbose(self.__options['verbose'])

            if self.__method == 'deauth':
                self.__util_paw.print_attack_deauth_info()

                self.__attack_paw.set_target_network_mac(self.__options['network_mac'])
                self.__attack_paw.set_target_mac(self.__options['target'])
                self.__attack_paw.set_interface(self.__options['interface'])
                self.__attack_paw.set_interval(self.__options['interval'])
                self.__attack_paw.set_count(self.__options['count'])

                self.__attack_paw.deauth()


def main() -> None:
    try:
        Kitten()
    except KeyboardInterrupt:
        print('\033[1m\nmeow.\033[0m')

if __name__ == '__main__':
    main()