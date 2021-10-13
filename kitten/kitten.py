#!/usr/bin/env python3
from paws.arg_paw import ArgPaw
from paws.attack_paw import AttackPaw
from paws.iface_paw import IfacePaw
from paws.util_paw import UtilPaw
from paws.scan_paw import ScanPaw

# get operating system on scan
# https://www.linux.org/threads/nmap-os-detection.4564/
# https://nmap.org/man/de/man-os-detection.html
# https://nmap.org/book/nmap-os-db.html
# https://svn.nmap.org/nmap/nmap-os-db (actual db)

# basic attacking / testing
# -> if a ssh port is found, recommend to test it
# -> test most common passwords + users (maybe based on operating system)

# scan for clients on network

# deauth:
# https://www.thepythoncode.com/article/force-a-device-to-disconnect-scapy

# evil twin maybe

class Kitten:

    arg_paw = None
    util_paw = None
    scan_paw = None
    iface_paw = None
    attack_paw = None

    command = None

    options = {}

    def __init__(self) -> None:
        self.arg_paw = ArgPaw()

        self.options = self.arg_paw.get_options()

        self.__set_command(self.options['cmd'])

        self.util_paw = UtilPaw(self.options)
        self.scan_paw = ScanPaw(self.options, self.util_paw)
        self.iface_paw = IfacePaw(self.options, self.util_paw)
        self.attack_paw = AttackPaw(self.util_paw)

        self.util_paw.print_prolog()
        self.handle_command()

    def __set_command(self, command : str):
        self.command = command
        
    def handle_command(self):
        command = self.options['cmd']
        method = self.options['mthd']

        if command == 'scan':

            if method == 'ports':
                self.util_paw.print_port_scan_info()
                open_ports = self.scan_paw.get_open_ports_multiprocessing()
                services = self.scan_paw.get_services(open_ports)
                self.util_paw.print_port_scan_results(services)

            elif method == 'networks':
                self.util_paw.print_networks_scan_info()
                self.scan_paw.get_wireless_networks()
        
        elif command == 'iface':

            if method == 'mode':
                self.iface_paw.set_interface(self.options['interface'])
                self.iface_paw.switch_interface_mode(self.options['mode'])

        elif command == 'attack':
            self.attack_paw.set_verbose(self.options['verbose'])

            if method == 'deauth':
                self.attack_paw.set_target_network_mac(self.options['network_mac'])
                self.attack_paw.set_target_mac(self.options['target'])
                self.attack_paw.set_interface(self.options['interface'])
                self.attack_paw.set_interval(self.options['interval'])
                self.attack_paw.set_count(self.options['count'])

                self.attack_paw.deauth()
def main():
    try:
        Kitten()
    except KeyboardInterrupt:
        print('\033[1m\nmeow.\033[0m')

if __name__ == '__main__':
    main()