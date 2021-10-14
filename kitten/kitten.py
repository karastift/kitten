#!/usr/bin/env python3
from ipaddress import IPv4Address

from objects.accesspoint import AccessPoint
from objects.eviltwin import EvilTwin
from objects.interfaces import (Interface, InterfaceNotFoundError,
                                get_interface_by_name, get_interfaces)
from objects.machine import Machine
from objects.network import Network

from utils.args import ArgumentParser
from utils.output import (print_attack_deauth_info, print_attack_eviltwin_info,
                          print_attack_fake_ap_info, print_network_interfaces,
                          print_network_interfaces_json,
                          print_networks_scan_info, print_port_scan_info,
                          print_port_scan_results,
                          print_port_scan_results_json, print_prolog,
                          print_text)


class Kitten:

    command = None
    method = None

    options = {}

    def __init__(self) -> None:

        args = ArgumentParser()
        self.options = args.get_options()

        print_prolog() if not self.options.get('json') else None

        self.set_command(self.options.get('cmd'))
        self.set_method(self.options.get('mthd'))

        self.execute()

    def set_options(self, options: dict):
        self.options = options

    def set_command(self, command : str) -> None:
        self.command = command
    
    def set_method(self, method: str) -> None:
        self.method = method
        
    def execute(self) -> None:

        if self.command == 'scan':

            if self.method == 'ports':

                if not self.options['json']: print_port_scan_info(self.options)

                m = Machine(IPv4Address(self.options['target']))
                m.update_open_ports()

                if self.options['json']:
                    print_port_scan_results_json(m.open_ports)
                else:
                    print_port_scan_results(m.open_ports)

            elif self.method == 'networks':

                interface = self.get_interface_safe(self.options['interface'])
                self.handle_automode(interface)

                print_networks_scan_info(self.options)
                
                interface.scan_for_wireless_networks()
        
        elif self.command == 'iface':

            if self.method == 'mode':

                interface_name = self.options['interface']
                mode = self.options['mode']
                
                interface = self.get_interface_safe(self.options['interface'])

                interface.switch_mode(mode)

                print_text(f'\nPut {interface_name} into {mode} mode.', end='\n\n', color='white', attrs=['bold'])
            
            elif self.method == 'list':
                interfaces = get_interfaces()

                if self.options['json']:
                    print_network_interfaces_json(interfaces)
                else:
                    print_network_interfaces(interfaces)

        elif self.command == 'attack':

            if self.method == 'deauth':
                print_attack_deauth_info(self.options)

                interface = self.get_interface_safe(self.options.get('interface'))

                self.handle_automode(interface)

                Network(bssid=self.options['network_mac']).deauth(
                    interface = interface,
                    target_mac = self.options['target'],
                    interval = self.options['interval'],
                    count = self.options['count'],
                    verbose = True,
                )
            
            if self.method == 'fakeap':
                print_attack_fake_ap_info(self.options)
                
                interface = self.get_interface_safe(self.options['interface'])

                self.handle_automode(interface)                

                AccessPoint(
                    ssid = self.options['ssid'],
                    bssid = self.options['mac_address'],
                    interface = interface,
                ).appear(interval=self.options['interval'])
            
            if self.method == 'eviltwin':
                print_attack_eviltwin_info(self.options)

                self.handle_automode(interface)

                EvilTwin(
                    ssid = self.options['ssid'],
                    bssid = self.options['bssid'],
                    interface = interface,
                ).start(
                    interval = self.options.get('interval'),
                    count = self.options.get('count'),
                )
    
    def handle_automode(self, interface: Interface) -> None:
        if self.options['automode'] and interface.get_mode() != 'monitor':
            interface.switch_mode('monitor')
    
    def get_interface_safe(self, interface_name: str) -> Interface:
        try:
            return get_interface_by_name(interface_name)
        except InterfaceNotFoundError as e:
            print_text(e.message, attrs=['bold'])
            exit()


def main() -> None:
    try:
        Kitten()
    except KeyboardInterrupt:
        print('\033[1m\nmeow.\033[0m')

if __name__ == '__main__':
    main()
