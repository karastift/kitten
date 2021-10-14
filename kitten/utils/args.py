import argparse

from scapy.volatile import RandMAC

class ArgumentParser:

    __options = None

    def __init__(self) -> None:
        kitten_parser = self.__create_parsers()
        self.__options = kitten_parser.parse_args().__dict__

    def __create_parsers(self) -> argparse.ArgumentParser:

        kitten_parser = argparse.ArgumentParser(
            epilog='\033[1mMade by kara.\033[0m',
            add_help=''
        )

        self.__add_costum_help_arg(kitten_parser)

        kitten_parser.add_argument(
            '-v', '--verbose',
            action='store_true',
            help='Run verbosely.',
        )

        subparsers = kitten_parser.add_subparsers(
            metavar='command',
            dest='cmd',
            required=True,
        )

        self.__configure_scan_parser(subparsers)
        self.__configure_iface_parser(subparsers)
        self.__configure_attack_parser(subparsers)

        return kitten_parser

    def __configure_attack_parser(self, subparsers: argparse._SubParsersAction) -> None:
        attack_parser = subparsers.add_parser(
            name='attack',
            help='Attack a target.',
        )
        subparsers = attack_parser.add_subparsers(
            metavar='method',
            dest='mthd',
            required=True,
        )

        self.__configure_attack_deauth_parser(subparsers)
        self.__configure_attack_fake_ap_parser(subparsers)
        self.__configure_attack_eviltwin_parser(subparsers)


    def __configure_attack_deauth_parser(self, subparsers: argparse._SubParsersAction) -> None:
        deauth_parser = subparsers.add_parser(
            name='deauth',
            help='Kick out devices from a network.',
        )
        deauth_parser.add_argument(
            dest='network_mac',
            type=str,
            help='MAC of the targeted network.',
        )
        deauth_parser.add_argument(
            dest='interface',
            type=str,
            help='Name of the interface to use (has to support monitor mode).',
        )
        deauth_parser.add_argument(
            '-am', '--automode',
            action='store_true',
            help='The selected interface is automatically put into the required mode.',
        )
        deauth_parser.add_argument(
            '-t', '--target',
            type=str,
            default=None,
            required=False,
            help='Define only one client to target. If undefined every client is attacked.',
        )
        deauth_parser.add_argument(
            '-i', '--interval',
            type=float,
            default=.1,
            required=False,
            help='Change the time between the sent packages.',
        )
        deauth_parser.add_argument(
            '-c', '--count',
            type=int,
            default=None,
            required=False,
            help='Change number of packets to send. If undefined or zero count is infinite.',
        )

    def __configure_attack_fake_ap_parser(self, subparsers: argparse._SubParsersAction) -> None:
        fake_ap_parser = subparsers.add_parser(
            name='fakeap',
            help='Fake a wireless access point.',
        )
        fake_ap_parser.add_argument(
            dest='ssid',
            type=str,
            help='Name of the fake access point.',
        )
        fake_ap_parser.add_argument(
            dest='interface',
            type=str,
            help='Name of the interface to use (has to support monitor mode).',
        )
        fake_ap_parser.add_argument(
            '-m', '--mac_address',
            default=str(RandMAC()),
            type=str,
            required=False,
            help='Mac address of the fake access point. (If undefined the address is randomly chosen).',
        )
        fake_ap_parser.add_argument(
            '-am', '--automode',
            action='store_true',
            help='The selected interface is automatically put into the required mode.',
        )
        fake_ap_parser.add_argument(
            '-i', '--interval',
            type=float,
            default=.1,
            required=False,
            help='Change the time between the sent packages.',
        )

    def __configure_attack_eviltwin_parser(self, subparsers: argparse._SubParsersAction) -> None:
        eviltwin_parser = subparsers.add_parser(
            name='eviltwin',
            help='Create and evil twin of an existing access point and disconnect clients from that access point.',
        )
        eviltwin_parser.add_argument(
            dest='ssid',
            type=str,
            help='Name of the targeted network.',
        )
        eviltwin_parser.add_argument(
            dest='interface',
            type=str,
            help='Name of the interface to use (has to support monitor mode).',
        )
        eviltwin_parser.add_argument(
            '-m', '--mac_address',
            default=str(RandMAC()),
            type=str,
            required=False,
            help='Mac address of the fake access point. (If undefined the address is randomly chosen).',
        )
        eviltwin_parser.add_argument(
            '-am', '--automode',
            action='store_true',
            help='The selected interface is automatically put into the required mode.',
        )
        eviltwin_parser.add_argument(
            '-i', '--interval',
            type=float,
            default=.1,
            required=False,
            help='Change the time between the sent packages.',
        )

    def __configure_iface_parser(self, subparsers: argparse._SubParsersAction) -> None:
        iface_parser = subparsers.add_parser(
            name='iface',
            help='Configure your network interface.',
        )

        subparsers = iface_parser.add_subparsers(
            metavar='method',
            dest='mthd',
            required=True,
        )

        self.__configure_iface_mode_parser(subparsers)
        self.__configure_iface_list_parser(subparsers)

    def __configure_iface_mode_parser(self, subparsers: argparse._SubParsersAction) -> None:
        mode_parser = subparsers.add_parser(
            name='mode',
            help='Configure the mode of your network interface.',
        )
        mode_parser.add_argument(
            dest='interface',
            type=str,
            help='Define the interface to configure.',
        )
        mode_parser.add_argument(
            dest='mode',
            type=str,
            help='The mode your interface will be put in.',
            choices=['managed', 'monitor']
        )
    
    def __configure_iface_list_parser(self, subparsers: argparse._SubParsersAction) -> None:
        list_parser = subparsers.add_parser(
            name='list',
            help='List network interfaces.',
        )
        list_parser.add_argument(
            '-j', '--json',
            action='store_true',
            help='Output will be in json format.'
        )
    
    def __configure_scan_parser(self, subparsers: argparse._SubParsersAction) -> None:
        scan_parser = subparsers.add_parser(
            name='scan',
            help='Scan a target.'
        )

        subparsers = scan_parser.add_subparsers(
            metavar='method',
            dest='mthd',
            required=True,
        )

        self.__configure_port_scan_parser(subparsers)
        self.__configure_networks_scan_parser(subparsers)

    def __configure_networks_scan_parser(self, subparsers: argparse._SubParsersAction) -> None:
        scan_parser = subparsers.add_parser(
            name='networks',
            help='Scan for wireless networks.'
        )
        scan_parser.add_argument(
            '-i', '--interface',
            type=str,
            required=True,
            help='The network interface which is used to sniff (it has to support monitor mode).',
        )
        scan_parser.add_argument(
            '-am', '--automode',
            action='store_true',
            help='The selected interface is automatically put into the required mode.',
        )

    def __configure_port_scan_parser(self, subparsers: argparse._SubParsersAction) -> None:
        scan_parser = subparsers.add_parser(
            name='ports',
            help='Scan a target for open ports.'
        )
        scan_parser.add_argument(
            dest='target',
            type=str,
            help='Define the target that is to be scanned.',
        )
        scan_parser.add_argument(
            '-mp', '--maxprocesses',
            type=int,
            default=75,
            help='Max number of processes that will be opened at the same time.',
        )
        scan_parser.add_argument(
            '-j', '--json',
            action='store_true',
            help='Output will be in json format.'
        )
    
    def __add_costum_help_arg(self, parser: argparse.ArgumentParser) -> None:
        parser.add_argument(
            '-h', '--help',
            action=argparse._HelpAction,
            help='Show this help message and exit.',
        )

    def get_options(self) -> dict:
        return self.__options