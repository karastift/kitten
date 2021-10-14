from __future__ import annotations
import json
from typing import List, TYPE_CHECKING

from objects.port import Port
from objects.network import Network

if TYPE_CHECKING:
    # imports that are only used for typechecking
    from objects.interfaces import Interface

ENDC = '\033[0m'
BOLD = '\033[1m'

colors_dict = {
    'header': '\033[95m',
    'underline': '\033[4m',
    'blue': '\033[94m',
    'cyan': '\033[96m',
    'green': '\033[92m',
    'yellow': '\033[93m',
    'red': '\033[91m',
    'white': '',
}

def print_text(
    text: str='',
    verbose: bool=False,
    color: str='white',
    background_color: str=None,
    end: str='\n',
    attrs: list=[],
    options: dict = {},
) -> None:
    if verbose and not options.get('verbose'): return

    background_color = 'on_' + background_color if background_color != None else None

    assert color in colors_dict.keys(), f'Unsupported color: {color}'

    if 'bold' in attrs:
        print(f'{ENDC}{BOLD}{colors_dict[color]}{text}{ENDC}', end=end)
    else:
        print(f'{ENDC}{colors_dict[color]}{text}{ENDC}', end=end)

def print_prolog() -> None:
    print_text('kitten', end='\t', attrs=['bold'])
    print_text('beta', end='\t', color='green')
    print_text('( https://github.com/karastift/kitten.git )')

def print_port_scan_info(options: dict) -> None:
    target = options.get('target')
    max_processes = options.get('maxprocesses')
    
    print_text(f'''{ENDC}
scan options:
| method:
|    {BOLD}(ports) scanning for ports{ENDC}
| target:
|    {BOLD}{target}{ENDC}
| max number of processes:
|    {BOLD}{max_processes}{ENDC}
 ‾‾‾
''')

def print_attack_fake_ap_info(options: dict) -> None:
    interface = options.get('interface')
    ssid = options.get('ssid')
    mac_address = options.get('mac_address')
    interval = options.get('interval')

    print_text(f'''{ENDC}
attack options:
| method:
|    {BOLD}(fakeap) faking a wireless access point{ENDC}
| interface:
|    {BOLD}{interface}{ENDC}
| ssid:
|    {BOLD}{ssid}{ENDC}
| bssid:
|    {BOLD}{mac_address}{ENDC}
| interval:
|    {BOLD}{interval}{ENDC}
 ‾‾‾

sending beacon frames (press Ctrl+C to finish):''') 

def print_attack_deauth_info(options: dict) -> None:
    target_network_mac = options.get('network_mac')
    interface = options.get('interface')
    target_mac = options.get('target')
    interval = options.get('interval')
    count = options.get('count')

    print_text(f'''{ENDC}
attack options:
| method:
|    {BOLD}(deauth) disconnecting clients with deauth packets{ENDC}
| targeted network:
|    {BOLD}{target_network_mac}{ENDC}
| interface:
|    {BOLD}{interface}{ENDC}
| targeted client:
|    {BOLD}{'ff:ff:ff:ff:ff:ff (broadcast)' if not target_mac else target_mac}{ENDC}
| interval:
|    {BOLD}{interval}{ENDC}
| count:
|    {BOLD}{count if count else '∞'}{ENDC}
 ‾‾‾
''')
    
def print_port_scan_results(ports: List[Port]) -> None:
    print_text(f'''{ENDC}
scan results:
| ports:''')

    if len(ports) == 0:
        print_text(f'''{ENDC}|   {BOLD}No open ports discovered.{ENDC}''')
    else:
        for port in ports:
            print_text(f'''{ENDC}|    {BOLD}{port.port_number} -> {port.service}{ENDC}''')

    print_text(f'{ENDC} ‾‾‾')


def print_port_scan_results_json(ports: List[Port]):
    dic = dict()
    for port in ports:
        dic[port.port_number] = port.service
    print(json.dumps(dic))
    
def print_networks_scan_info(options: dict) -> None:
    target = options.get('interface')

    print_text(f'''{ENDC}
scan options:
| method:
|    {BOLD}(networks) scanning for networks{ENDC}
| interface:
|    {BOLD}{target}{ENDC}
 ‾‾‾

scan results:
| networks found:
|    {BOLD}BSSID\t\t\tDBMSIGNAL\tCHANNEL\t\tCRYPTO\t\tSSID{ENDC}
|''')

def print_scanned_network(network: Network) -> None:
    
    bssid = network.get_bssid()
    ssid = network.get_ssid()
    dbm_signal = network.get_dbm_signal()
    channel = network.get_channel()
    crypto = list(network.get_crypto())[0]

    last_tab_space = '\t' if len(crypto) >= 8 else '\t\t'
    print_text(f'''{ENDC}|    {BOLD}{bssid}\t\t{dbm_signal}\t\t{channel}\t\t{crypto}{last_tab_space}{ssid}{ENDC}''')

def print_network_interfaces( interfaces: List[Interface]):
    print_text(f'''{ENDC}
iface options:
| method:
|    {BOLD}(list) list all wireless network interfaces{ENDC}
 ‾‾‾

interfaces:
|    {BOLD}NAME\t\t\tMODE{ENDC}
|''')
    for interface in interfaces:
        print_text(f'''{ENDC}|    {BOLD}{interface.get_name()}\t\t{interface.get_mode()}{ENDC}''')

    print_text(' ‾‾‾', attrs=['bold'])

def print_as_json( dic: dict):
    print(json.dumps(dic))

def print_permission_error(self):
    print_text('Not enough permissions. Please restart with sudo.', color='red', attrs=['bold'])

def print_network_interfaces_json( interfaces: List[Interface]):
    dic = dict()
    for interface in interfaces:
        dic[interface.get_name()] = interface.get_mode()
    
    print(json.dumps(dic))