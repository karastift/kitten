import json
import os

class UtilPaw:

    __options = None

    __verbose = None

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

    def __init__(self, options) -> None:
        self.__options = options

    def set_verbose(self, verbose: bool) -> None:
        self.__verbose = verbose
    
    def get_most_common_ports(self) -> list:
        path = os.path.join(os.path.dirname(__file__), '../data/port_data.json')
        f = open(path, 'r')
        data = json.load(f)
            
        return data['most_common_ports']

    def print_text(
        self,
        text: str='',
        verbose: bool=False,
        color: str='white',
        background_color: str=None,
        end: str='\n',
        attrs: list=[]
    ) -> None:
        if verbose and not self.__verbose: return

        background_color = 'on_' + background_color if background_color != None else None

        assert color in self.colors_dict.keys(), f'Unsupported color: {color}'

        if 'bold' in attrs:
            print(f'{self.ENDC}{self.BOLD}{self.colors_dict[color]}{text}{self.ENDC}', end=end)
        else:
            print(f'{self.ENDC}{self.colors_dict[color]}{text}{self.ENDC}', end=end)

    def print_prolog(self) -> None:
        self.print_text('kitten', end='\t', attrs=['bold'])
        self.print_text('beta', end='\t', color='green')
        self.print_text('( https://github.com/karastift/kitten.git )')

    def print_port_scan_info(self) -> None:
        target = self.__options['target']
        max_processes = self.__options['maxprocesses']

        self.print_text(f'''{self.ENDC}
scan options:
| method:
|    {self.BOLD}(ports) scanning for ports{self.ENDC}
| target:
|    {self.BOLD}{target}{self.ENDC}
| max number of processes:
|    {self.BOLD}{max_processes}{self.ENDC}
 ‾‾‾
'''     )

    def print_attack_deauth_info(self) -> None:
        target_network_mac = self.__options['network_mac']
        interface = self.__options['interface']
        target_mac = self.__options['target']
        interval = self.__options['interval']
        count = self.__options['count']

        self.print_text(f'''{self.ENDC}
attack options:
| method:
|    {self.BOLD}(deauth) disconnecting clients with deauth packets{self.ENDC}
| targeted_network:
|    {self.BOLD}{target_network_mac}{self.ENDC}
| interface:
|    {self.BOLD}{interface}{self.ENDC}
| targeted client:
|    {self.BOLD}{'ff:ff:ff:ff:ff:ff (broadcast)' if not target_mac else target_mac}{self.ENDC}
| interval:
|    {self.BOLD}{interval}{self.ENDC}
| count:
|    {self.BOLD}{count if count else '∞'}{self.ENDC}
 ‾‾‾
'''     )
    
    def print_port_scan_results(self, scan_results: dict) -> None:
        self.print_text(f'''{self.ENDC}
scan results:
| ports:''')

        if len(scan_results.keys()) == 0:
            self.print_text(f'''{self.ENDC}|   {self.BOLD}No open ports discovered.{self.ENDC}''')
        else:
            for port in scan_results.keys():
                self.print_text(f'''{self.ENDC}|    {self.BOLD}{port} -> {scan_results[port]}{self.ENDC}''')

        self.print_text(f'{self.ENDC} ‾‾‾')

    def print_networks_scan_info(self) -> None:
        target = self.__options['interface']

        self.print_text(f'''{self.ENDC}
scan options:
| method:
|    {self.BOLD}(networks) scanning for networks{self.ENDC}
| interface:
|    {self.BOLD}{target}{self.ENDC}
 ‾‾‾

scan results:
| networks found:
|    {self.BOLD}BSSID\t\t\tDBMSIGNAL\tCHANNEL\t\tCRYPTO\t\tSSID{self.ENDC}
|''')

    def print_scanned_network(self, network: dict) -> None:
        last_tab_space = '\t' if len(network['crypto']) >= 8 else '\t\t'
        self.print_text(f'''{self.ENDC}|    {self.BOLD}{network['bssid']}\t\t{network['dbm_signal']}\t\t{network['channel']}\t\t{network['crypto']}{last_tab_space}{network['ssid']}{self.ENDC}''')

    def print_permission_error(self):
        self.print_text('Not enough permissions. Please restart with sudo.', color='red', attrs=['bold'])