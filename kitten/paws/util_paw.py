import json
import os

class UtilPaw:

    options = None

    verbose = None

    HEADER = '\033[95m'
    BLUE = '\033[94m'
    CYAN = '\033[96m'
    GREEN = '\033[92m'
    WARNING = '\033[93m'
    RED = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'

    colors_dict = {
        'blue': BLUE,
        'cyan': CYAN,
        'green': GREEN,
        'yellow': WARNING,
        'red': RED,
        'white': '',
    }

    def __init__(self, options) -> None:

        self.options = options

        self.__set_verbose(options['verbose'])

    def __set_verbose(self, verbose: bool) -> None:
        self.verbose = verbose

    def print_text(
        self,
        text: str='',
        verbose: bool=False,
        color: str='white',
        background_color: str=None,
        end: str='\n',
        attrs: list=[]
    ) -> None:
        if verbose and not self.verbose: return

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
        target = self.options['target']
        max_processes = self.options['maxprocesses']

        self.print_text(f'''{self.ENDC}
scan options:
| method:
|    {self.BOLD}scanning for ports{self.ENDC}
| target:
|    {self.BOLD}{target}{self.ENDC}
| max number of processes:
|    {self.BOLD}{max_processes}{self.ENDC}
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

    def print_networks_scan_info(self):
        target = self.options['interface']

        self.print_text(f'''{self.ENDC}
scan options:
| method:
|    {self.BOLD}scanning for networks{self.ENDC}
| interface:
|    {self.BOLD}{target}{self.ENDC}
 ‾‾‾

scan results:
| networks found:
|    {self.BOLD}BSSID\t\t\tDBMSIGNAL\tCHANNEL\t\tCRYPTO\t\tSSID{self.ENDC}
|''')

    def print_scanned_network(self, network: dict):
        last_tab_space = '\t' if len(network['crypto']) >= 8 else '\t\t'
        self.print_text(f'''{self.ENDC}|    {self.BOLD}{network['bssid']}\t\t{network['dbm_signal']}\t\t{network['channel']}\t\t{network['crypto']}{last_tab_space}{network['ssid']}{self.ENDC}''')

    def print_permission_error(self):
        self.print_text('Not enough permissions. Please restart with sudo.', color='red', attrs=['bold'])
    
    def get_most_common_ports(self) -> list:
        path = os.path.join(os.path.dirname(__file__), '../data/port_data.json')
        f = open(path, 'r')
        data = json.load(f)
            
        return data['most_common_ports']
