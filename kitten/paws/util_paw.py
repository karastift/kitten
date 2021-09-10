import json
import os
from termcolor import cprint


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

        cprint(text=text, color=color, on_color=background_color, attrs=attrs, end=end)

    def print_prolog(self) -> None:
        self.print_text('kitten', end='\t', attrs=['bold'])
        self.print_text('beta', end='\t', color='green')
        self.print_text('( https://github.com/karastift/kitten.git )')

    def print_scan_info(self) -> None:
        target = self.options['target']
        max_processes = self.options['maxprocesses']

        self.print_text(f'''{self.ENDC}
scan options:
| target:
|    {self.BOLD}{target}{self.ENDC}
| max number of processes:
|    {self.BOLD}{max_processes}{self.ENDC}
 ‾‾‾
'''     )
    
    def print_scan_results(self, scan_results: dict) -> None:
        self.print_text(f'''{self.ENDC}
scan results:
| ports:''')

        if len(scan_results.keys()) == 0:
            self.print_text(f'''{self.ENDC}|   {self.BOLD}No open ports discovered.{self.ENDC}''')
        else:
            for port in scan_results.keys():
                self.print_text(f'''{self.ENDC}|    {self.BOLD}{port} -> {scan_results[port]}{self.ENDC}''')

        self.print_text(f'{self.ENDC} ‾‾‾')
    
    def get_most_common_ports(self) -> list:
        path = os.path.join(os.path.dirname(__file__), '../data/port_data.json')
        f = open(path, 'r')
        data = json.load(f)
            
        return data['most_common_ports']
