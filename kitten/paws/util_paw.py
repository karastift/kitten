import json
from termcolor import cprint


class UtilPaw:

    options = None

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

    def print_text(
        self,
        text: str='',
        verbose: bool=False,
        color: str='white',
        background_color: str=None,
        end: str='\n',
        attrs: list=[]
    ) -> None:
        if verbose and not self.options['verbose']: return

        background_color = 'on_' + background_color if background_color != None else None

        cprint(text=text, color=color, on_color=background_color, attrs=attrs, end=end)

    def print_prolog(self) -> None:
        self.print_text('kitten', end='\t', attrs=['bold'])
        self.print_text('beta', end='\t', color='green')
        self.print_text('( https://github.com/karastift/kitten.git )')

    def print_scan_info(self):
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
    
    def print_scan_results(self, scan_results: dict):
        self.print_text(f'''{self.ENDC}
scan results:
| ports:''')

        for port in scan_results.keys():
            self.print_text(f'''{self.ENDC}|    {self.BOLD}{port} -> {scan_results[port]}{self.ENDC}''')

        self.print_text(f'{self.ENDC} ‾‾‾')
    
    def get_most_common_ports(self) -> list:
        f = open('./kitten/data/port_data.json', 'r')
        data = json.load(f)
            
        return data['most_common_ports']
