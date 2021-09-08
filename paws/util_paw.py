import json
from time import sleep

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

    def print_text(self, text: str='', verbose: bool=False, color: str='white', end: str='\n') -> None:
        if verbose and not self.options['verbose']: return

        if color == 'white': return print(text, end=end)
        if color == 'green': return print(f'{self.GREEN}{text}{self.ENDC}', end=end)
        if color == 'blue': return print(f'{self.BLUE}{text}{self.ENDC}', end=end)
        if color == 'cyan': return print(f'{self.CYAN}{text}{self.ENDC}', end=end)
        if color == 'red': return print(f'{self.RED}{text}{self.ENDC}', end=end)
        if color == 'bold': return print(f'{self.BOLD}{text}{self.ENDC}', end=end)

        raise f'Unsupported color "{color}"'

    def print_prolog(self) -> None:
        self.print_text('kitten', end='\t', color='bold')
        self.print_text('early-access', end='\n', color='green')
        self.print_text('( https://github.com/karastift/kitten.git )')
    
    def get_most_common_ports(self) -> list:
        f = open('./data/port_data.json', 'r')
        data = json.load(f)
            
        return data['most_common_ports']