from typing import List
import subprocess
from objects.interfaces import Interface

from paws.util_paw import UtilPaw

class IfacePaw:

    __util_paw = None
    
    _interface = ''
    _automode = bool()

    def __init__(self, util_paw: UtilPaw) -> None:
        self.__util_paw = util_paw

    def set_automode(self, automode: bool) -> None:
        self._automode = automode
    
    def set_interface(self, interface_name: str) -> None:

        interface = self.get_interface_by_name(interface_name)
        self._interface = interface

        if self._automode and interface.get_mode() != 'monitor':
            interface.switch_mode('monitor')
        
        if not self._automode and interface.get_mode() == 'managed':
            self.__util_paw.print_text('Your interface is in managed mode. Some scans require monitor mode. So if you get no results that could be the reason. Set the -am flag to automatically change the mode into the required one.', color='yellow', attrs=['bold'])