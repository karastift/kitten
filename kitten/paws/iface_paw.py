import subprocess
from objects.interface import Interface

from paws.util_paw import UtilPaw

class IfacePaw:

    __util_paw = None
    
    _interface = ''
    _automode = bool()

    def __init__(self, options, util_paw: UtilPaw) -> None:
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
        
    def get_interface_by_name(self, name: str) -> Interface:
        interfaces = self.get_interfaces()
        return next(iface for iface in interfaces if iface.get_name() == name)

    def get_selected_interface(self) -> Interface:
        return self._interface

    def get_interfaces(self) -> list:
        output = subprocess.getoutput('iwconfig').split('\n\n')

        interfaces = []
        
        for line in output:
            if 'no wireless' in line:
                continue

            name = ''
            mode = ''

            if '802' in line:
                name = line.split(' ')[0]
            
            if 'Managed' in line:
                mode = 'managed'

            if 'Monitor' in line:
                mode = 'monitor'

            interfaces.append(Interface(
                name=name,
                mode=mode,
            ))
        
        return interfaces