import subprocess

from paws.util_paw import UtilPaw

class IfacePaw:

    __util_paw = None
    
    _interface = ''
    _automode = bool()

    def __init__(self, options, util_paw: UtilPaw) -> None:
        self.__util_paw = util_paw

    def set_automode(self, automode: bool) -> None:
        self._automode = automode
    
    def set_interface(self, interface: str) -> None:

        interface = self.get_interface_by_name(interface)
        self._interface = interface['name']

        if self._automode and interface['mode'] != 'monitor':
            self.switch_interface_mode('monitor')
        
        if not self._automode and interface['mode'] == 'managed':
            self.__util_paw.print_text('Your interface is in managed mode. Some scans require monitor mode. So if you get no results that could be the reason. Set the -am flag to automatically change the mode into the required one.', color='yellow', attrs=['bold'])
        

    def get_interface_by_name(self, name: str) -> str:
        interfaces = self.get_interfaces()
        return next(iface for iface in interfaces if iface['name'] == name)
    
    def get_selected_interface(self) -> str:
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

            interfaces.append({
                'name': name,
                'mode': mode,
            })
        
        return interfaces

    def switch_interface_mode(self, mode: str) -> None:
        assert mode in {'monitor', 'managed'}, f'Invalid mode "{mode}"'

        try:
            process = subprocess.Popen(f'ifconfig {self._interface} down'.split(' '))
            code = process.wait()

            if code == 255:
                process.kill()
                raise PermissionError


            subprocess.Popen(f'iwconfig {self._interface} mode {mode}'.split(' ')).wait()
            subprocess.Popen(f'ifconfig {self._interface} up'.split(' ')).wait()

            self.__util_paw.print_text(f'\nPut {self._interface} into {mode} mode.', end='\n\n', color='white', attrs=['bold'])

        except PermissionError:
            self.__util_paw.print_permission_error()
            exit()