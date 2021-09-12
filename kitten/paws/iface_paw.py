import subprocess

from paws.util_paw import UtilPaw

class IfacePaw:

    _util_paw = None
    
    _interface = None
    _automode = None
    _prev_mode = 'monitor'

    def __init__(self, util_paw: UtilPaw) -> None:
        self._util_paw = util_paw

    def set_automode(self, automode: bool):
        self._automode = automode
    
    def set_interface(self, interface: str):

        interface = self.get_interface(interface)
        self._interface = interface['name']

        if self._automode and interface['mode'] != 'monitor':
            self._prev_mode = interface['mode']
            self.switch_interface_mode('monitor')
        
        elif interface['mode'] != 'monitor':
            self._util_paw.print_text('Your interface must be in monitor mode. Set the \'-am\' (automode) flag to change the mode when kitten runs.', color='red', attrs=['bold'])
            exit()

    def get_interface(self, name: str):
        interfaces = self.get_interfaces()
        return next(iface for iface in interfaces if iface['name'] == name)
    
    def get_selected_interface(self):
        return self._interface

        
    def get_interfaces(self):
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


    def switch_interface_mode(self, mode: str):
        assert mode in {'monitor', 'managed'}, f'Invalid mode "{mode}"'

        try:
            subprocess.Popen(f'ifconfig {self._interface} down'.split(' ')).wait()
            subprocess.Popen(f'iwconfig {self._interface} mode {mode}'.split(' ')).wait()
            subprocess.Popen(f'ifconfig {self._interface} up'.split(' ')).wait()

        except PermissionError:
            self.switch_interface_mode(self._prev_mode)
            self._util_paw.print_permission_error()
            exit()