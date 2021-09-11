from multiprocessing.dummy import Pool
import subprocess
import threading
import socket
from time import sleep
from paws.util_paw import UtilPaw

class ScanPaw:

    _util_paw = None

    # scapy imports
    Dot11Beacon = None
    Dot11 = None
    Dot11Elt = None
    sniff = None

    # port scanning
    _target = None
    _maxprocesses = None
    _maxthreads = None

    # scanning for networks
    _interface = None
    _networks_found = {}
    _prev_length = 0
    _automode = None
    _prev_mode = None

    def __init__(self, options, util_paw: UtilPaw) -> None:
        self._util_paw = util_paw

        method = options['mthd']
        if method == 'ports':
            self.__set_target(options['target'])
            self.__set_maxprocesses(options['maxprocesses'])
            self.__set_maxthreads(options['maxthreads'])
        
        elif method == 'networks':
            self.__set_automode(options['automode'])
            self.__set_interface(options['interface'])
            self.__init_scapy_util()

    def __init_scapy_util(self):
        scapy_all = __import__('scapy.all', fromlist=['Dot11Beacon', 'Dot11', 'Dot11Elt', 'sniff'])
        self.Dot11 = scapy_all.Dot11
        self.Dot11Beacon = scapy_all.Dot11Beacon
        self.Dot11Elt = scapy_all.Dot11Elt
        self.sniff = scapy_all.sniff

    def __set_target(self, target: str) -> None:
        try:
            self._target = socket.gethostbyname(target)
        except socket.gaierror:
            self._util_paw.print_text('Hostname could not be resolved.', color='red')
            exit()

    def __set_maxthreads(self, maxthreads: int) -> None:
        self._maxthreads = maxthreads

    def __set_maxprocesses(self, maxprocesses: int) -> None:
        self._maxprocesses = maxprocesses

    def is_open_port(self, port: int) -> bool:

        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        socket.setdefaulttimeout(1)
        
        result = s.connect_ex((self._target, port))
        if result == 0:
            self._util_paw.print_text(f'Found open port: ', end='', verbose=True)
            self._util_paw.print_text(port, color='cyan', verbose=True)

            return port
        
        s.close()
        return None


    def get_services(self, ports: list) -> dict:
        services = dict.fromkeys(ports, 'unknown')
        for port in ports:
            try:
                services[port] = socket.getservbyport(port, 'tcp')
            except socket.error:
                pass
        
        return services

    def get_open_ports_multiprocessing(self) -> list:
        try:
            with Pool(self._maxprocesses) as p:
                return list(filter(None, p.map(self.is_open_port, self._util_paw.get_most_common_ports())))

        except socket.error:
            self._util_paw.print_text('Server does not respond.', color='red', attrs=['bold'])
            exit()

    def get_open_ports_threading(self) -> list:

        open_ports = []
        most_common_ports = self._util_paw.get_most_common_ports()

        try:
            def append_port_if_open(port: int) -> None:
                if self.is_open_port(port) != None: open_ports.append(port)

            while len(most_common_ports) != 0:
                port = most_common_ports[0]
                if threading.active_count() >= self._maxthreads:
                    sleep(0.1)
                else:
                    t = threading.Thread(target=append_port_if_open, args=[port])
                    t.start()
                    most_common_ports.pop(0)

            while threading.active_count() != 1:
                sleep(1)

        except socket.error:
            self._util_paw.print_text('Server does not respond.', color='red', attrs=['bold'])
            exit()

        return open_ports

    def __set_automode(self, automode: bool):
        self._automode = automode
    
    def __set_interface(self, interface: str):

        interface = self.get_interface(interface)
        self._interface = interface['name']

        if self._automode and interface['mode'] != 'monitor':
            self._prev_mode = interface['mode']
            self.switch_interface_mode('monitor')
        
        elif interface['mode'] != 'monitor':
            self._util_paw.print_text('Your interface must be in monitor mode. Set the \'-am\' (automode) flag to change the mode when kitten runs.', color='red', attrs=['bold'])
            exit()


    def __handle_packet(self, packet):
        if packet.haslayer(self.Dot11Beacon):
            
            bssid = packet[self.Dot11].addr2
            
            try:
                ssid = packet[self.Dot11Elt].info.decode()
            except UnicodeDecodeError:
                ssid = packet[self.Dot11Elt].info
            
            try:
                dbm_signal = packet.dBm_AntSignal
            except:
                dbm_signal = 'N/A'
            
            stats = packet[self.Dot11Beacon].network_stats()
            
            channel = stats.get('channel')
            
            crypto = stats.get('crypto')

            if bssid not in self._networks_found.keys():
                self._networks_found[bssid] = {
                    'bssid': bssid,
                    'ssid': ssid,
                    'dbm_signal': dbm_signal,
                    'channel': channel,
                    'crypto': list(crypto)[0]
                }
                
                self._util_paw.print_scanned_network(self._networks_found[bssid])

    def get_wireless_networks(self):
        try:
            self.sniff(prn=self.__handle_packet, iface=self._interface)

        except KeyboardInterrupt:

            self.switch_interface_mode(self._prev_mode)
            return self._networks_found
        
        except PermissionError:
            self.switch_interface_mode(self._prev_mode)
            self._util_paw.print_permission_error()
            exit()
    
    def get_interface(self, name: str):
        interfaces = self.get_interfaces()
        return next(iface for iface in interfaces if iface['name'] == name)

        
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
        assert mode in {'monitor', 'managed'}, 'Invalid mode.'

        subprocess.Popen(f'sudo ifconfig {self._interface} down'.split(' ')).wait()
        subprocess.Popen(f'sudo iwconfig {self._interface} mode {mode}'.split(' ')).wait()
        subprocess.Popen(f'sudo ifconfig {self._interface} up'.split(' ')).wait()