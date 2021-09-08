from multiprocessing.dummy import Pool
import threading
import socket
from time import sleep
from paws.util_paw import UtilPaw

class ScanPaw:

    util_paw = None

    options = None

    target = None

    def __init__(self, options, util_paw: UtilPaw) -> None:
        self.options = options
        self.util_paw = util_paw

    def is_open_port(self, port: int) -> bool:

        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        socket.setdefaulttimeout(1)
        
        result = s.connect_ex((self.target, port))
        if result == 0:
            self.util_paw.print_text(f'Found open port: ', end='', verbose=True)
            self.util_paw.print_text(port, color='cyan', verbose=True)

            return port
        
        s.close()
        return None


    def get_services(self, ports: list):
        services = dict.fromkeys(ports, 'unknown')
        for port in ports:
            try:
                services[port] = socket.getservbyport(port, 'tcp')
            except socket.error:
                pass
        
        return services

    def set_target(self, target: str):
        try:
            self.target = socket.gethostbyname(target)
        except socket.gaierror:
            self.util_paw.print_text('Hostname could not be resolved.', color='red')
            exit()

    def get_open_ports_multiprocessing(self) -> list:
        try:
            self.set_target(self.options['target'])

            with Pool(self.options['maxprocesses']) as p:
                return list(filter(None, p.map(self.is_open_port, self.util_paw.get_most_common_ports())))

        except socket.error:
            self.util_paw.print_text('Server does not respond.', color='red')
            exit()

    def get_open_ports_threading(self) -> list:

        open_ports = []
        most_common_ports = self.util_paw.get_most_common_ports()


        try:

            self.set_target(self.options['target'])
            
            def append_port_if_open(port: int):
                if self.is_open_port(port) != None: open_ports.append(port)

            while len(most_common_ports) != 0:
                port = most_common_ports[0]
                if threading.active_count() >= self.options['maxthreads']:
                    sleep(0.1)
                else:
                    t = threading.Thread(target=append_port_if_open, args=[port])
                    t.start()
                    most_common_ports.pop(0)

            while threading.active_count() != 1:
                sleep(1)

        except socket.error:
            self.util_paw.print_text('Server does not respond.', color='red')
            exit()

        return open_ports