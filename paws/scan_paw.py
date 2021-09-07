import json
import sys
import threading
import socket
from time import sleep
from paws.util_paw import UtilPaw
# import nmap

class ScanPaw:

    util_paw = None

    options = None

    def __init__(self, options, util_paw: UtilPaw) -> None:
        self.options = options
        self.util_paw = util_paw

        util_paw.print_text(text='Initialized ScanPaw...', verbose=True)

    def is_port_open(self, target: str, port: int) -> bool:

        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        socket.setdefaulttimeout(1)
        
        result = s.connect_ex((target, port))
        if result == 0:
            self.util_paw.print_text(f'Found open port: {port}', verbose=True)

            return True
        
        s.close()
        return False


    def get_services(self, ports: list):
        # try:
        #     open_ports[port] = socket.getservbyport(port, 'tcp')
        # except socket.error:
        #     open_ports[port] = 'unknown'
        pass

    def get_open_ports(self) -> list:

        open_ports = []
        most_common_ports = self.util_paw.get_most_common_ports()


        try:

            target = socket.gethostbyname(self.options['target'])

            def append_port_if_open(port: int):
                if self.is_port_open(target, port): open_ports.append(port)

            while len(most_common_ports) != 0:
                port = most_common_ports[0]
                if threading.active_count() >= 500:
                    sleep(0.1)
                else:
                    t = threading.Thread(target=append_port_if_open, args=[port])
                    t.start()
                    most_common_ports.pop(0)

            while threading.active_count() != 1:
                sleep(1)

        except socket.gaierror:
            self.util_paw.print_text('Hostname could not be resolved.', color='red')
        except socket.error:
            self.util_paw.print_text('Server does not respond.', color='red')

        return open_ports