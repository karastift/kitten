import socket
from multiprocessing.dummy import Pool
from ipaddress import IPv4Address, IPv6Address
from typing import List

from objects.port import Port
from paws.util_paw import UtilPaw


class Machine:
    
    def __init__(
        self,
        ipv4: IPv4Address = None,
        ipv6: IPv6Address = None,
        domain: str = '',
        os: str = 'unknown',
        open_ports: List[Port] = list(),
    ) -> None:
        if not (domain or ipv4 or ipv6 ):
            raise TypeError('"domain" or "ipv4" or "ipv6" has to be defined.')

        self.ipv4 = ipv4
        self.ipv6 = ipv6
        self.domain = domain
        self.os = os
        self.open_ports = open_ports

        self.update_info()

    def update_info(self):
        if self.ipv4:
            prefix6to4 = int(IPv6Address('2002::'))
            self.ipv6 = IPv6Address(prefix6to4 | (int(self.ipv4) << 80))
        elif self.ipv6:
            self.ipv4 = self.ipv6.sixtofour
        else:
            self.ipv4 = IPv4Address(socket.gethostbyname(self.domain))
            prefix6to4 = int(IPv6Address('2002::'))
            self.ipv6 = IPv6Address(prefix6to4 | (int(self.ipv4) << 80))

    def get_services_of_ports(self, ports: List[Port]) -> List[Port]:
        for port in ports:
            port.update_service()
        
        return ports
    
    def is_port_open(self, port: Port) -> bool:

        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        socket.setdefaulttimeout(1)
        
        result = s.connect_ex((self.ipv4.compressed, port.port_number))
        
        if result == 0:
            return True
        
        s.close()
        return False
    
    def update_open_ports(
        self,
        maxprocesses: int = 75,
    ) -> None:
        common_ports = UtilPaw({'verbose': True}).get_most_common_ports()


        try:
            with Pool(maxprocesses) as p:
                self.open_ports = list(
                    filter(
                        None,
                        p.map(
                            lambda port_number: Port(port_number) if self.is_port_open(Port(port_number)) else None,
                            common_ports,
                        )
                    )
                )
            for port in self.open_ports:
                port.update_service()

        except socket.error:
            print('Server does not respond.')
            exit()