import socket


class Port:

    def __init__(
        self,
        port_number: int,
        service: str = 'unknown',
    ) -> None:
        self.port_number = port_number
        self.service = service
    
    def update_service(self):
        try:
            self.service = socket.getservbyport(self.port_number, 'tcp')
        except socket.error:
            pass
    
    def __str__(self) -> str:
        return f'Port({self.port_number}, {self.service})'