from paws.util_paw import UtilPaw

class AttackPaw:

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
    _networks_found = {}
    _prev_length = 0

    def __init__(self, options, util_paw: UtilPaw) -> None:
        self._util_paw = util_paw

        method = options['mthd']
        if method == 'ports':
            self.__set_target(options['target'])
            self.__set_maxprocesses(options['maxprocesses'])
            self.__set_maxthreads(options['maxthreads'])
        
        elif method == 'networks':
            self.set_automode(options['automode'])
            self.set_interface(options['interface'])
            super().__init__(options, self._util_paw)
            self.__init_scapy_util()
    
    def __init_scapy_deauth_util(self):
        pass