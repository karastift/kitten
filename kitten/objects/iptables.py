from subprocess import Popen


class Iptables:

    def __init__(self) -> None:
        pass
    
    def insert_forward_rule(self, queue_num: int):
        Popen(f'iptables -I FORWARD -j NFQUEUE --queue-num {queue_num}'.split(' ')).wait()
    
    def flush_rules(self):
        Popen('iptables --flush'.split(' ')).wait()