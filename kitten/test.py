from scapy.all import (Dot11Beacon, Dot11, Dot11Elt, sniff)
from threading import Thread
import pandas
import time
import os

# scan for networks (scan paw)
# deauth network (attack paw)

networks = pandas.DataFrame(columns=["BSSID", "SSID", "dBm_Signal", "Channel", "Crypto"])
# set the index BSSID (MAC address of the AP)
networks.set_index("BSSID", inplace=True)

def callback(packet):
    if packet.haslayer(Dot11Beacon):
        # extract the MAC address of the network
        bssid = packet[Dot11].addr2
        # get the name of it
        try:
            ssid = packet[Dot11Elt].info.decode()
        except UnicodeDecodeError:
            ssid = packet[Dot11Elt].info
        
        try:
            dbm_signal = packet.dBm_AntSignal
        except:
            dbm_signal = "N/A"
        # extract network stats
        stats = packet[Dot11Beacon].network_stats()
        # get the channel of the AP
        channel = stats.get("channel")
        # get the crypto
        crypto = stats.get("crypto")
        networks.loc[bssid] = (ssid, dbm_signal, channel, crypto)

def print_all():
    while True:
        os.system('clear')
        print(networks)
        time.sleep(0.5)

def change_channel():
    ch = 1
    while True:
        os.system(f"iwconfig {interface} channel {ch}")
        # switch channel from 1 to 14 each 0.5s
        ch = ch % 14 + 1
        time.sleep(0.5)

def main():
    # interface name, check using iwconfig
    interface = "wlx00c0ca98dc79"
    # start the thread that prints all the networks
    printer = Thread(target=print_all)
    printer.daemon = True
    printer.start()
    # start sniffing
    sniff(prn=callback, iface=interface)
    

printed = set()
prev_length = 0
networks = {}

def print_found():
    global prev_length
    if len(networks.keys()) is not prev_length:
        prev_length = len(networks.keys())
        last = list(networks.keys())[-1]
        print(f'{last}\t{networks[last]["ssid"]}')
        

def handle_packet(packet):
    if packet.haslayer(Dot11Beacon):
        
        bssid = packet[Dot11].addr2
        
        try:
            ssid = packet[Dot11Elt].info.decode()
        except UnicodeDecodeError:
            ssid = packet[Dot11Elt].info
        
        try:
            dbm_signal = packet.dBm_AntSignal
        except:
            dbm_signal = "N/A"
        
        stats = packet[Dot11Beacon].network_stats()
        
        channel = stats.get("channel")
        
        crypto = stats.get("crypto")

        if bssid not in networks.keys():
            networks[bssid] = {
                'ssid': ssid,
                'dbm_signal': dbm_signal,
                'channel': channel,
                'crypto': crypto
            }
        
        print_found()


def get_wireless_networks():
    sniff(prn=handle_packet, iface="wlx00c0ca98dc79")

get_wireless_networks()