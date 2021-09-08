import socket
import threading
import sys
import json
from time import sleep
import timeit
from multiprocessing.dummy import Pool

# target = socket.gethostbyname(sys.argv[1])

def is_port_open(port: int) -> bool:
    print(port)

    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    socket.setdefaulttimeout(1)
    
    result = s.connect_ex((target, port))
    if result == 0:
        return port
    
    s.close()
    return False

def get_most_common_ports() -> list:
    f = open('./data/port_data.json', 'r')
    data = json.load(f)
        
    return data['most_common_ports']

def get_open_ports_threading() -> list:

    open_ports = []
    most_common_ports = get_most_common_ports()


    try:

        def append_port_if_open(port: int):
            if is_port_open(port): open_ports.append(port)

        while len(most_common_ports) != 0:
            port = most_common_ports[0]
            if threading.active_count() >= 100:
                sleep(0.1)
            else:
                t = threading.Thread(target=append_port_if_open, args=[port])
                t.start()
                most_common_ports.pop(0)

        while threading.active_count() != 1:
            sleep(1)

    except socket.gaierror:
        print('Hostname could not be resolved.')
    except socket.error:
        print('Server does not respond.')

    return open_ports


# implement this
# def get_open_ports_multiprocessing() -> list:
#     with Pool(75) as p:
#         return p.map(is_port_open, get_most_common_ports())


# t1 = timeit.default_timer()
# print(list(filter(None, get_open_ports_multiprocessing())))
# print(timeit.default_timer() - t1)

import argparse

parser = argparse.ArgumentParser(description="Glücksspiel")
subparsers = parser.add_subparsers()
# wuerfeln-Befehle
parser_wuerfeln = subparsers.add_parser("wuerfeln", help="Simulation eines Würfels")
parser_wuerfeln.add_argument("--wuerfe", "-w", type=int, default=1, help="Anzahl der Würfe")
parser_wuerfeln.add_argument("--seiten", "-s", type=int, choices=[6, 12, 20], default=6, help="Seitenanzahl des Würfels")
parser_wuerfeln.add_argument("--schummeln", "-sch", action="store_true", help="Schummel-Flag")
parser_wuerfeln.set_defaults(func=wuerfeln_fct)
# muenze-Befehl
parser_muenze = subparsers.add_parser("muenze", help="Simulation von Münzwürfen")
parser_muenze.add_argument("--wuerfe", "-w", type=int, default=1, help="Anzahl der Würfe")
parser_muenze.set_defaults(func=muenze_fct)
# lotto-Befehl
parser_lotto = subparsers.add_parser("lotto", help="Simulation von Lotto 6 aus 49")
parser_lotto.add_argument("--zahlen", "-z", type=int, nargs=6, choices=np.arange(1, 50), required=True, help="Deine 6 Zahlen")
parser_lotto.add_argument(    "--superzahl", "-sz", type=int, choices=np.arange(0, 10), required=True, help="Superzahl")
parser_lotto.set_defaults(func=lotto_fct)
args = parser.parse_args()
try:
    args.func(args)
except AttributeError:
    parser.print_help()
    parser.exit()