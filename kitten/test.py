import netifaces
import netaddr
from pprint import pprint as print
import subprocess



def get_interface_info():
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

def switch_interface(eigentlich_self_inteface, mode: str):
    assert mode in {'monitor', 'managed'}, 'Invalid mode.'

    subprocess.Popen(f'sudo ifconfig {eigentlich_self_inteface} down'.split(' ')).wait()
    subprocess.Popen(f'sudo iwconfig {eigentlich_self_inteface} mode {mode}'.split(' ')).wait()
    subprocess.Popen(f'sudo ifconfig {eigentlich_self_inteface} up'.split(' ')).wait()

info = get_interface_info()
print(info)

switch_interface(info[0]['name'], 'managed')

info = get_interface_info()
print(info)