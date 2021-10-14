import os
import json


def get_most_common_ports() -> list:
    path = os.path.join(os.path.dirname(__file__), '../data/port_data.json')
    f = open(path, 'r')
    data = json.load(f)
        
    return data['most_common_ports']