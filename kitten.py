import argparse

Parser = argparse.ArgumentParser(description='Process some integers.')
Parser.add_argument('-v', action='store_true', help='Run verbosely.')
Parser.add_argument('-v', action='store_true', help='Run verbosely.')

class Kitten:

    options = {
        "port_range": 65535,
        "verbose": False,
    }

    def __init__(self) -> None:
        print(self.get_parsed_args())

    def get_parsed_args(self):
        return Parser.parse_args()

if __name__ == '__main__':
    Kitten()