import argparse

class ArgPaw:

    options = None

    kitten_parser = None
    scan_parser = None

    def __init__(self) -> None:
        self.kitten_parser = self.__create_parsers()
        self.options = self.kitten_parser.parse_args().__dict__

    def __create_parsers(self) -> argparse.ArgumentParser:

        kitten_parser = argparse.ArgumentParser(
            epilog='\033[1mMade by kara.\033[0m',
            add_help=''
        )

        self.__add_costum_help_arg(kitten_parser)

        kitten_parser.add_argument(
            '-v', '--verbose',
            action='store_true',
            help='Run verbosely.',
        )

        subparsers = kitten_parser.add_subparsers(
            metavar='command',
            dest='cmd',
            required=True,
        )

        self.__configure_scan_parser(subparsers)


        return kitten_parser
    
    def __configure_scan_parser(self, subparsers: argparse._SubParsersAction):
        scan_parser = subparsers.add_parser(
            name='scan',
            help='Scan a target for open ports.'
        )
        scan_parser.add_argument(
            dest='target',
            type=str,
            help='Define the target that is to be scanned.',
        )
        scan_parser.add_argument(
            '-mt', '--maxthreads',
            type=int,
            default=100,
            help='Max number of threads that will be opened at the same time.',
        )
        scan_parser.add_argument(
            '-mp', '--maxprocesses',
            type=int,
            default=75,
            help='Max number of processes that will be opened at the same time.',
        )
    
    def __add_costum_help_arg(self, parser: argparse.ArgumentParser):
        parser.add_argument(
            '-h', '--help',
            action=argparse._HelpAction,
            help='Show this help message and exit.',
        )

    def get_options(self):
        return self.options