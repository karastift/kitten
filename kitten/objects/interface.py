import subprocess

class Interface:
    __name = ''
    __mode = ''

    def __init__(self, name: str, mode: str) -> None:
        self.__name = name
        self.__mode = mode

    def __set_mode(self, mode: str) -> None:
        '''
        ### Do not use this method in your own scripts! The method is shall only be used in the Interface class It will only set the attribute of the class to the mode. It won't change the behaviour of the device.
        '''
        self.__mode = mode

    def get_name(self) -> str:
        return self.__name

    def get_mode(self) -> str:
        return self.__mode
    
    def switch_mode(self, mode: str):
        assert mode in {'monitor', 'managed'}, f'Invalid mode "{mode}". Please choose "managed" or "monitor".'
        try:
            process = subprocess.Popen(f'ifconfig {self.__name} down'.split(' '))
            code = process.wait()

            if code == 255:
                process.kill()
                raise PermissionError


            subprocess.Popen(f'iwconfig {self.__name} mode {mode}'.split(' ')).wait()
            subprocess.Popen(f'ifconfig {self.__name} up'.split(' ')).wait()

            self.__set_mode(mode)


        except PermissionError:
            self.__util_paw.print_permission_error()
            exit()