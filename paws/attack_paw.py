from paws.util_paw import UtilPaw

class AttackPaw:

    util_paw = None

    def __init__(self, options, util_paw: UtilPaw) -> None:
        self.util_paw = util_paw
    
    