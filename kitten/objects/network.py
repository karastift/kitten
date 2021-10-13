class Network:
    _bssid = ''
    _ssid = ''
    _dbm_signal = ''
    _channel = ''
    _crypto = set()

    def __init__(self,
        bssid: str,
        ssid: str,
        dbm_signal: str,
        channel: str,
        crypto: str,
    ) -> None:
        self._bssid = bssid
        self._ssid = ssid
        self._dbm_signal = dbm_signal
        self._channel = channel
        self._crypto = crypto

    def get_bssid(self) -> str:
        return self._bssid

    def get_ssid(self) -> str:
        return self._ssid

    def get_dbm_signal(self) -> str:
        return self._dbm_signal

    def get_channel(self) -> str:
        return self._channel

    def get_crypto(self) -> set:
        return self._crypto