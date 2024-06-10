import requests


class AccessPoint:
    def __init__(self, bssid, ssid, dbm_signal, channel, type):
        self._bssid = bssid
        self._ssid = ssid
        self._dbm_signal = dbm_signal
        self._channel = channel
        self.type = type

    @staticmethod
    def fetch_and_map_whitelist(name):
        response = requests.get(f'https://bakalauras.onrender.com/whitelist/{name}/accesspoints')
        if response.status_code == 200:
            data = response.json()
            if data:
                access_points = [AccessPoint(ap['bssid'], ap['ssid'], 0, 0, 0) for ap in data]
                return access_points
            else:
                print("WhiteListAP not found")
                return None
        else:
            print(f"Error: {response.status_code}")
            return None

    @staticmethod
    def is_in_whitelist(access_point, whitelist):
        for ap in whitelist:
            if ap._bssid == access_point._bssid and ap._ssid == access_point._ssid:
                return True
        return False

    @staticmethod
    def is_duplicate(found_ap, known_ap_list):
        for knownAP in known_ap_list:
            if knownAP._bssid == found_ap._bssid and knownAP._ssid == found_ap._ssid:
                return True
        return False

    @staticmethod
    def is_in_known_ap_list(found_ap, known_ap_list):
        for knownAP in known_ap_list:
            if knownAP._bssid == found_ap._bssid:
                return True
        return False

    @property
    def bssid(self):
        return self._bssid

    @property
    def ssid(self):
        return self._ssid

    @property
    def dbm_signal(self):
        return self._dbm_signal

    @property
    def channel(self):
        return self._channel
