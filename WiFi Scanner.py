import argparse
import json
from threading import Thread
from scapy.all import *
import pandas
import requests
import math
import os
import time

from colorama import Fore, Style
from scapy.layers.dot11 import Dot11Beacon, Dot11, Dot11Elt

from access_point import AccessPoint

parser = argparse.ArgumentParser(description='WiFi Scanner')
parser.add_argument('-s', '--ScannerName', required=True, type=str, help='the name of the scanner')
parser.add_argument('-wl', '--WhiteList', required=True, type=str, help='the name of the whitelist')
parser.add_argument('-r', '--Range', nargs='+', type=float, help='the range of channels to scan (2.4, 5.0)')
args = parser.parse_args()
scannerName = args.ScannerName
whitelist_name = args.WhiteList
rangeScan = args.Range
networks = pandas.DataFrame(columns=["BSSID", "SSID", "dBm_Signal", "Channel", "Crypto", "Distance"])
networks.set_index("BSSID", inplace=True)
stop_sniffing = False


def get_configuration():
    response = requests.get(f'https://bakalauras.onrender.com/scanners/configuration/{scannerName}')
    if response.status_code == 200:
        data = response.json()
        config = {
            "scanInterval": data.get("scanInterval"),
            "scanSecurityType": data.get("scanSecurityType"),
            "scanUnidentifiedAP": data.get("scanUnidentifiedAP")
        }
        return config
    else:
        print(f"Error: {response.status_code}")
        return None


def callback(packet):
    if packet.haslayer(Dot11Beacon):
        bssid = packet[Dot11].addr2
        ssid = packet[Dot11Elt].info.decode()
        if ssid == "":
            return
        try:
            dbm_signal = packet.dBm_AntSignal
        except:
            dbm_signal = 0
        stats = packet[Dot11Beacon].network_stats()
        channel = stats.get("channel")
        crypto = stats.get("crypto")
        found_AP = AccessPoint(bssid, ssid, dbm_signal, channel)

        if not is_in_whitelist(found_AP, access_points):
            send_notification("0", scannerName, bssid, ssid, channel, dbm_signal)
            networks.loc[found_AP.bssid] = (found_AP.ssid, found_AP.dbm_signal, found_AP.channel, None, None, 1)
        else:
            networks.loc[found_AP.bssid] = (found_AP.ssid, found_AP.dbm_signal, found_AP.channel, None, None, 0)


def send_notification(notificationType, scannerName, bssid, ssid, channel, rssi):
    url = "https://bakalauras.onrender.com/notifications/create"
    headers = {'Content-Type': 'application/json'}
    data = {
        "notificationType": notificationType,
        "scannerName": scannerName,
        "bssid": bssid,
        "ssid": ssid,
        "channel": channel,
        "rssi": rssi
    }
    response = requests.post(url, headers=headers, data=json.dumps(data))
    if response.status_code == 200:
        print("Notification sent successfully.")
        tempAP = AccessPoint(bssid, ssid, rssi, channel)
        access_points.append(tempAP)
    else:
        print(f"Failed to send notification. Status code: {response.status_code}, Message: {response.text}")


def print_all():
    while True:
        os.system("clear")
        for index, row in networks.iterrows():
            if row["Type"] == 1:
                print(str(row) + Fore.RED + " [UNKNOWN]" + Style.RESET_ALL)
            else:
                print(str(row) + Fore.GREEN + " [KNOWN]" + Style.RESET_ALL)
        time.sleep(0.5)


def change_channel():
    if 2.4 in rangeScan and 5.0 in rangeScan:
        ch = 1
        max_ch = 165
    elif 2.4 in rangeScan:
        ch = 1
        max_ch = 14
    elif 5.0 in rangeScan:
        ch = 36
        max_ch = 165

    while True:
        os.system(f"iwconfig {interface} channel {ch}")
        if ch == max_ch:
            stop_sniffing = True
            break
        else:
            ch += 1
        time.sleep(0.5)


def is_in_whitelist(access_point, whitelist):
    for ap in whitelist:
        if ap._bssid == access_point._ssid and ap._ssid == access_point._bssid:
            return True
    return False


def stop_sniffing_fillter(packet):
    return stop_sniffing


if __name__ == "__main__":

    config = get_configuration()
    if config is not None:
        print(config)
        access_points = AccessPoint.fetch_and_map_whitelist(whitelist_name)
        found_aps = []
        if access_points is not None:
            for ap in access_points:
                print(ap._bssid, ap._ssid, ap._dbm_signal, ap._channel)
        input("Press any key to continue...")
        interface = "wlan0mon"

        printer = Thread(target=print_all)
        printer.daemon = True
        printer.start()

        channel_changer = Thread(target=change_channel)
        channel_changer.daemon = True
        channel_changer.start()
        while True:
            stop_sniffing = False
            found_aps.clear()
            sniff(prn=callback, iface=interface, stop_filter=stop_sniffing_fillter)
            time.sleep(config["scanInterval"])
