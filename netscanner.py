import scapy.all as scapy
import optparse
import netifaces as ni

def banner(adress1):
    print(f"""
    █▀▀▄ █▀▀ ▀▀█▀▀   █▀▀ █▀▀ █▀▀█ █▀▀▄ █▀▀▄ █▀▀ █▀▀█
    █░░█ █▀▀ ░░█░░   ▀▀█ █░░ █▄▄█ █░░█ █░░█ █▀▀ █▄▄▀
    ▀░░▀ ▀▀▀ ░░▀░░   ▀▀▀ ▀▀▀ ▀░░▀ ▀░░▀ ▀░░▀ ▀▀▀ ▀░▀▀
                                                                                𝗴𝗶𝘁𝗵𝘂𝗯: 𝘀𝘄𝗶𝗽𝗮𝘅
𝕟𝕖𝕥-𝕤𝕔𝕒𝕟𝕟𝕖𝕣
Your IP Adress: {adress1}
Example: python3 netscanner.py -i 10.0.2.0/24
--------------------------------------------------------------
""")

adress1 = ip2 = ni.ifaddresses('eth0')[ni.AF_INET][0]['addr']


banner(adress1)

def get_input():
    parse_object = optparse.OptionParser()
    parse_object.add_option("-i", "--ipaddress", dest="ip_address", help="Enter IP Address")

    (user_input, arguments) = parse_object.parse_args()

    if not user_input.ip_address:
        print("Enter IP Address")

    return user_input


def scan_network(ip):
    arp_request_packet = scapy.ARP(pdst=ip)
    broadcast_packet = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    combined_packet = broadcast_packet / arp_request_packet
    (answered_list, unanswered_list) = scapy.srp(combined_packet, timeout=1 , verbose=0)
    answered_list.summary()


user_ip_address = get_input()
scan_network(user_ip_address.ip_address)
