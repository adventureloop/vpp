#!/usr/bin/env python3

import abc

from scapy.layers.l2 import Ether
from scapy.packet import Raw
from scapy.layers.inet import IP, UDP
from scapy.layers.inet6 import IPv6
from scapy.contrib.mpls import MPLS


class BridgeDomain(metaclass=abc.ABCMeta):
    """Bridge domain abstraction"""

    @property
    def frame_request(self):
        """Ethernet frame modeling a generic request"""
        return (
            Ether(src="00:00:00:00:00:01", dst="00:00:00:00:00:02")
            / IP(src="1.2.3.4", dst="4.3.2.1")
            / UDP(sport=10000, dport=20000)
            / Raw("\xa5" * 100)
        )

    @property
    def frame_reply(self):
        """Ethernet frame modeling a generic reply"""
        return (
            Ether(src="00:00:00:00:00:02", dst="00:00:00:00:00:01")
            / IP(src="4.3.2.1", dst="1.2.3.4")
            / UDP(sport=20000, dport=10000)
            / Raw("\xa5" * 100)
        )

    @abc.abstractmethod
    def ip_range(self, start, end):
        """range of remote ip's"""
        pass

    @abc.abstractmethod
    def encap_mcast(self, pkt, src_ip, src_mac, vni):
        """Encapsulate mcast packet"""
        pass

    @abc.abstractmethod
    def encapsulate(self, pkt, vni):
        """Encapsulate packet"""
        pass

    @abc.abstractmethod
    def decapsulate(self, pkt):
        """Decapsulate packet"""
        pass

    @abc.abstractmethod
    def check_encapsulation(self, pkt, vni, local_only=False):
        """Verify the encapsulation"""
        pass

    def assert_eq_pkts(self, pkt1, pkt2):
        """Verify the Ether, IP, UDP, payload are equal in both
        packets
        """
        self.assertEqual(pkt1[Ether].src, pkt2[Ether].src)
        self.assertEqual(pkt1[Ether].dst, pkt2[Ether].dst)
        if MPLS in pkt1 or MPLS in pkt2:
            self.assertEqual(pkt1[MPLS].label, pkt2[MPLS].label)
            self.assertEqual(pkt1[MPLS].cos, pkt2[MPLS].cos)
            self.assertEqual(pkt1[MPLS].ttl, pkt2[MPLS].ttl)
        if IP in pkt1 or IP in pkt2:
            self.assertEqual(pkt1[IP].src, pkt2[IP].src)
            self.assertEqual(pkt1[IP].dst, pkt2[IP].dst)
        elif IPv6 in pkt1 or IPv6 in pkt2:
            self.assertEqual(pkt1[IPv6].src, pkt2[IPv6].src)
            self.assertEqual(pkt1[IPv6].dst, pkt2[IPv6].dst)
        self.assertEqual(pkt1[UDP].sport, pkt2[UDP].sport)
        self.assertEqual(pkt1[UDP].dport, pkt2[UDP].dport)
        self.assertEqual(pkt1[Raw], pkt2[Raw])

    def test_decap(self):
        """Decapsulation test
        Send encapsulated frames from pg0
        Verify receipt of decapsulated frames on pg1
        """

        encapsulated_pkt = self.encapsulate(self.frame_request, self.single_tunnel_vni)

        self.pg0.add_stream(
            [
                encapsulated_pkt,
            ]
        )

        self.pg1.enable_capture()

        self.pg_start()

        # Pick first received frame and check if it's the non-encapsulated
        # frame
        out = self.pg1.get_capture(1)
        pkt = out[0]
        self.assert_eq_pkts(pkt, self.frame_request)

    def test_encap(self):
        """Encapsulation test
        Send frames from pg1
        Verify receipt of encapsulated frames on pg0
        """
        self.pg1.add_stream([self.frame_reply])

        self.pg0.enable_capture()

        self.pg_start()

        # Pick first received frame and check if it's correctly encapsulated.
        out = self.pg0.get_capture(1)
        pkt = out[0]
        self.check_encapsulation(pkt, self.single_tunnel_vni)

        payload = self.decapsulate(pkt)
        self.assert_eq_pkts(payload, self.frame_reply)

    def test_ucast_flood(self):
        """Unicast flood test
        Send frames from pg3
        Verify receipt of encapsulated frames on pg0
        """
        self.pg3.add_stream([self.frame_reply])

        self.pg0.enable_capture()

        self.pg_start()

        # Get packet from each tunnel and assert it's correctly encapsulated.
        out = self.pg0.get_capture(self.n_ucast_tunnels)
        for pkt in out:
            self.check_encapsulation(pkt, self.ucast_flood_bd, True)
            payload = self.decapsulate(pkt)
            self.assert_eq_pkts(payload, self.frame_reply)

    def test_mcast_flood(self):
        """Multicast flood test
        Send frames from pg2
        Verify receipt of encapsulated frames on pg0
        """
        self.pg2.add_stream([self.frame_reply])

        self.pg0.enable_capture()

        self.pg_start()

        # Pick first received frame and check if it's correctly encapsulated.
        out = self.pg0.get_capture(1)
        pkt = out[0]
        self.check_encapsulation(
            pkt, self.mcast_flood_bd, local_only=False, mcast_pkt=True
        )

        payload = self.decapsulate(pkt)
        self.assert_eq_pkts(payload, self.frame_reply)

    def test_mcast_rcv(self):
        """Multicast receive test
        Send 20 encapsulated frames from pg0 only 10 match unicast tunnels
        Verify receipt of 10 decap frames on pg2
        """
        mac = self.pg0.remote_mac
        ip_range_start = 10
        ip_range_end = 30
        mcast_stream = [
            self.encap_mcast(self.frame_request, ip, mac, self.mcast_flood_bd)
            for ip in self.ip_range(ip_range_start, ip_range_end)
        ]
        self.pg0.add_stream(mcast_stream)
        self.pg2.enable_capture()
        self.pg_start()
        out = self.pg2.get_capture(10)
        for pkt in out:
            self.assert_eq_pkts(pkt, self.frame_request)
