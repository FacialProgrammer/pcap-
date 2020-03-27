#!/usr/bin/env python
# coding=utf-8

from dpkt.tcp import TCP


class TCPStream(object):

    def __init__(self, src, dst, src_port, dst_port, ip_stream, ts):
        self.src = src
        self.dst = dst
        self.sport = src_port
        self.dport = dst_port
        self.ip_stream = ip_stream
        self.start_time = ts
        self.end_time = ts
        self.bytes = 0
        self.number=0
        self.tcp_packets = []
        self.fragment_number = 0
        self.current_frag_attribute = 0
        self.frag_ts = []

    def __len__(self):
        return self.bytes

    @property
    def duration(self):
        return self.end_time - self.start_time
