#!/usr/bin/env python
# coding=utf-8


class IPStream(object):

    def __init__(self, src, dst, ts):
        self.id = 0
        self.src = src
        self.dst = dst
        self.bytes = 0
        self.start_time = ts
        self.end_time = ts
        self.ip_datagrams = []
        self.tcp_streams = []

    def __len__(self):
        return self.bytes

    @property
    def duration(self):
        return self.end_time - self.start_time
