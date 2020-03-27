#!/usr/bin/env python
# coding=utf-8
from dpkt.tcp import TCP
import socket


def inet_to_str(inet):
    try:
        return socket.inet_ntop(socket.AF_INET, inet)
    except ValueError:
        return socket.inet_ntop(socket.AF_INET6, inet)


def test_in_iRTT(ip_streams, pre_ts, tcp_target_seq):
    """
    判断两个数据分组之间的时间间隔是否在一个RTT时间内

    :param ip_streams: 游戏交互IP数据报文字典,
           pre_ts:前一个报文的时间戳,
           tcp_target_seq:目标数据分组的seq值,
    :return True:在一个RTT内传输完成
            False:不在一个RTT内传输完成
    """
    itag = 1
    flag_break = 0
    count = 0
    SYN_ts = 0
    ACK_ts = 0
    for ip_stream in ip_streams:
        for ts, ip in ip_stream.ip_datagrams:
            if not isinstance(ip.data, TCP):
                continue
            tcp = ip.data
            tcp_seq = tcp.seq
            #ip数据字典的第一个与第三个数据分组即为TCP三次握手的第一个与第三个数据分组
            #计算握手时的RTT
            count += 1
            if count == 1:
                SYN_ts = ts
            if count == 3:
                ACK_ts = ts
            irtt = ACK_ts - SYN_ts
            if tcp_seq == tcp_target_seq:
                if ts - pre_ts < irtt:
                    itag = 0
                    flag_break = 1
                    break
            else:
                continue
        if flag_break == 1:
            break
    return itag


def calculate_downloss_rate(ip_streams, target_ip_src, target_ip_dst):
    """
    计算游戏数据的下行链路丢包率
    :param ip_streams: 游戏交互IP数据报文字典,
           target_ip_src:游戏服务器IP地址,
           target_ip_dst:终端IP地址,
    :return 下行链路丢包率
    """
    pre_seq = 0
    pre_ts = 0
    loss_count = 0
    all_count = 0
    for ip_stream in ip_streams:
        for ts, ip in ip_stream.ip_datagrams:
            if not isinstance(ip.data, TCP):
                continue
            tcp = ip.data
            ip_src = inet_to_str(ip.src)
            ip_dst = inet_to_str(ip.dst)
            tcp_seq = tcp.seq
            tcp_len = len(tcp.data)
            if (ip_src == target_ip_src and ip_dst == target_ip_dst):
                all_count += 1
                if pre_seq == 0 and pre_ts == 0:
                    pre_seq = tcp_seq
                    pre_ts = ts
                if pre_seq < tcp_seq:
                    pre_seq = tcp_seq
                    pre_ts = ts
                if (pre_seq > tcp_seq) and (pre_seq != tcp_seq + tcp_len):
                    tcp_target_seq = tcp_seq + tcp_len
                    if test_in_iRTT(ip_streams, pre_ts, tcp_target_seq):
                        loss_count += 1
                    pre_seq = tcp_seq
                    pre_ts = ts
                if(pre_seq == tcp_seq + tcp_len):
                    pre_seq = tcp_seq
                    pre_ts = ts
    return loss_count / all_count
