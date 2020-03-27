#!/usr/bin/env python
# coding=utf-8

import xlwt
from dpkt.tcp import TCP
import socket


def inet_to_str(inet):
    try:
        return socket.inet_ntop(socket.AF_INET, inet)
    except ValueError:
        return socket.inet_ntop(socket.AF_INET6, inet)


def calculate_delay(ip_streams, target_ip_src, target_ip_dst, target_tcp_ack, pkt_seq_ts):
    """
    计算请求与响应报文时延
    :param ip_streams: 游戏交互IP数据报文字典,
           target_ip_src:游戏服务器IP地址,
           target_ip_dst:终端IP地址,
           target_tcp_ack:响应报文的ack,
           pkt_seq_ts:请求报文的时间戳
    :return delay
    """
    delay = 0
    for ip_stream in ip_streams:
        for ts, ip in ip_stream.ip_datagrams:
            if isinstance(ip.data, TCP):
                tcp = ip.data
                ip_src = inet_to_str(ip.src)
                ip_dst = inet_to_str(ip.dst)
                tcp_ack = tcp.ack
                tcp_time = ts
                if (
                        ip_src == target_ip_src and ip_dst == target_ip_dst
                        and tcp_ack == target_tcp_ack
                ):
                    delay = tcp_time - pkt_seq_ts
                    break
        if delay != 0:
            break
    return delay


def retransmission_test(ip_streams, target_ip_src, target_ip_dst, target_tcp_src_port, target_tcp_dst_port,
                        target_tcp_seq, target_tcp_ack):
    """
    判断请求报文是否重传
    :param ip_streams: 游戏交互IP数据报文字典,
           target_ip_src:游戏服务器IP地址,
           target_ip_dst:终端IP地址,
           target_tcp_src_port:游戏服务器TCP端口号,
           target_tcp_dst_port:终端TCP端口号,
           target_tcp_seq:报文的seq,
           target_tcp_ack:报文的ack
    :return True:重传报文,
            False:未重传
    """
    count = 0
    for ip_stream in ip_streams:
        for ts, ip in ip_stream.ip_datagrams:
            if not isinstance(ip.data, TCP):
                continue
            tcp = ip.data
            ip_src = inet_to_str(ip.src)
            ip_dst = inet_to_str(ip.dst)
            tcp_src_port = tcp.sport
            tcp_dst_port = tcp.dport
            tcp_ack = tcp.ack
            tcp_seq = tcp.seq
            if (ip_src == target_ip_src and ip_dst == target_ip_dst
                    and tcp_src_port == target_tcp_src_port
                    and tcp_dst_port == target_tcp_dst_port
                    and tcp_seq == target_tcp_seq
                    and tcp_ack == target_tcp_ack):
                count += 1
            else:
                continue
    if count == 1:
        return True
    else:
        return False


def calculate_MTP(ip_streams, target_ip_src, target_ip_dst, file_name):
    """
    计算整个交互过程中平均MTP值
    :param ip_streams: 游戏交互IP数据报文字典,
           target_ip_src:游戏服务器IP地址,
           target_ip_dst:终端IP地址,
    :return 平均MTP
    """
    # workbook = xlwt.Workbook(encoding='utf-8')
    # data_sheet = workbook.add_sheet('analysis')
    # title = 'MTP(ms)'
    # data_sheet.write(0, 0, title)
    row_count = 1
    count_all = 0
    MTP_all = 0
    # delay_min = 10000
    # delay_max = 0
    for ip_stream in ip_streams:
        for ts, ip in ip_stream.ip_datagrams:
            if not isinstance(ip.data, TCP):
                continue
            tcp = ip.data
            ip_src = inet_to_str(ip.src)
            ip_dst = inet_to_str(ip.dst)
            tcp_src_port = tcp.sport
            tcp_dst_port = tcp.dport
            tcp_ack = tcp.ack
            tcp_seq = tcp.seq
            tcp_time = ts
            tcp_segment_len = len(tcp.data)
            if (
                    ip_src == target_ip_dst
                    and ip_dst == target_ip_src
                    and tcp_segment_len > 0
            ):  # 终端向服务器发送的携带数据的报文
                target_tcp_ack = tcp_seq + tcp_segment_len
                pkt_seq_ts = tcp_time
                if retransmission_test(ip_streams, ip_src, ip_dst, tcp_src_port, tcp_dst_port, tcp_seq, tcp_ack) == 1:
                    MTP = calculate_delay(ip_streams, target_ip_src, target_ip_dst, target_tcp_ack, pkt_seq_ts) * 1000
                    # if delay_max < MTP : delay_max = MTP
                    # if delay_min > MTP : delay_min = MTP
                    if MTP == 0:
                        continue
                        # print('%s:%s-->%s:%s seq = %s, ack = %s, time = %f, len = %s'
                        #       % (ip_src, tcp_src_port, ip_dst, tcp_dst_port, tcp_seq, tcp_ack, tcp_time,
                        #          tcp_segment_len), file=data)
                    else:
                        # data_sheet.write(row_count, 0, '%f' % MTP)
                        count_all += 1
                        MTP_all += MTP
                        row_count += 1
                else:
                    continue
                    # print('%s:%s-->%s:%s seq = %s, ack = %s, time = %f, len = %s'
                    #       % (ip_src, tcp_src_port, ip_dst, tcp_dst_port, tcp_seq, tcp_ack, tcp_time, tcp_segment_len),
                    #       file=data)
            else:
                continue
                # print('%s:%s-->%s:%s seq = %s, ack = %s, time = %f, len = %s'
                #       % (ip_src, tcp_src_port, ip_dst, tcp_dst_port, tcp_seq, tcp_ack, tcp_time, tcp_segment_len),
                #       file=data)
    average_MTP = MTP_all / count_all
    #print('%f'%(delay_max - delay_min))
    # print(count_all)
    # print('average_rtt = %f' % average_MTP)
    # workbook.save(file_name + '_MTP.xls')
    return average_MTP
