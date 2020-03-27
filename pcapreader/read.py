#!/usr/bin/env python
# coding=utf-8


import time
import dpkt
from dpkt.ip import IP
from IPStream import IPStream
from TCPStream import TCPStream
from FragmentStream import FragmentStream
import socket
def read(pcap_path,ip_packet_dict,tcp_packet_dict,photo_packet_dict,Fragmentation_dict):
    """

    :param pcap_path: pcap文件路径（相对或绝对）
    :return: (timestamp,ip)的列表，其中timestamp为相对时间。
    """
    i=1
    j=0
    k=0
    default_end=0  # 默认分片的结束时间
    action_start=0  # 动作开始时间
    try:
        print("Read pcap started." + str(time.time()))  # pcap数据包开始处理的时间戳
        start = None  # pcap数据包第一个pkt的时间戳
        last = None  # 存放当前处理的pkt的上一个图片流pkt的相对时间戳
        with open(pcap_path, "rb") as deal_pcap:
            pcap = dpkt.pcap.Reader(deal_pcap)
            for ts, buf in pcap:
                if not start:  # 提取第一条pkt时间戳
                    start = ts
                try:
                    ip = dpkt.ethernet.Ethernet(buf).data
                except Exception:
                    continue
                ts = ts - start  # 计算相对时间
                if not isinstance(ip, IP):
                    continue
                if not isinstance(ip.data, dpkt.tcp.TCP):
                    continue
                tcp=ip.data
                tls=tcp.data
                RST = bool(tcp.flags & dpkt.tcp.TH_RST)  # 提取rst标志
                if tcp.sport==443 or tcp.dport == 443:  # 过滤掉非443端口
                    if ip and not RST:
                        if ip.src <ip.dst:  # 把双向的IP流量视为单向处理
                            src, dst = socket.inet_ntoa(ip.src), socket.inet_ntoa(ip.dst)
                        else:
                            src, dst = socket.inet_ntoa(ip.dst), socket.inet_ntoa(ip.src)
                        if (src, dst) not in ip_packet_dict.keys():  # IP流字典中不存在该二元组，创建新条目记录二元组
                            ip_stream = IPStream(src, dst, ts)
                            ip_packet_dict[(src, dst)] = ip_stream
                        else:  # 二元组已在IP流字典中存在，更新字典值
                            ip_stream = ip_packet_dict[(src, dst)]
                            if ts > ip_stream.end_time:
                                ip_stream.end_time = ts
                            elif ts < ip_stream.start_time:
                                ip_stream.start_time = ts
                        ip_stream.bytes += len(ip)
                        ip_stream.ip_datagrams.append((ts, ip))
                        if ip.src <ip.dst:  # 把双向TCP流量视为单向处理
                            sport, dport = tcp.sport, tcp.dport
                        else:
                            sport, dport = tcp.dport, tcp.sport
                        if (src, dst, sport, dport) not in tcp_packet_dict.keys():  # TCP流字典中不存在该四元组，创建新条目记录四元组
                            tcp_stream = TCPStream(src, dst, sport, dport, ip_stream, ts)
                            tcp_packet_dict[(src, dst, sport, dport)] = tcp_stream
                            ip_stream.tcp_streams.append(tcp_stream)
                        else:
                            tcp_stream = tcp_packet_dict[(src, dst, sport, dport)]  # TCP流字典中已存在该四元组
                            if ts > tcp_stream.end_time: #更新字典
                                tcp_stream.end_time = ts
                            elif ts < tcp_stream.start_time:
                                tcp_stream.start_time = ts
                            if (src, dst, sport, dport) in photo_packet_dict.keys():  # 若该四元组在图片流字典中
################################# 此段寻找分片请求报文
                                if tcp.dport == 80 and "pos=" in str(tls): # 分片请求报文的特征，长度291附近
                                    tcp_stream.fragment_number += 1
                                    tcp_stream.current_frag_attribute=ts
                                    tcp_stream.frag_ts.append(ts)
                                    ack=tcp.ack
                                    seq=tcp.seq
                                    tcp_data_len=len(tcp.data)
                                    fragment_stream = FragmentStream(src,dst,sport,dport, tcp.sport, tcp.dport, ip_stream,ack,seq,tcp_data_len,ts)
                                    Fragmentation_dict[(src,dst,sport,dport,ts)] = fragment_stream
                                if (src, dst, sport, dport, tcp_stream.current_frag_attribute) in Fragmentation_dict.keys(): # 如果当前图片流中保存的标记以及TCP四元组组成的五元组在分片流字典中已存在
                                    fragment_stream = Fragmentation_dict[(src, dst, sport, dport, tcp_stream.current_frag_attribute)] # 取出对应的分片流字典
                                    fin = bool(tcp.flags & dpkt.tcp.TH_FIN) # 取出当前pkt的FIN标志位
                                    if fragment_stream.fin_flag == 0:
                                        if fin : # 如果FIN第一次为真
                                            fragment_stream.end_time = ts
                                            fragment_stream.fin_flag = 1
                                        #否则开始组分片流
                                        elif tcp.dport==80:
                                            if fragment_stream.ack<tcp.ack:
                                                fragment_stream.bytes+=tcp.ack-fragment_stream.ack
                                                fragment_stream.ack=tcp.ack
                                                fragment_stream.end_time = ts
                                        elif tcp.sport==80:
                                            fragment_stream.end_time = ts
                                if last and float(ts - last) > 20:  # 判断此pkt与上一个处于图片流中的pkt的时间戳差值
                                    default_end = last
                                    action_start = ts
                                    during_time=default_end-action_start
                                last=ts
                        tcp_stream.bytes += len(tcp)
                        tcp_stream.tcp_packets.append((ts, tcp))
                        if tls[0:1]==b'\x16' and tls[1:3]==b'\x03\x01' and tls[5:6]==b'\x01':  # 判断tcp.data是否为谷歌街景图片流
                            if "ggpht.com" in str(tls):
                                if (src, dst, sport, dport) not in photo_packet_dict.keys():  # 若是，则将tcp_stream对象存入图片流字典
                                    photo_packet_dict[(src, dst, sport, dport)]=tcp_stream
    except Exception as e:
        print(e)
    print("Read pcap finished." + str(time.time()))  # 结束读取pcap文件的时间戳
    return photo_packet_dict.values(),during_time