#!/usr/bin/env python
# coding=utf-8

import dpkt
from dpkt.ip import IP
from dpkt.tcp import TCP
#from LinuxCookedProcess import linux_cooked_processpip
import subprocess
import sys
import os
import re
import time
import socket
from IPStream import IPStream
from TCPStream import TCPStream
#from FragmentStream import FragmentStream


# CONTENT_TYPE_PATTERN = re.compile(r"Content-Type:\s*(.+?)\s")
# CONTENT_LENGTH_PATTERN = re.compile(r"Content-Length:\s*(\d+?)\s")
ip_packet_dict = dict()
tcp_packet_dict = dict()
photo_packet_dict=dict()
Fragmentation_dict=dict()
array=[]
array2=[]
array3=[]

def read(pcap_path):
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
        num=0
        temp=""
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
                if tcp.sport==80 or tcp.dport == 80:  # 过滤掉非80端口
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
                       # print(ip_stream.ip_datagrams)
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
                        tcp_stream.bytes += len(tcp)
                        tcp_stream.tcp_packets.append((ts, tcp))

                        if tls[0:3]==b'GET'and tls[4:9]==b'/?qt=':
                                array.append(ts)
                                temp+=str(tls)
                                if (src, dst, sport, dport) not in photo_packet_dict.keys():
                                    photo_packet_dict[(src, dst, sport, dport)]=tcp_stream
                        if "Host: sv0.map.bdimg.com" in str(tls):
                                num+=1

    except Exception as e:
        print(e)
    print("Read pcap finished." + str(time.time()))  # 结束读取pcap文件的时间戳
    return photo_packet_dict.values(),num,temp,ip_packet_dict.values()
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

def calcu_sub_str_num(mom_str,sun_str):
    count=0
    for i in range(len(mom_str)-1): #因为i的下标从0开始，所以len（mom_str）-1
      if mom_str[i:i+len(sun_str)] == sun_str:
          count=count+1
    return count
def caculate(photo_streams,num):
    print("z总共包含图片个数：", num)
    i=1
    start = 999999
    end = 0
    temp=0
    for photo_stream in photo_streams:
        tcp_stream = tcp_packet_dict[(photo_stream.src, photo_stream.dst, photo_stream.sport, photo_stream.dport)]
        if tcp_stream.start_time<start:
            start = tcp_stream.start_time
        if tcp_stream.end_time>end:
            end = tcp_stream.end_time
        print("第",i,"个图片流")
        print(tcp_stream.src, " -> ",tcp_stream.dst,"端口：",tcp_stream.sport," -> ",tcp_stream.dport,"     开始时间(s):",tcp_stream.start_time,"结束时间(s):",tcp_stream.end_time,"持续时间(s):",tcp_stream.duration,"流大小(bytes):",tcp_stream.bytes)
        i+=1
        temp=tcp_stream.end_time
#    print("街景加密图片流的传输时延为",end-start,"秒")
    return temp
# file='F:\\code\\实验一测试数据（只记录场景）\\test1_官方街景.pcap'

file='F:\\fixpos1.pcap'
photo_streams,num,listlink,dict=read(file)
temp=caculate(photo_streams,num)
print("图片流应用层请求时间：",array[0],"图片流应用层响应时间：",temp,"持续时间：",temp-array[0])
print("下行链路丢包率：",calculate_downloss_rate(dict,"180.97.33.91","192.168.0.186")+calculate_downloss_rate(dict,"192.168.0.186","180.97.33.91"))
#180.97.33.91 115.239.210.232

