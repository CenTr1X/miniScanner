from data import *
from scapy.all import IP, TCP, ICMP, sr, sr1
from numpy import array_split
from threading import Thread
import socket
import sys

'''
description: 端口扫描主接口
param {type} 
    ip{string} 目的ip地址
    timeout{int} 超时阈值
    scan_mod{string:"all"|"valuable"} 扫描模式，全部扫描或按常用端口扫描
    start{int} 起始端口，全扫描模式下使用
    end{int} 末尾端口，全扫描模式下使用
    top{int:50|100|1000} 扫描前top个采用端口，部分扫描模式下使用
return {type} 
    res{dict} 扫描结果 key为端口，value为端口状态
'''
def ports_scan(ip, scan_mod, timeout, start, end, top, threads_count):
    print(ip, scan_mod, timeout, start, end, top, threads_count)
    if scan_mod == "all":  # 全端口扫描
        target = [x for x in range(start, end+1)]
    elif scan_mod == "valuable":  #部分端口扫描
        target = globals()['top' + str(top) + '_ports']
    else:
        print("scan_mod must be set as 'all' or 'valuable'")
        return
    res = start_ports_scan(ip, target, timeout, threads_count)
    return res

'''
description: 启动扫描，生成线程
param {type} 
    ip{string} 目的ip地址
    target{list} 目标端口列表
    timeout{int} 超时阈值
    threads_count{int} 线程数
return {type} 
    res{dict} 扫描结果 key为端口，value为端口状态
'''
def start_ports_scan(ip, target, timeout, threads_count):
    dst_ip = IP(dst=ip)
    res = {k:"" for k in target}
    threads = []
    print(target, threads_count)
    target_per_thread = array_split(target, threads_count)
    for target_ports in target_per_thread:
        threads.append(Thread(target=ports_scan_per_thread, args=(dst_ip, target_ports, res, timeout)))
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    return res

'''
description: 线程扫描方法
param {type} 
    dst_ip{object} 目的ip
    target{list} 目标端口列表
    res{dict} 结果字典
    timeout{int} 超时阈值
return {type} 
    res{dict} 扫描结果 key为端口，value为端口状态
'''
def ports_scan_per_thread(dst_ip, target, res, timeout):
    for port in target:
        dst_syn_tcp = TCP(sport=1234, dport=port, flags="S")
        response = sr1(dst_ip/dst_syn_tcp, timeout=timeout, verbose=False)
        if str(type(response))=="":
            res[port] = "Filtered"
        elif response.haslayer(TCP):
            if response.getlayer(TCP).flags == 0x12:  # SYN/ACK 包
                dst_rst_tcp = TCP(sport=1234, dport=port, flags="R")
                sr(dst_ip/dst_rst_tcp, timeout=timeout,  verbose=False)
                res[port] = "Open"
            elif response.getlayer(TCP).flags == 0x14:   # RST 包
                res[port] = "Closed"
            else: 
                res[port] = "Unknown"
        elif response.haslayer(ICMP): #ICMP 包
            icmp_msg = response.getlayer(ICMP)
            if int(icmp_msg.type) == 3 and int(icmp_msg.code) in [1,2,3,9,10,13]:
                res[port] = "Filtered"
        else:
            res[port] = "Unknown"

if __name__ == "__main__":
    #res = ports_scan('10.10.10.129')
    print(res)