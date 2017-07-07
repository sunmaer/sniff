/**
 * 网络流量在线分析系统
 *
 * pcap_catch.c
 * 抓取网络数据包
 *
 * Created by 單棲情緒 on 2017/7/3.
 * Copyright © 2017年 單棲情緒. All rights reserved.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pcap.h>
#include <errno.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>

void  callback(u_char *dumpfile, const struct pcap_pkthdr *pkthdr, const u_char *packet)
{
    pcap_dump(dumpfile, pkthdr, packet);
}

int main()
{
    char *device; // 网络设备
    char errbuf[PCAP_ERRBUF_SIZE]; // 错误信息
    bpf_u_int32 net; // 网络号
    bpf_u_int32 mask; // 掩码
    struct in_addr addr;
    pcap_t *handle; // 会话句柄
    struct bpf_program filter; /* 已经编译好的过滤器 */
    char filter_app[] = "ip"; /* 过滤表达式 */
    
    /* 网络设备名 */
    device = pcap_lookupdev(errbuf);
    if(device == NULL)
    {
        printf("pcap_lookupdev:%s\n",errbuf);
        exit(1);
    }
    printf("网络设备：%s\n", device);
    
    /* 网络号和掩码 */
    if(pcap_lookupnet(device, &net, &mask, errbuf) == -1){
        printf("error\n");
        exit(1);
    }
    
    addr.s_addr = net;
    printf("网络号：%s\n", inet_ntoa(addr));
    
    addr.s_addr = mask;
    printf("网络掩码：%s\n", inet_ntoa(addr));
    
    /* 设置抓取时长 */
    int to_ms;
    printf("请输入抓取时长(s）：");
    scanf("%d", &to_ms);
    to_ms *= 1000; // 秒数转换为毫秒数
    
    /* 以混杂模式打开会话 */
    handle = pcap_open_live(device, 65535, 1, to_ms, errbuf);
    if(handle == NULL)
    {
        printf("pcap_open_live:%s\n",errbuf);
        exit(1);
    }
    
    /* 编译并应用过滤器 */
    if (pcap_compile(handle, &filter, filter_app, 1, mask) <0 )
    {
        printf("Unable to compile the packet filter\n");
        return 0;
    }
    if (pcap_setfilter(handle, &filter) < 0)
    {
        printf("Error setting the filter.\n");
        exit(1);
    }
    
    /* 离线存储数据包 */
    pcap_dumper_t *dumpfile;
    dumpfile = pcap_dump_open(handle, "/Users/sunmaer/我的文件/华中农业大学/综合实训/sniff/packet.data");
    if(dumpfile == NULL){
        printf("Error opening output file\n");
        exit(1);
    }
    
    /* 抓取网络数据包 */
    pcap_dispatch(handle, 0, callback, (u_char *)dumpfile);
    
    printf("数据包抓取成功\n");
    
    /* 关闭 dumpfile */
    pcap_dump_close(dumpfile);
    /* 关闭会话 */
    pcap_close(handle);
    
    return 0;
}

