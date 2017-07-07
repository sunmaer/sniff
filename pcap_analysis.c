/**
 * 网络流量在线分析系统
 *
 * pcap_analysis.c
 * 分析网络数据包
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

/* 数据包 IP 地址及端口 */
typedef struct _netset
{
    u_int       sip;
    u_int       dip;
    u_short     sport;
    u_short     dport;
    u_char      protocol;
}netset;

/* 数据包信息节点 */
typedef struct _net_link_node
{
    netset  nln_set; // 数据包 IP 地址及端口
    int     nln_upl_size; // 数据包上传数据量
    int     nln_downl_size; // 数据包下载数据量
    int     nln_upl_pkt; // 数据包上传个数
    int     nln_downl_pkt; // 数据包下载个数
    u_char  nln_status; // 连接状态
/* A 运行 TCP 客户程序, B 运行 TCP 服务器程序 */
#define CLOSED      0x00
/* TCP 的连接建立 */
#define SYN_SENT    0x01    // A 向 B 发送连接请求报文段，首部中同步位 SYN = 1,A 进入同步已发送状态 SYN-SENT
#define SYN_RECVD   0x02    // B 收到连接请求报文段，确认报文段中 SYN 和 ACK 都置1，B 进入同步收到状态 SYN-RCVD
#define ESTABLISHED 0x03    // A 收到 B 的确认后，还须向 B 确认，确认报文段 ACK 置1，A 进入已连接状态 ESTABLISHED
/* TCP 的连接释放 */
#define FIN_WAIT_1  0x04    // client send FIN
#define CLOSE_WAIT  0x05    // server recv FIN, and send ACK
#define FIN_WAIT_2  0x06    // client recv ACK
#define LAST_ACK    0x07    // server send FIN
#define TIME_WAIT   0x08    // client recv FIN
    // CLOSED: client send ACK, server recv ACK
#define UNDEFINED   0xff
    struct  _net_link_node *next; // 下一个数据包地址
}net_link_node, *p_net_link;

/* 链表头-统计信息 */
typedef struct _net_link_header
{
    int count_conn; // 连接个数
    int count_upl_pkt; // 数据包总上传数据量
    int count_downl_pkt; // 数据包总下载数据量
    int count_upl; // 数据包总上传个数
    int count_downl; // 数据包总下载个数
    p_net_link link; // 第一个数据包地址
}net_link_header;

/* 将 int 类型的时间转换为 年-月-日 时：分：秒 形式 */
char *longTime(long ltime)
{
    time_t t;
    struct tm *p;
    static char s[100];
    
    t = ltime;
    p = localtime(&t);
    
    strftime(s, sizeof(s), "%Y-%m-%d %H:%M:%S", p);
    return s;
}

/* 点十分制 IP 地址转换函数 */
#define IPTOSBUFFERS    12
static char *iptos(bpf_u_int32 in)
{
    static char output[IPTOSBUFFERS][3*4+3+1];
    static short which;
    u_char *p;
    
    p = (u_char *)&in;
    which = (which + 1 == IPTOSBUFFERS ? 0 : which + 1);
    sprintf(output[which], "%d.%d.%d.%d", p[0], p[1], p[2], p[3]);
    return output[which];
}

/*
 * 三个链表
 * 一个哈希链表，保存处于连接状态的数据包
 * 两个链表分别保存tcp和udp的流量
 */

net_link_header *FLowLink_TCP; // TCP 流量链表
net_link_header *FLowLink_UDP; // UDP 流量链表

/* ========== hash table ============= */
#define HASH_TABLE_SIZE 0xffff
p_net_link HashTable[HASH_TABLE_SIZE]; // 保存处于连接状态的数据包

/* 初始化流量链表 */
void init_flowLink(net_link_header *head)
{
    head->count_conn        = 0;
    head->count_upl_pkt     = 0;
    head->count_downl_pkt   = 0;
    head->count_upl         = 0;
    head->count_downl       = 0;
    head->link              = NULL;
}

/* 清空流量链表 */
void clear_flowLink(net_link_header *head)
{
    if( head->link == NULL ){ return;}
    
    net_link_node *pTemp1 = NULL;
    net_link_node *pTemp2 = NULL;
    
    pTemp1 = head->link;
    pTemp2 = pTemp1->next;
    while( pTemp2 != NULL )
    {
        free(pTemp1);
        pTemp1 = pTemp2;
        pTemp2 = pTemp1->next;
    }
    free(pTemp1);
    
    head->link = NULL;
}

/* TCP 数据包流量分析 */
void parse_flowLink_TCP(FILE *fOutput)
{
    fprintf(fOutput, "TCP连接个数：\t%d\n", FLowLink_TCP->count_conn);
    fprintf(fOutput, "TCP数据包个数：\t%d\n", FLowLink_TCP->count_upl_pkt + FLowLink_TCP->count_downl_pkt);
    fprintf(fOutput, "TCP数据总流量：\t%d bytes\n", FLowLink_TCP->count_upl + FLowLink_TCP->count_downl);
    fprintf(fOutput, "TCP数据上传量：\t%d bytes\n", FLowLink_TCP->count_upl);
    fprintf(fOutput, "TCP数据下载量：\t%d bytes\n", FLowLink_TCP->count_downl);
    fprintf(fOutput, "--------------------------------------------------------\n");
    
    net_link_node *pTemp = NULL;
    pTemp = FLowLink_TCP->link;
    while( pTemp != NULL )
    {
        fprintf(fOutput, "%s\t%u\t", iptos(pTemp->nln_set.sip), pTemp->nln_set.sport);
        fprintf(fOutput, "==>\t%s\t%u\t", iptos(pTemp->nln_set.dip), pTemp->nln_set.dport);
        fprintf(fOutput, "上传包数量：%d\t", pTemp->nln_upl_pkt);
        fprintf(fOutput, "下载包数量：%d\t", pTemp->nln_downl_pkt);
        fprintf(fOutput, "上传量：%d bytes\t", pTemp->nln_upl_size);
        fprintf(fOutput, "下载量：%d bytes\t", pTemp->nln_downl_size);
        fprintf(fOutput, "\n");
        pTemp = pTemp->next;
    }
    clear_flowLink(FLowLink_TCP);
}

/* UDP 数据包流量分析 */
void parse_flowLink_UDP(FILE *fOutput)
{
    fprintf(fOutput, "UDP数据包个数：\t%d\n", FLowLink_UDP->count_upl_pkt + FLowLink_UDP->count_downl_pkt);
    fprintf(fOutput, "UDP数据流量：\t%d bytes\n", FLowLink_UDP->count_upl + FLowLink_UDP->count_downl);
    clear_flowLink(FLowLink_UDP);
}

void add_to_flowLink(net_link_header *head, const net_link_node *theNode)
{
    net_link_node *newNode = (net_link_node *)malloc(sizeof(net_link_node));
    memcpy(newNode, theNode, sizeof(net_link_node));
    
    head->count_conn ++;
    head->count_upl_pkt     += newNode->nln_upl_pkt;
    head->count_downl_pkt   += newNode->nln_downl_pkt;
    head->count_upl         += newNode->nln_upl_size;
    head->count_downl       += newNode->nln_downl_size;
    
    /* 插入一个节点 */
    newNode->next = head->link;
    head->link = newNode;
}

/* HASH 值计算 */
u_short get_hash(const netset *theSet)
{
    u_int srcIP = theSet->sip;
    u_int desIP = theSet->dip;
    u_int port  = (u_int)(theSet->sport * theSet->dport);
    u_int res   = (srcIP^desIP)^port;
    u_short hash= (u_short)((res & 0x00ff)^(res >> 16));
    return hash;
}

/* 连接状态数据包 */
void add_to_hashTable(u_short hash, const net_link_node *theNode, u_char flags)
{
    net_link_node *HashNode = (net_link_node *)malloc(sizeof(net_link_node));
    memcpy(HashNode, theNode, sizeof(net_link_node));
    
    if(HashTable[hash] == NULL) // 判断当前 HASH 关键字是否已存在，不存在就将当前节点加入 HASH 链表
    {
        HashTable[hash] = HashNode;
        return;
    }
    net_link_node *pTemp = HashTable[hash];
    net_link_node *pBack = NULL;
    int isSame_up = 0; // 同一上传连接
    int isSame_down = 0; // 同一下载连接
    while(pTemp != NULL)
    {
        /* IP 地址和端口匹配 */
        isSame_up = (pTemp->nln_set.sip == HashNode->nln_set.sip)
        && (pTemp->nln_set.dip == HashNode->nln_set.dip)
        && (pTemp->nln_set.sport == HashNode->nln_set.sport)
        && (pTemp->nln_set.dport == HashNode->nln_set.dport);
        
        isSame_down = (pTemp->nln_set.dip == HashNode->nln_set.sip)
        && (pTemp->nln_set.sip == HashNode->nln_set.dip)
        && (pTemp->nln_set.dport == HashNode->nln_set.sport)
        && (pTemp->nln_set.sport == HashNode->nln_set.dport);
        
        if( isSame_up )
        {
            pTemp->nln_upl_size += HashNode->nln_upl_size;
            pTemp->nln_upl_pkt ++;
            if(pTemp->nln_status == ESTABLISHED && (flags & TH_FIN) )
            {
                pTemp->nln_status = FIN_WAIT_1;
            }
            else if (pTemp->nln_status == TIME_WAIT && (flags & TH_ACK))
            {
                pTemp->nln_status = CLOSED;
                if(pBack == NULL)
                {
                    HashTable[hash] = NULL;
                }
                else
                {
                    pBack->next = pTemp->next;
                }
                add_to_flowLink(FLowLink_TCP, pTemp);
                free(pTemp);
            }
            else if(pTemp->nln_status == CLOSE_WAIT && (flags & TH_FIN))
            {
                pTemp->nln_status = LAST_ACK;
            }
            free(HashNode);
            break;
        }
        else if( isSame_down )
        {
            pTemp->nln_downl_size += HashNode->nln_upl_size;
            pTemp->nln_downl_pkt ++;
            if(pTemp->nln_status == ESTABLISHED && (flags & TH_FIN))
            {
                pTemp->nln_status = CLOSE_WAIT;
            }
            else if(pTemp->nln_status == LAST_ACK && (flags & TH_ACK))
            {
                pTemp->nln_status = CLOSED;
                if(pBack == NULL)
                {
                    HashTable[hash] = NULL;
                }
                else
                {
                    pBack->next = pTemp->next;
                }
                add_to_flowLink(FLowLink_TCP, pTemp);
                free(pTemp);
            }
            else if(pTemp->nln_status == FIN_WAIT_1 && (flags & TH_ACK))
            {
                pTemp->nln_status = FIN_WAIT_2;
            }
            else if(pTemp->nln_status == FIN_WAIT_2 && (flags & TH_FIN))
            {
                pTemp->nln_status = TIME_WAIT;
            }
            
            free(HashNode);
            break;
        }
        pBack = pTemp;
        pTemp = pTemp->next;
    }
    if(pTemp == NULL)
    {
        pBack->next = HashNode;
    }
}

/* 初始化 HASH 表 */
void clear_hashTable()
{
    int i = 0;
    net_link_node *pTemp1 = NULL;
    net_link_node *pTemp2 = NULL;
    for(i = 0; i < HASH_TABLE_SIZE; i++)
    {
        if(HashTable[i] == NULL){ continue;}
        
        pTemp1 = HashTable[i];
        while(pTemp1 != NULL)
        {
            pTemp2 = pTemp1->next;
            add_to_flowLink(FLowLink_TCP, pTemp1);
            free(pTemp1);
            pTemp1 = pTemp2;
        }
        HashTable[i] = NULL;
    }
}


/* 数据包分析函数 */
void  pcapAnalysis(u_char *dumpfile, const struct pcap_pkthdr *pkthdr, const u_char *packet);

int main(int argc, char **argv)
{
    printf("载入文件......\n");
    
    /* 输入分析周期 */
    int cycle;
    printf("输入分析周期(s)：");
    scanf("%d", &cycle);
    cycle = cycle > 0?cycle:10;
    
    pcap_t *handle; // 会话句柄
    char errbuf[PCAP_ERRBUF_SIZE]; // 错误信息
    
    /* 读取离线存储数据包文件 */
    handle = pcap_open_offline("/Users/sunmaer/我的文件/华中农业大学/综合实训/sniff/packet.data",errbuf);
    printf("开始分析\n");
    
    FLowLink_TCP = (net_link_header *)malloc(sizeof(net_link_header));
    
    FLowLink_UDP = (net_link_header *)malloc(sizeof(net_link_header));
    
    init_flowLink(FLowLink_TCP);
    init_flowLink(FLowLink_UDP);
    
    pcap_loop(handle, -1, pcapAnalysis, (u_char *)&cycle);
    printf("分析结束\n");
    
    free(FLowLink_TCP);
    free(FLowLink_UDP);
    return 0;
}

void  pcapAnalysis(u_char *userarg, const struct pcap_pkthdr *pkthdr, const u_char *packet)
{
    
    static int id = 1;
    
    struct ether_header *eptr = (struct ether_header*)packet; // 得到以太网字头
    struct ip *ipptr = (struct ip*)(packet+sizeof(struct ether_header)); // 得到 IP 报头
    struct tcphdr *tcpptr = (struct tcphdr*)(packet+sizeof(struct ether_header)+sizeof(struct ip)); // 得到 TCP 包头
    struct udphdr *udpptr = (struct udphdr*)(packet+sizeof(struct ether_header)+sizeof(struct ip)); // 得到 UDP 包头
    u_char *ptr;
    int i;
    
    /* 计算周期内的相关统计量并输出到文件 */
    int  *cycle = (int *)userarg; // 计算周期
    static long tstamp_start = 0; // 第一次抓包时间
    static long tstamp_offset = 0; // 上一轮分析周期结束时间
    static long tstamp_now = 0; // 当前数据包抓取时间
    
    /* 存储分析结果 */
    char *file_output = "/Users/sunmaer/我的文件/华中农业大学/综合实训/sniff/result.data";
    FILE *fOutput;
    fOutput = fopen(file_output, "a+");
    
    u_short ipLen_real  = 0;
    u_short ipLen_total = 0;
    u_short tcpLen_real = 0;
    u_short dataLen     = 0;
    
    netset          *CurSet    = (netset *)malloc(sizeof(netset));
    net_link_node   *LinkNode   = (net_link_node *)malloc(sizeof(net_link_node));
    
    if(id == 1) {
        tstamp_start = pkthdr->ts.tv_sec;
        tstamp_offset = tstamp_start;
        
        fOutput = fopen(file_output, "w");
        fclose(fOutput); // 清空文件
        fOutput = fopen(file_output, "a+");
        /* 数据包文件名字 */
        fprintf(fOutput, "数据文件：%s\n", "packet.data");
        fprintf(fOutput, "分析周期：%d s\n", *cycle);
    }
    
    tstamp_now = pkthdr->ts.tv_sec;
    
    if((tstamp_now - tstamp_offset) >= *cycle) {
        fprintf(fOutput, "\n>>>>> 时间段：%s", longTime(tstamp_offset));
        fprintf(fOutput, " --> %s\n", longTime(tstamp_offset + *cycle));
        
        /* 统计 UDP 数据包数量，数据量大小 */
        fprintf(fOutput, "--------------------------------------------------------\n");
        clear_hashTable();
        parse_flowLink_UDP(fOutput);
        init_flowLink(FLowLink_UDP);
        
        /* 统计 TCP 数据包数量，数据量大小 */
        fprintf(fOutput, "--------------------------------------------------------\n");
        parse_flowLink_TCP(fOutput);
        init_flowLink(FLowLink_TCP);
        fprintf(fOutput, "\n");
        /* 下一个分析周期开始时间 */
        tstamp_offset = tstamp_now;
    }
    
    if(ntohs(eptr->ether_type) == ETHERTYPE_IP) { // 判断是否为 IP 数据包
        if(ipptr->ip_p == IPPROTO_TCP || ipptr->ip_p == IPPROTO_UDP) { // 判断是否为 TCP UDP 数据包
            
            ipLen_real = (ipptr->ip_hl & 0x0f)*4;  // 大小端处理并且填充至4字节整数倍
            ipLen_total = ntohs(ipptr->ip_len);

            CurSet->sip = ipptr->ip_src.s_addr; // 存储源 IP 地址
            CurSet->dip = ipptr->ip_dst.s_addr; // 存储目的 IP 地址
            CurSet->protocol = ipptr->ip_p;
            
            if(ipptr->ip_p == IPPROTO_TCP) {
                
                tcpLen_real = (((tcpptr->th_off)>>4) & 0x0f) * 4;
                dataLen = ipLen_total - ipLen_real - tcpLen_real;
                
                CurSet->sport = ntohs(tcpptr->th_sport); // 存储 TCP 源端口
                CurSet->dport = ntohs(tcpptr->th_dport); // 存储 TCP 目的端口
            } else if(ipptr->ip_p == IPPROTO_UDP) {
                
                dataLen = ntohs(udpptr->uh_ulen) - 8; // UDP 用户数据包长度包括8个字节的首部信息
                CurSet->sport = ntohs(udpptr->uh_sport); // 存储 UDP 源端口
                CurSet->dport = ntohs(udpptr->uh_dport); // 存储 UDP 目的端口
            }
            
            /* 保存当前数据包 */
            LinkNode->nln_set       = *CurSet;
            LinkNode->nln_upl_size  = dataLen;
            LinkNode->nln_downl_size= 0;
            LinkNode->nln_upl_pkt   = 1;
            LinkNode->nln_downl_pkt = 0;
            LinkNode->nln_status    = ESTABLISHED;
            LinkNode->next          = NULL;
            
            if(ipptr->ip_p == IPPROTO_TCP)
            {
                /* 将当前节点加入 TCP 协议 HASH 链表 */
                add_to_hashTable(get_hash(CurSet), LinkNode, tcpptr->th_flags);
            }
            else if(ipptr->ip_p == IPPROTO_UDP)
            {
                /* 将当前节点加入 UDP 协议链表 */
                add_to_flowLink(FLowLink_UDP, LinkNode);
            }

        }
    }
    
    fprintf(fOutput, "\n**************************开始**************************\n");
    fprintf(fOutput, "ID：%d\n", id++);
    fprintf(fOutput, "数据包长度：%d\n", pkthdr->len);
    fprintf(fOutput, "实际捕获包长度：%d\n", pkthdr->caplen);
    fprintf(fOutput, "时间：%s", ctime((const time_t *)&pkthdr->ts.tv_sec));
    
    fprintf(fOutput, "-----------------数据链路层 解析以太网帧-----------------\n");
    ptr = eptr->ether_dhost;
    i = ETHER_ADDR_LEN;
    fprintf(fOutput, "目的 MAC 地址：");
    do
    {
        fprintf(fOutput, "%s%x", (i == ETHER_ADDR_LEN)?"":":", *ptr++);
    } while(--i>0);
    fprintf(fOutput, "\n");
    
    ptr = eptr->ether_shost;
    i = ETHER_ADDR_LEN;
    fprintf(fOutput, "源   MAC 地址：");
    do
    {
        fprintf(fOutput, "%s%x", (i == ETHER_ADDR_LEN)?"":":", *ptr++);
    } while(--i>0);
    fprintf(fOutput, "\n");
    
    fprintf(fOutput, "以太网帧类型：%x\n", ntohs(eptr->ether_type));
    
    fprintf(fOutput, "-----------------数据链路层 解析 IP 报头-----------------\n");
    fprintf(fOutput, "版本号：%d\n", ipptr->ip_v);
    fprintf(fOutput, "首部长度：%d\n", ipptr->ip_hl);
    fprintf(fOutput, "服务类型：%hhu\n", ipptr->ip_tos);
    fprintf(fOutput, "报文总长度：%d\n", ntohs(ipptr->ip_len));
    fprintf(fOutput, "标识：%d\n", ntohs(ipptr->ip_id));
    fprintf(fOutput, "片偏移：%d\n", ntohs(ipptr->ip_off));
    fprintf(fOutput, "生存时间：%hhu\n", ipptr->ip_ttl);
    fprintf(fOutput, "协议类型：%hhu\n", ipptr->ip_p);
    fprintf(fOutput, "首部校验和：%d\n", ntohs(ipptr->ip_sum));
    fprintf(fOutput, "源地址：%s\n", inet_ntoa(ipptr->ip_src));
    fprintf(fOutput, "目的地址：%s\n", inet_ntoa(ipptr->ip_dst));
    
    
    /* 根据 IP 报头协议类型字段判断数据携带协议类型，TCP 协议类型为6， UDP 协议类型为17 */
    if(ipptr->ip_p == IPPROTO_TCP) {
        
        fprintf(fOutput, "-----------------数据链路层 解析 TCP 报头-----------------\n");
        fprintf(fOutput, "目的端口：%d\n", ntohs(tcpptr->th_dport));
        fprintf(fOutput, "源端口：%d\n", ntohs(tcpptr->th_sport));
        fprintf(fOutput, "序列号：%u\n", tcpptr->th_seq);
        fprintf(fOutput, "确认号：%u\n", tcpptr->th_ack);
        fprintf(fOutput, "报头长度：%d\n", tcpptr->th_off);
        fprintf(fOutput, "保留：%d\n", tcpptr->th_x2);
        fprintf(fOutput, "标志：%hhu\n", tcpptr->th_flags);
        fprintf(fOutput, "窗口：%d\n", ntohs(tcpptr->th_win));
        fprintf(fOutput, "校验和：%d\n", ntohs(tcpptr->th_sum));
        fprintf(fOutput, "紧急：%d\n", ntohs(tcpptr->th_urp));
        
    } else if(ipptr->ip_p == IPPROTO_UDP) {
        
        fprintf(fOutput, "----------------数据链路层 解析 UDP 报头-----------------\n");
        fprintf(fOutput, "源端口：%d\n", ntohs(udpptr->uh_sport));
        fprintf(fOutput, "目的端口：%d\n", ntohs(udpptr->uh_dport));
        fprintf(fOutput, "用户数据包长度：%d\n", ntohs(udpptr->uh_ulen));
        fprintf(fOutput, "校验和：%d\n", ntohs(udpptr->uh_sum));
        
    }
    
    fprintf(fOutput, "**************************结束**************************\n");

    free(CurSet);
    free(LinkNode);
    fclose(fOutput);
}

