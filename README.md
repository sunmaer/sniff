## 介绍

基于 C语言 网络流量在线分析系统

## 实验环境

> 1.操作系统：macOS Sierra 10.12.5

> 2.编程语言：C语言

> 3.网络数据包捕获函数包：libpcap

> 4.Xcode 8.3.3 + mac终端 

## 环境配置

#### 1.tcpdump网站(http://www.tcpdump.org)下载libpcap的latest release

#### 2.解压之后，在软件目录下执行./configure 

#### 3.执行 make

#### 4.执行 make install,此时，在/usr/local/lib目录下会生成libpcap的动态链接库，如：libpcap.dylib

#### 5.执行export DYLD_LIBRARY_PATH=/usr/local/lib 将此目录加入动态链接库的CLASSPATH
#### 6.编写测试代码测试是否可用：
```bash
// vim device.c
#include <stdio.h>
#include <pcap/pcap.h>
int main(int argc,char *argv[]) {
  char *dev,errbuf[PCAP_ERRBUF_SIZE];
  dev=pcap_lookupdev(errbuf);
  if(dev==NULL) {
    printf("couldn't find default device: %s\n",errbuf);
    return(2);
  }
  printf("Device: %s\n",dev);
  return(0);
}
```

#### 7.执行编译指令：
```bash
gcc -o device device.c -l pcap
```

#### 8.测试例程：
```bash
sudo ./device
``` 
如果显示：Device: en0
说明测试成功。

## 运行程序

> 进入项目目录，在终端中运行下面的命令

```bash
sudo su
gcc -o catch pcap_catch.c -l pcap
./catch
gcc -o analysis pcap_analysis.c -l pcap
./analysis
```


## 实现功能
- [x] 实时抓取网络中的数据包
- [x] 离线存储网络中的数据包
- [x] 分析各个网络协议格式
- [x] 采用Hash链表的形式将网络数据以连接（双向流）的形式存储
- [x] 计算并显示固定时间间隔内网络连接（双向流）的统计量