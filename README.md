## 使用说明

### config配置参数说明
* method:指定工作模式分为offline与online两种，offline处理离线pcap、pcang数据包，online接入网卡流量
* device:制定online模式下，接入网卡的设备名称
* filter:设置过滤规则
* pcapFileDir:设置offline模式下离线数据包所在文件夹
* saveFileDir:设置offline模式下离线数据包所在文件夹
* savemode:保存方法分为两种packet、flow。packet表示将提取每一条流中每个数据包的特征，然后一条流一个文件保存。flow表示将提取每一条流的特征，然后按照每一个输入的pcap数据包保存该数据包中所有流的特征。

### 流特征说明
	特征文件以txt文本模式存储，存储格式如下


### 包特征说明
	特征文件以txt文本模式存储，存储格式如下
