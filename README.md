## 使用说明

### config配置参数说明
* method:指定工作模式分为offline与online两种，offline处理离线pcap、pcang数据包，online接入网卡流量
* device:制定online模式下，接入网卡的设备名称
* filter:设置过滤规则
* tuple:网络流量分流，"5"：按照srcIP dstIP srcPort dstPort transportLayer分流；"3"：按照srcIP dstIP transportLayer分流。
* pcapFileDir:设置offline模式下离线数据包所在文件夹
* saveFileDir:设置offline模式下离线数据包所在文件夹
* savemode:保存方法分为两种packet、flow。packet表示将提取每一条流中每个数据包的特征，然后一条流一个文件保存。flow表示将提取每一条流的特征，然后按照每一个输入的pcap数据包保存该数据包中所有流的特征。

### 流特征说明
```
	特征文件以txt文本模式存储，存储格式如下
	srcip string
	dstip string
	srcport string
	dstport string
	transportLayer string
	//上行包到达时间间隔
	uptime_mean float64
	uptime_std float64
	uptime_min float64
	uptime_max float64
	//下行包到达时间间隔
	downtime_mean float64
	downtime_std float64
	downtime_min float64
	downtime_max float64
	//包到达时间
	time_mean float64
	time_std float64
	time_min float64
	time_max float64
	//流持续时间
	duration float64
	//上行数据包数目
	uppacketnum int
	//每分钟上行数据包数目
	uppacketnum_minute float64
	//下行数据包数目
	downpacketnum int
	//每分钟下行数据包数目
	downpacketnum_minute float64
	//总包数
	packetnum int
	//每分钟包数
	packetnum_minute float64
	//下行数据包比上行数据包
	downuppacket_percent float64
	//上行包头占总长度的比例
	uphead_percent float64
	//下行包头占总长度的比例
	downhead_percent float64
	extensionNum int
	servername string
	//tcp psh字段数据包占比
	psh float64
	//tcp urg字段数据包占比
	urg float64
```


### 包特征说明
	特征文件以txt文本模式存储，存储格式如下

```
\\数据包时间间隔 保留4为小数
time float
\\数据包方向，与流的第一个数据包的流向一致为0，反之为1
direction int 
srcIP string
dstIP string
\\ip协议 ttl
ttl uint64
\\传输层协议，tcp为0，udp为1，其他为2
transportLayer int
\\srcPort dstPort
srcPort unint64
dstPort unint64
\\传输层载荷长度
lenPayload int
\\tcp seqnum acknum
seqnum uint64
acknum uint64
\\tcp flags
fin
syn
rst
psh
ack
urg
ece
cwr
ns
```
