package main

import (
	"bufio"
	"fmt"
	"io/ioutil"
	"log"
	"math"
	"os"
	"strconv"
	"strings"
	"time"
	"trafficAnalysis/tool"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

type flowFeature struct {
	srcip string
	dstip string
	srcport string
	dstport string
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
	//每秒上行数据包数目
	uppacketnum_second float64
	//下行数据包数目
	downpacketnum int
	//每秒下行数据包数目
	downpacketnum_second float64
	//总包数
	packetnum int
	//每秒包数
	packetnum_second float64
	//下行数据包比上行数据包
	downuppacket_percent float64
	//上行包头占总长度的比例
	uphead_percent float64
	//下行包头占总长度的比例
	downhead_percent float64

	servername string
	extensionNum int
}


type packetFeature struct {
	timestamp time.Time
	lenPacket int
	//ip
	srcIP string
	dstIP string
	flag uint8
	ttl uint8
	//transport
	transportLayer string
	srcPort string
	dstPort string
	lenPayload int
	//tls
	tlsVersion int
	tlsType int
	handShakeType []int
	handShakeTypeLen []int
	servername string
	extensionNum int
}


//按制定筛选规则，过滤流量，并提取流量中特征
func extractFeature(config CONFIG)  {
	var packetSource *gopacket.PacketSource	

	//根据配置文件选择在线解析或者离线解析
	//打开pcap数据包
	if config.Method == "offline" {
		files, _ := ioutil.ReadDir(config.PacpFileDir)
		for a, file := range files {
			fmt.Println(a, file)
			handle, err := pcap.OpenOffline(config.PacpFileDir+file.Name())
			if err != nil {
				fmt.Println("open pcapfile error")
				log.Fatal(err)
			} else {
				fmt.Println("open file success")
			}
			err = handle.SetBPFFilter(config.Filter)
			if err != nil {
				fmt.Println("setbpffilter error")
				log.Fatal(err)
			} else {
				fmt.Printf("setbpffilter success\n")
			}
			packetSource = gopacket.NewPacketSource(handle, handle.LinkType())
			//获取每个数据包
			packets := packetSource.Packets()
			if packets == nil {
				fmt.Println("error99")
			}
			flows := make([][]packetFeature, 0) 
			mapAddress := make(map[string]int, 0)

			//遍历数据包，对每个数据包做解析

			test := 1
			for packet := range packets {
				pFeature := extractPacketFeature(packet)
				packetsToFlow(pFeature, mapAddress, &flows)
				test = test + 1
			}
			fFeatures := make([]flowFeature, len(flows))
			for i := 0; i < len(flows); i++ {
				extractFlowFeature(flows[i], &fFeatures[i])
			}
			//解析后的结果保存到feature下对应的文件目录
			//saveFeature(config, file.Name(), flows)
			saveFeatureone(config, file.Name(), fFeatures)
		}
	} else if config.Method == "online" {
		timeStr := time.Now().Format("2006-01-02 15:04:05")
		handle, err := pcap.OpenLive(config.Device, 2048, true, 30*time.Second)
		if err != nil {
			fmt.Println(80)
			log.Fatal(err)
		}
		err = handle.SetBPFFilter(config.Filter)
		if err != nil {
			log.Fatal(err)
		}
		packetSource = gopacket.NewPacketSource(handle, handle.LinkType())
		//获取每个数据包
		packets := packetSource.Packets()
		if packets == nil {
			fmt.Println("error99")
		}
		flows := make([][]packetFeature, 0) 
		mapAddress := make(map[string]int, 0)

		//遍历数据包，对每个数据包做解析

		test := 1
		for packet := range packets {
			pFeature := extractPacketFeature(packet)
			packetsToFlow(pFeature, mapAddress, &flows)
			test = test + 1
		}
		fFeatures := make([]flowFeature, len(flows))
		for i := 0; i < len(flows); i++ {
			extractFlowFeature(flows[i], &fFeatures[i])
		}
		//解析后的结果保存到feature下对应的文件目录
		saveFeature(config, timeStr+config.Device, flows)
	}
	return 
}

// 根据数据包的四元组，将数据包分成流
func packetsToFlow(pFeature packetFeature, mapAddress map[string]int,flows *[][]packetFeature) {
	one := new(packetFeature)
	one.srcIP = pFeature.srcIP
	one.dstIP = pFeature.dstIP
	one.srcPort = pFeature.srcPort
	one.dstPort = pFeature.dstPort
	//newAddress := tool.CombineIP(one.srcIP, one.dstIP)
	newAddress := tool.CombineIPPort(one.srcIP ,one.srcPort, one.dstIP, one.dstPort)
	value := tool.SearchAddress(newAddress, mapAddress)
	if value == -1 {
		nums := len(*flows)
		mapAddress[string(newAddress)] = nums
		oneflow := []packetFeature{pFeature}
		*flows = append(*flows, oneflow)
	} else {
		(*flows)[value] = append((*flows)[value], pFeature)
	}
}

// 提取数据包的基本特征
func extractPacketFeature(packet gopacket.Packet) packetFeature {
	var feature packetFeature
	feature.lenPacket = len(packet.Data())
	feature.timestamp = packet.Metadata().CaptureInfo.Timestamp

	//ip层字段提取
	ipLayer := packet.Layer(layers.LayerTypeIPv4)
	ip, _ := ipLayer.(*layers.IPv4)
	var transportLayer gopacket.LayerType
	if ip!= nil {
		transportLayer = ip.NextLayerType()
		feature.srcIP = ip.SrcIP.String()
		feature.dstIP = ip.DstIP.String()
		feature.ttl = ip.TTL
	} else {
		log.Fatal(ip)
	}
	if transportLayer == layers.LayerTypeTCP {
		//tcp层字段提取
		feature.transportLayer = "tcp"
		tcpLayer := packet.Layer(layers.LayerTypeTCP)
		tcp, _ := tcpLayer.(*layers.TCP)
		if tcp != nil {
			feature.srcPort = strconv.FormatUint(uint64(tcp.SrcPort), 10)
			feature.dstPort = strconv.FormatUint(uint64(tcp.DstPort), 10)
			feature.lenPayload = len(tcp.LayerPayload())
		} else {
			log.Fatal(tcp)
		}

		//tls层字段提取
		tls := tcp.Payload
		var err error
		totalLen := len(tls)

		if len(tls) < 6 {
			return feature
		}
		ressemableUDP := false
		for oneLayerLen := 0; oneLayerLen < totalLen; {
			lengthH := 0
			if oneLayerLen+5 > totalLen || oneLayerLen < 0 {
				break
			}
			lengthH, err = tool.NetBytesToInt(tls[oneLayerLen+3:oneLayerLen+5], 2)
			if err != nil {
				break
			}
			if lengthH > totalLen {
				break
			}
			if oneLayerLen + lengthH + 5 > totalLen {
				break
			}
			if err != nil {
				log.Fatal("error 178")
			}
			switch tls[oneLayerLen] {
			case 20:
			case 22: 
				handShakeProcess(tls[oneLayerLen:], &feature)
			case 23: 
			default:
				ressemableUDP =  true
			}
			if ressemableUDP {
				break
			}
		
			oneLayerLen = lengthH + oneLayerLen + 5
		}
	} else if transportLayer == layers.LayerTypeUDP {
		feature.transportLayer = "udp"
		//udp字段提取
		udpLayer := packet.Layer(layers.LayerTypeUDP)
		udp, _ := udpLayer.(*layers.UDP)
		if udp != nil {
			feature.srcPort = strconv.FormatUint(uint64(udp.SrcPort), 10)
			feature.dstPort = strconv.FormatUint(uint64(udp.DstPort), 10)
			feature.lenPayload = len(udp.LayerPayload())
		} else {
			log.Fatal(udp)
		}
	}
	return feature
}

func saveFeatureone(config CONFIG, file string, features []flowFeature){
	length := len(features)
	saveFile := config.SaveFileDir + file
	fHandle, err := os.OpenFile(saveFile, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0666)
	if err != nil {
		fmt.Println("saveFeature file error")
	}
	w := bufio.NewWriter(fHandle)
	var one string
	for i := 0; i < length; i++ {
		if features[i].packetnum <= 50 {
			continue
		}
		one = ""
		one += features[i].srcip + "\t"
		one += features[i].dstip + "\t"
		one += features[i].srcport + "\t"
		one += features[i].dstport + "\t"
		one += strconv.FormatFloat(features[i].uptime_mean, 'f', 4, 64) + "\t"
		one += strconv.FormatFloat(features[i].uptime_std, 'f', 4, 64) + "\t"
		one += strconv.FormatFloat(features[i].uptime_min, 'f', 4, 64) + "\t"
		one += strconv.FormatFloat(features[i].uptime_max, 'f', 4, 64) + "\t"
		one += strconv.FormatFloat(features[i].downtime_mean, 'f', 4, 64) + "\t"
		one += strconv.FormatFloat(features[i].downtime_std, 'f', 4, 64) + "\t"
		one += strconv.FormatFloat(features[i].downtime_max, 'f', 4, 64) + "\t"
		one += strconv.FormatFloat(features[i].downtime_min, 'f', 4, 64) + "\t"
		one += strconv.FormatFloat(features[i].time_mean, 'f', 4, 64) + "\t"
		one += strconv.FormatFloat(features[i].time_std, 'f', 4, 64) + "\t"
		one += strconv.FormatFloat(features[i].time_max, 'f', 4, 64) + "\t"
		one += strconv.FormatFloat(features[i].time_min, 'f', 4, 64) + "\t"
		one += strconv.FormatFloat(features[i].duration, 'f', 4, 64) + "\t"
		one += strconv.Itoa(features[i].uppacketnum) + "\t"
		one += strconv.FormatFloat(features[i].uppacketnum_second, 'f', 4, 64) + "\t"
		one += strconv.Itoa(features[i].downpacketnum) + "\t"
		one += strconv.FormatFloat(features[i].downpacketnum_second, 'f', 4, 64) + "\t"
		one += strconv.Itoa(features[i].packetnum) + "\t"
		one += strconv.FormatFloat(features[i].packetnum_second, 'f', 4, 64) + "\t"
		one += strconv.FormatFloat(features[i].downuppacket_percent, 'f', 4, 64) + "\t"
		one += strconv.FormatFloat(features[i].uphead_percent, 'f', 4, 64) + "\t"
		one += strconv.FormatFloat(features[i].downhead_percent, 'f', 4, 64) + "\t"
		one += features[i].servername + "\t"
		one += strconv.Itoa(features[i].extensionNum)
		one += features[i].servername
		w.WriteString(one + "\n")
	}
	w.Flush()
	fHandle.Close()
}



func saveFeature(config CONFIG, file string, features [][]packetFeature) {
	sum := 0
	fmt.Printf("流的种类: %d\n", len(features))
	acti := 0
	for i := 0; i < len(features); i++ {
		sum += len(features[i])
		var count int
		for j := 0; j < len(features[i]); j++ {
			if features[i][j].lenPayload != 0 {
				count++
			}
		}
		if count < 100 {
			continue
		}
		saveFile := config.SaveFileDir + file
		fHandle, err := os.OpenFile(saveFile + strconv.Itoa(acti) + ".txt", os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0666)
		if err != nil {
			fmt.Println("saveFeature file error")
		}
		w := bufio.NewWriter(fHandle)
		for j := 0; j < len(features[i]); j++ {
			if features[i][j].lenPayload != 0 {
				time := features[i][j].timestamp
				if j == 0 {
					one := time.Sub(time)
					w.WriteString(strconv.FormatFloat(one.Seconds(), 'f', 4, 64) + "\t")
				} else if j > 0 {
					w.WriteString(strconv.FormatFloat(time.Sub(features[i][j-1].timestamp).Seconds(), 'f', 4, 64) + "\t")
				}
				w.WriteString(strconv.Itoa(features[i][j].lenPayload) + "\n")
			}
		}
		w.Flush()
		fHandle.Close()
		acti++
	}
	fmt.Printf("数据包总量: %d\n", sum)
}

func handShakeProcess(tls []byte, feature *packetFeature) {
	lengthH := len(tls)
	var err error
	for j := 0; j < lengthH; {
		handShakeType := 0
		handShakeType, err = tool.NetBytesToInt(tls[0:1], 1)
		if err != nil {
			log.Fatal("error 191")
		}
		feature.handShakeType = append(feature.handShakeType, handShakeType)
		handShakeTypeLen := 0
		handShakeTypeLen, err = tool.NetBytesToInt(tls[j+1:j+4], 3)
		if err != nil {
			log.Fatal("error 199")
		}
		j = j + 4 + handShakeTypeLen
		feature.handShakeTypeLen = append(feature.handShakeTypeLen, handShakeTypeLen)
		switch handShakeType {
		case 1:{
			sessionLen := 0
			sessionLen, err = tool.NetBytesToInt(tls[38:39], 1)

			chiperSuitLen := 0
			chiperSuitLen, err = tool.NetBytesToInt(tls[39+sessionLen:41+sessionLen], 2)
			extensionLen := 0
			extensionLen, err = tool.NetBytesToInt(tls[(43+chiperSuitLen+sessionLen):(45+chiperSuitLen+sessionLen)], 2)
			position := 45 + chiperSuitLen + sessionLen
			extensionNum := 0
			for i := 0; i < extensionLen; {
				extensionType := 0
				extensionType, err = tool.NetBytesToInt(tls[position:position+2], 2)
				oneExtensionLen := 0
				switch extensionType {
				//servername
				case 0:
					oneExtensionLen, _ = tool.NetBytesToInt(tls[position+2:position+4], 2)
					servername, _ := tool.NetByteToString(tls[position+4+5:position+4+oneExtensionLen], oneExtensionLen)
					feature.servername = servername
					fmt.Println(feature.servername)
				default:
					oneExtensionLen, _ = tool.NetBytesToInt(tls[position+2:position+4], 2)
				}
				extensionNum++
				i = i + 4 + oneExtensionLen
				position = position + 4 + oneExtensionLen
			}
			feature.extensionNum = extensionNum
		}
		}
	}
	feature.transportLayer = "tls"
}

// 提取每一条双向流的特征
func extractFlowFeature(flow []packetFeature, fFeature *flowFeature) {
	length := len(flow)
	fFeature.srcip = flow[0].srcIP
	fFeature.dstip = flow[0].dstIP
	fFeature.srcport = flow[0].srcPort
	fFeature.dstport = flow[0].dstPort
	//上行时间间隔
	var uptime_pre time.Time
	var uptime_count float64 = 0
	var uptime_total float64 = 0
	var uptime_var float64 = 0
	var uptime_max float64 = 0
	var uptime_min float64 = math.MaxFloat64

	//下行时间间隔
	var downtime_pre time.Time
	var downtime_count float64 = 0
	var downtime_total float64 = 0
	var downtime_var float64 = 0
	var downtime_max float64 = 0
	var downtime_min float64 = math.MaxFloat64

	//时间间隔
	var time_pre time.Time
	var time_total float64
	var time_var float64
	var time_max float64 = 0
	var time_min float64 = math.MaxFloat64
	
	var one float64

	//数据包长度，包头长度
	var packetlen int64
	var headlen int64
	var uppacketlen int64
	var upheadlen int64
	var downpacketlen int64
	var downheadlen int64

	for i := 0; i < length; i++ {
		packetlen += int64(flow[i].lenPacket)
		headlen += int64(flow[i].lenPacket - flow[i].lenPayload) 
		//计算上行时间间隔
		if uptime_pre.IsZero() {
			uppacketlen += int64(flow[i].lenPacket)
			upheadlen += int64(flow[i].lenPacket - flow[i].lenPayload)
			uptime_pre = flow[i].timestamp
		} else if strings.Compare(flow[i].srcIP, fFeature.srcip)  == 0 {
			uppacketlen += int64(flow[i].lenPacket)
			upheadlen += int64(flow[i].lenPacket - flow[i].lenPayload)
			uptime_count++
			one = flow[i].timestamp.Sub(uptime_pre).Seconds()
			uptime_total += one
			uptime_var += math.Pow(one, 2)
			if one > uptime_max {
				uptime_max = one
			}
			if one < uptime_min {
				uptime_min = one
			}
		}
		//计算下行时间间隔
		if downtime_pre.IsZero() && strings.Compare(flow[i].srcIP , fFeature.dstip) == 0 {
			downpacketlen += int64(flow[i].lenPacket)
			downheadlen += int64(flow[i].lenPacket - flow[i].lenPayload)
			downtime_pre = flow[i].timestamp
		} else if strings.Compare(flow[i].srcIP, fFeature.dstip) == 0 {
			downpacketlen += int64(flow[i].lenPacket)
			downheadlen += int64(flow[i].lenPacket - flow[i].lenPayload)
			downtime_count++
			one = flow[i].timestamp.Sub(downtime_pre).Seconds()
			downtime_total += one
			downtime_var += math.Pow(one, 2)
			if one > downtime_max {
				downtime_max = one
			}
			if one < downtime_min {
				downtime_min = one
			}
		}
		//时间间隔
		if time_pre.IsZero() {
			time_pre = flow[i].timestamp
		} else {
			one = flow[i].timestamp.Sub(time_pre).Seconds()
			time_total += one
			time_var += math.Pow(one, 2)
			if one > time_max {
				time_max = one
			}
			if one < time_min {
				time_min = one
			}
		}
		if len(fFeature.servername) == 0 && len(flow[i].servername) != 0 {
			fFeature.servername = flow[i].servername
		}
		fFeature.extensionNum += flow[i].extensionNum
	}
	if uptime_min == math.MaxFloat64 {
		fFeature.uptime_min = 0
	} else {
		fFeature.uptime_min = uptime_min
	}
	fFeature.uptime_max = uptime_max
	if uptime_count != 0 {
		fFeature.uptime_mean = uptime_total / uptime_count
		fFeature.uptime_std = uptime_var / uptime_count - math.Pow(fFeature.uptime_mean, 2)
		fFeature.uptime_std = math.Sqrt(fFeature.uptime_std)
	}
	fFeature.downtime_max = downtime_max
	if downtime_min == math.MaxFloat64 {
		fFeature.downtime_min = 0
	} else {
		fFeature.downtime_min = downtime_min
	}
	if downtime_count != 0 {
		fFeature.downtime_mean = downtime_total / downtime_count 
		fFeature.downtime_std = downtime_var / downtime_count - math.Pow(fFeature.downtime_mean, 2)
		fFeature.downtime_std = math.Sqrt(fFeature.downtime_std)
	}

	fFeature.time_max = time_max
	fFeature.time_min = time_min
	fFeature.time_mean = time_total / float64(length - 1)
	fFeature.time_std = time_var / float64(length - 1) - math.Pow(fFeature.time_mean, 2)
	fFeature.time_std = math.Sqrt(fFeature.time_std)

	fFeature.duration = float64(flow[length-1].timestamp.Sub(flow[0].timestamp))
	fFeature.uppacketnum = int(math.Floor(uptime_count+1))
	fFeature.uppacketnum_second = float64(fFeature.uppacketnum) / fFeature.duration
	fFeature.downpacketnum = int(math.Floor(downtime_count+1))
	fFeature.downpacketnum_second = float64(fFeature.downpacketnum) / fFeature.duration
	fFeature.packetnum = length
	fFeature.packetnum_second = float64(fFeature.packetnum) / fFeature.duration
	if fFeature.uppacketnum == 0 {
		fFeature.downuppacket_percent = 0
	} else {
		fFeature.downuppacket_percent = float64(fFeature.downpacketnum)/ float64(fFeature.uppacketnum)
	}
	if upheadlen == 0 {
		fFeature.uphead_percent = 0
	} else {
		fFeature.uphead_percent = float64(upheadlen) / float64(uppacketlen)
	}
	if downpacketlen == 0 {
		fFeature.downhead_percent = 0
	} else {
		fFeature.downhead_percent = float64(downheadlen) / float64(downpacketlen)
	}
}
