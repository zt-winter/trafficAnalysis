package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"math"
	"net"
	"os"
	"strconv"
	"sync"
	"time"
	"trafficAnalysis/tool"

	"github.com/Shopify/sarama"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/grd/statistics"
)

type dataconvar struct {
	ip          net.IP
	varianceSrc float64
	varianceDst float64
}

type flowFeature struct {
	Srcip          net.IP
	Dstip          net.IP
	Srcport        uint16
	Dstport        uint16
	TransportLayer uint16
	//上行包到达时间间隔
	Uptime_mean float64
	Uptime_std  float64
	Uptime_min  float64
	Uptime_max  float64
	//下行包到达时间间隔
	Downtime_mean float64
	Downtime_std  float64
	Downtime_min  float64
	Downtime_max  float64
	//包到达时间
	Time_mean float64
	Time_std  float64
	Time_min  float64
	Time_max  float64
	//流持续时间
	Duration float64
	//上行数据包数目
	Uppacketnum int
	//每分钟上行数据包数目
	Uppacketnum_minute float64
	//下行数据包数目
	Downpacketnum int
	//每分钟下行数据包数目
	Downpacketnum_minute float64
	//总包数
	Packetnum int
	//每分钟包数
	Packetnum_minute float64
	//下行数据包比上行数据包
	Downuppacket_percent float64
	//上行包头占总长度的比例
	Uphead_percent float64
	//下行包头占总长度的比例
	Downhead_percent float64

	ExtensionNum int
	Servername   string

	//tcp psh字段数据包占比
	Psh float64
	//tcp urg字段数据包占比
	Urg float64
}

type packetFeature struct {
	Timestamp time.Time
	LenPacket int
	//eth
	SrcMac net.HardwareAddr
	DstMac net.HardwareAddr

	//ip
	SrcIP net.IP
	DstIP net.IP
	Ttl   uint8
	//transport
	TransportLayer uint16
	SrcPort        uint16 //udp also has
	DstPort        uint16 //udp also has
	LenPayload     int    //udp alse has
	Seqnum         uint32
	Acknum         uint32
	Fin            bool
	Syn            bool
	Rst            bool
	Psh            bool
	Ack            bool
	Urg            bool
	Ece            bool
	Cwr            bool
	Ns             bool
	//tls
	TlsVersion       int
	TlsType          int
	HandShakeType    []uint
	HandShakeTypeLen []uint
	Servername       string
	ExtensionNum     int
}

// 按制定筛选规则，过滤流量，并提取流量中特征
func extractFeature(config CONFIG) {
	var packetSource *gopacket.PacketSource

	logFIle, err := os.OpenFile("./trafficAnalysis.log", os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0644)
	if err != nil {
		panic(err)
	}
	log.SetOutput(logFIle)
	log.SetFlags(log.Llongfile | log.Ldate | log.Ltime)
	//根据配置文件选择在线解析或者离线解析
	//打开pcap数据包
	if config.Method == "offline" {
		files, err := ioutil.ReadDir(config.PacpFileDir)
		if err != nil {
			log.Fatalln("this is no directory")
		}
		fmt.Println(time.Now())
		//	var wg sync.WaitGroup
		for a, file := range files {
			//wg.Add(1)
			//go func() {
			fmt.Println(a, file)
			//defer wg.Done()
			handle, err := pcap.OpenOffline(config.PacpFileDir + file.Name())
			if err != nil {
				log.Fatal(err)
			} else {
			}
			err = handle.SetBPFFilter(config.Filter)
			if err != nil {
				log.Fatal(err)
			}
			packetSource = gopacket.NewPacketSource(handle, handle.LinkType())

			flows := make([][]packetFeature, 0, 500)
			mapAddress := make(map[string]int, 500)

			//遍历数据包，对每个数据包做解析
			test := 1
			for {
				packet, err := packetSource.NextPacket()
				if err == io.EOF {
					break
				} else if err != nil {
					log.Fatal(err)
					continue
				}
				pFeature := extractPacketFeature(&packet)
				packetsToFlow(config, &pFeature, mapAddress, &flows)
				test = test + 1
			}

			/*
				for packet := range packetSource.Packets() {
					pFeature := extractPacketFeature(&packet)
					packetsToFlow(config, &pFeature, mapAddress, &flows)
					test = test + 1
				}
			*/

			fFeatures := make([]flowFeature, len(flows))
			for i := 0; i < len(flows); i++ {
				extractFlowFeature(flows[i], &fFeatures[i])
			}
			//解析后的结果保存到feature下对应的文件目录
			//saveFeature(config, file.Name(), flows)
			if config.SaveMode == "packet" {
				saveFeature(config, file.Name(), flows)
			} else if config.SaveMode == "flow" {
				saveFlowFeature(config, file.Name(), fFeatures)
			} else if config.SaveMode == "kafka" {
				saveKafka(config, fFeatures)
			} else {
				log.Fatal("savemode error\n")
			}
			//}()
			//wg.Wait()
		}
		fmt.Println(time.Now())
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
			pFeature := extractPacketFeature(&packet)
			packetsToFlow(config, &pFeature, mapAddress, &flows)
			test = test + 1
		}
		fFeatures := make([]flowFeature, len(flows))
		for i := 0; i < len(flows); i++ {
			extractFlowFeature(flows[i], &fFeatures[i])
		}
		//解析后的结果保存到feature下对应的文件目录
		saveFeature(config, timeStr+config.Device, flows)
	}
}

// 根据数据包的四元组，将数据包分成流
func packetsToFlow(config CONFIG, pFeature *packetFeature, mapAddress map[string]int, flows *[][]packetFeature) {
	newAddress := make([]byte, 0)
	if config.Tuple == "3" {
		newAddress = tool.CombineIP((*pFeature).SrcIP, (*pFeature).DstIP)
	} else if config.Tuple == "5" {
		newAddress = tool.CombineIPPort((*pFeature).SrcIP, (*pFeature).SrcPort, (*pFeature).DstIP, (*pFeature).DstPort)
	}
	value := tool.SearchAddress(newAddress, mapAddress)
	if value == -1 {
		nums := len(*flows)
		mapAddress[string(newAddress)] = nums
		oneflow := []packetFeature{*pFeature}

		/*
			oneflow := make([]packetFeature, 0, 200)
			oneflow = append(oneflow, *pFeature)
		*/
		*flows = append(*flows, oneflow)
	} else {
		(*flows)[value] = append((*flows)[value], *pFeature)
	}
}

// 提取数据包的基本特征
func extractPacketFeature(packet *gopacket.Packet) packetFeature {
	var feature packetFeature
	feature.LenPacket = len((*packet).Data())
	feature.Timestamp = (*packet).Metadata().CaptureInfo.Timestamp

	//mac层字段提取
	ethLayer := (*packet).Layer(layers.LayerTypeEthernet)
	eth, _ := ethLayer.(*layers.Ethernet)
	if eth != nil {
		feature.SrcMac = eth.SrcMAC
		feature.DstMac = eth.DstMAC
	}

	//ip层字段提取
	ipLayer := (*packet).Layer(layers.LayerTypeIPv4)
	ip, _ := ipLayer.(*layers.IPv4)
	var transportLayer gopacket.LayerType
	if ip != nil {
		transportLayer = ip.NextLayerType()
		feature.SrcIP = ip.SrcIP
		feature.DstIP = ip.DstIP
		feature.Ttl = ip.TTL
	} else {
		//log.Println("ip is nil")
		return feature
	}
	if transportLayer == layers.LayerTypeTCP {
		//tcp层字段提取
		feature.TransportLayer = 0
		tcpLayer := (*packet).Layer(layers.LayerTypeTCP)
		tcp, _ := tcpLayer.(*layers.TCP)
		if tcp != nil {
			feature.Seqnum = tcp.Seq
			feature.Acknum = tcp.Ack
			feature.Fin = tcp.FIN
			feature.Syn = tcp.SYN
			feature.Rst = tcp.RST
			feature.Psh = tcp.PSH
			feature.Ack = tcp.ACK
			feature.Urg = tcp.URG
			feature.Ece = tcp.ECE
			feature.Cwr = tcp.CWR
			feature.Ns = tcp.NS
			feature.SrcPort = uint16(tcp.SrcPort)
			feature.DstPort = uint16(tcp.DstPort)
			//feature.srcPort = strconv.FormatUint(uint64(tcp.SrcPort), 10)
			//feature.dstPort = strconv.FormatUint(uint64(tcp.DstPort), 10)
			feature.LenPayload = len(tcp.LayerPayload())
		} else {
			log.Fatal(tcp)
		}

		//tls层字段提取
		tls := tcp.Payload
		var err error
		totalLen := tool.IntToUint(len(tls))

		if len(tls) < 6 {
			return feature
		}
		ressemableUDP := false
		var oneLayerLen uint
		for oneLayerLen = 0; oneLayerLen < totalLen; {
			var lengthH uint = 0
			if oneLayerLen+5 > totalLen || oneLayerLen < 0 {
				break
			}
			lengthH, err = tool.NetBytesToUint(tls[oneLayerLen+3:oneLayerLen+5], 2)
			if err != nil {
				break
			}
			if lengthH > totalLen {
				break
			}
			if oneLayerLen+lengthH+5 > totalLen {
				break
			}
			if err != nil {
				log.Fatal("error 178")
			}
			switch tls[oneLayerLen] {
			case 20:
			case 22:
				handShakeProcess(tls[oneLayerLen+5:oneLayerLen+lengthH+5], &feature)
			case 23:
			default:
				ressemableUDP = true
			}
			if ressemableUDP {
				break
			}

			oneLayerLen = lengthH + oneLayerLen + 5
		}
	} else if transportLayer == layers.LayerTypeUDP {
		feature.TransportLayer = 1
		//udp字段提取
		udpLayer := (*packet).Layer(layers.LayerTypeUDP)
		udp, _ := udpLayer.(*layers.UDP)
		if udp != nil {
			feature.SrcPort = uint16(udp.SrcPort)
			feature.DstPort = uint16(udp.DstPort)
			//feature.srcPort = strconv.FormatUint(uint64(udp.SrcPort), 10)
			//feature.dstPort = strconv.FormatUint(uint64(udp.DstPort), 10)
			feature.LenPayload = len(udp.LayerPayload())
		} else {
			log.Fatal(udp)
		}
	}
	return feature
}

func saveFlowFeature(config CONFIG, file string, features []flowFeature) {
	length := len(features)
	saveFile := config.SaveFileDir + file
	fHandle, err := os.OpenFile(saveFile+".txt", os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0666)
	if err != nil {
		fmt.Println("saveFeature file error")
	}
	w := bufio.NewWriter(fHandle)
	var one string
	for i := 0; i < length; i++ {
		if features[i].Packetnum <= 50 {
			continue
		}
		one = ""
		one += features[i].Srcip.String() + "\t"
		one += features[i].Dstip.String() + "\t"
		one += strconv.FormatUint(uint64(features[i].Srcport), 10) + "\t"
		one += strconv.FormatUint(uint64(features[i].Dstport), 10) + "\t"

		one += strconv.Itoa(features[i].Downpacketnum) + "\t"
		one += strconv.Itoa(int(features[i].TransportLayer)) + "\t"
		one += strconv.FormatFloat(features[i].Uptime_mean, 'f', 4, 64) + "\t"
		one += strconv.FormatFloat(features[i].Uptime_std, 'f', 4, 64) + "\t"
		one += strconv.FormatFloat(features[i].Uptime_min, 'f', 4, 64) + "\t"
		one += strconv.FormatFloat(features[i].Uptime_max, 'f', 4, 64) + "\t"
		one += strconv.FormatFloat(features[i].Downtime_mean, 'f', 4, 64) + "\t"
		one += strconv.FormatFloat(features[i].Downtime_std, 'f', 4, 64) + "\t"
		one += strconv.FormatFloat(features[i].Downtime_min, 'f', 4, 64) + "\t"
		one += strconv.FormatFloat(features[i].Downtime_max, 'f', 4, 64) + "\t"
		one += strconv.FormatFloat(features[i].Time_mean, 'f', 4, 64) + "\t"
		one += strconv.FormatFloat(features[i].Time_std, 'f', 4, 64) + "\t"
		one += strconv.FormatFloat(features[i].Time_min, 'f', 4, 64) + "\t"
		one += strconv.FormatFloat(features[i].Time_max, 'f', 4, 64) + "\t"
		one += strconv.FormatFloat(features[i].Duration, 'f', 4, 64) + "\t"
		one += strconv.Itoa(features[i].Uppacketnum) + "\t"
		one += strconv.FormatFloat(features[i].Uppacketnum_minute, 'f', 4, 64) + "\t"
		one += strconv.Itoa(features[i].Downpacketnum) + "\t"
		one += strconv.FormatFloat(features[i].Downpacketnum_minute, 'f', 4, 64) + "\t"
		one += strconv.Itoa(features[i].Packetnum) + "\t"
		one += strconv.FormatFloat(features[i].Packetnum_minute, 'f', 4, 64) + "\t"
		one += strconv.FormatFloat(features[i].Downuppacket_percent, 'f', 4, 64) + "\t"
		one += strconv.FormatFloat(features[i].Uphead_percent, 'f', 4, 64) + "\t"
		one += strconv.FormatFloat(features[i].Downhead_percent, 'f', 4, 64) + "\t"
		one += strconv.Itoa(features[i].ExtensionNum) + "\t"
		if features[i].Servername == "" {
			one += strconv.Itoa(0) + "\t"
		} else {
			one += strconv.Itoa(1) + "\t"
		}
		one += strconv.FormatFloat(features[i].Psh, 'f', 4, 64) + "\t"
		one += strconv.FormatFloat(features[i].Urg, 'f', 4, 64) + "\t"
		w.WriteString(one + "\n")
	}
	w.Flush()
	fHandle.Close()
}

func saveFeature(config CONFIG, file string, features [][]packetFeature) {
	sum := 0
	acti := 0
	for i := 0; i < len(features); i++ {
		sum += len(features[i])
		var count int
		for j := 0; j < len(features[i]); j++ {
			if features[i][j].LenPayload != 0 {
				count++
			}
		}
		if count < 100 {
			continue
		}
		saveFile := config.SaveFileDir + file
		fHandle, err := os.OpenFile(saveFile+strconv.Itoa(acti)+".txt", os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0666)
		if err != nil {
			fmt.Println("saveFeature file error")
		}
		w := bufio.NewWriter(fHandle)
		firstSrcIP := features[i][0].SrcIP
		var lasttimestamp time.Time
		for j := 0; j < len(features[i]); j++ {
			if features[i][j].LenPayload != 0 {
				time := features[i][j].Timestamp
				if j == 0 {
					one := time.Sub(time)
					w.WriteString(strconv.FormatFloat(one.Seconds(), 'f', 4, 64) + "\t")
				} else if j > 0 {
					w.WriteString(strconv.FormatFloat(time.Sub(lasttimestamp).Seconds(), 'f', 4, 64) + "\t")
				}
				lasttimestamp = time
				//内网到外网direction = 0, 外网到内网direction = 1
				/*
					if features[i][j].srcIP[:7] == "192.168" {
						w.WriteString(strconv.Itoa(0) + "\t")
					} else if features[i][j].dstIP[:7] == "192.168" {
						w.WriteString(strconv.Itoa(1) + "\t")
					} else
				*/
				if net.IP.Equal(features[i][j].SrcIP, firstSrcIP) {
					w.WriteString(strconv.Itoa(0) + "\t")
				} else {
					w.WriteString(strconv.Itoa(1) + "\t")
				}
				w.WriteString(features[i][j].SrcIP.String() + "\t")
				w.WriteString(features[i][j].DstIP.String() + "\t")
				w.WriteString(strconv.FormatUint(uint64(features[i][j].Ttl), 10) + "\t")
				//udp = 0, tcp = 1
				if features[i][j].TransportLayer == 1 {
					w.WriteString(strconv.Itoa(0) + "\t")
				} else if features[i][j].TransportLayer == 0 {
					w.WriteString(strconv.Itoa(1) + "\t")
				} else {
					w.WriteString(strconv.Itoa(2) + "\t")
				}
				w.WriteString(strconv.FormatUint(uint64(features[i][j].SrcPort), 10) + "\t")
				w.WriteString(strconv.FormatUint(uint64(features[i][j].DstPort), 10) + "\t")
				w.WriteString(strconv.Itoa(features[i][j].LenPayload) + "\t")
				w.WriteString(strconv.FormatUint(uint64(features[i][j].Seqnum), 10) + "\t")
				w.WriteString(strconv.FormatUint(uint64(features[i][j].Acknum), 10) + "\t")
				if features[i][j].Fin {
					w.WriteString(strconv.Itoa(1) + "\t")
				} else {
					w.WriteString(strconv.Itoa(0) + "\t")
				}
				if features[i][j].Syn {
					w.WriteString(strconv.Itoa(1) + "\t")
				} else {
					w.WriteString(strconv.Itoa(0) + "\t")
				}
				if features[i][j].Rst {
					w.WriteString(strconv.Itoa(1) + "\t")
				} else {
					w.WriteString(strconv.Itoa(0) + "\t")
				}
				if features[i][j].Psh {
					w.WriteString(strconv.Itoa(1) + "\t")
				} else {
					w.WriteString(strconv.Itoa(0) + "\t")
				}
				if features[i][j].Ack {
					w.WriteString(strconv.Itoa(1) + "\t")
				} else {
					w.WriteString(strconv.Itoa(0) + "\t")
				}
				if features[i][j].Urg {
					w.WriteString(strconv.Itoa(1) + "\t")
				} else {
					w.WriteString(strconv.Itoa(0) + "\t")
				}
				if features[i][j].Ece {
					w.WriteString(strconv.Itoa(1) + "\t")
				} else {
					w.WriteString(strconv.Itoa(0) + "\t")
				}
				if features[i][j].Cwr {
					w.WriteString(strconv.Itoa(1) + "\t")
				} else {
					w.WriteString(strconv.Itoa(0) + "\t")
				}
				if features[i][j].Ns {
					w.WriteString(strconv.Itoa(1) + "\t")
				} else {
					w.WriteString(strconv.Itoa(0) + "\t")
				}
				if len(features[i][j].Servername) != 0 {
					w.WriteString(strconv.Itoa(1) + "\t")
				} else {
					w.WriteString(strconv.Itoa(0) + "\t")
				}
				w.WriteString(strconv.Itoa(features[i][j].ExtensionNum) + "\t")

				w.WriteString("\n")
			}
		}
		w.Flush()
		fHandle.Close()
		acti++
	}
	fmt.Printf("数据包总量: %d\n", sum)
}

func handShakeProcess(tls []byte, feature *packetFeature) {
	lengthH := tool.IntToUint(len(tls))
	var err error

	var j uint
	for j = 0; j < lengthH; {
		var handShakeType uint = 0
		handShakeType, err = tool.NetBytesToUint(tls[0:1], 1)
		if err != nil {
			log.Fatal("NetBytesToInt error")
		}
		feature.HandShakeType = append(feature.HandShakeType, handShakeType)
		var handShakeTypeLen uint = 0
		handShakeTypeLen, err = tool.NetBytesToUint(tls[j+1:j+4], 3)
		if handShakeTypeLen > lengthH-j-4 {
			return
		}
		if err != nil {
			log.Fatal("NetBytesToInt error")
		}
		if handShakeTypeLen <= 0 {
			break
		}
		j = j + 4 + handShakeTypeLen
		feature.HandShakeTypeLen = append(feature.HandShakeTypeLen, handShakeTypeLen)
		switch handShakeType {
		case 1:
			{
				var sessionLen uint = 0
				if handShakeTypeLen <= 39 {
					break
				}
				sessionLen, err = tool.NetBytesToUint(tls[38:39], 1)
				if handShakeTypeLen <= 41+sessionLen || sessionLen >= math.MaxUint-41 {
					break
				}
				var chiperSuitLen uint = 0
				chiperSuitLen, err = tool.NetBytesToUint(tls[39+sessionLen:41+sessionLen], 2)
				var extensionLen uint = 0
				if handShakeTypeLen <= 45+chiperSuitLen+sessionLen || chiperSuitLen+sessionLen >= math.MaxUint {
					break
				}
				extensionLen, err = tool.NetBytesToUint(tls[(43+chiperSuitLen+sessionLen):(45+chiperSuitLen+sessionLen)], 2)
				position := 45 + chiperSuitLen + sessionLen
				extensionNum := 0
				var i uint
				for i = 0; i < extensionLen; {
					var extensionType uint = 0
					if handShakeTypeLen <= position+2 {
						break
					}
					extensionType, err = tool.NetBytesToUint(tls[position:position+2], 2)
					var oneExtensionLen uint = 0
					switch extensionType {
					//servername
					case 0:
						oneExtensionLen, _ = tool.NetBytesToUint(tls[position+2:position+4], 2)
						servername, _ := tool.NetByteToString(tls[position+4+5:position+4+oneExtensionLen], int(oneExtensionLen))
						feature.Servername = servername
					default:
						oneExtensionLen, _ = tool.NetBytesToUint(tls[position+2:position+4], 2)
					}
					extensionNum++
					i = i + 4 + oneExtensionLen
					position = position + 4 + oneExtensionLen
				}
				feature.ExtensionNum = extensionNum
				if extensionNum != 0 {
					feature.ExtensionNum = 0
				}
			}
		}
	}
	feature.TransportLayer = 0
}

// 提取每一条双向流的特征
func extractFlowFeature(flow []packetFeature, fFeature *flowFeature) {
	length := len(flow)
	fFeature.Srcip = flow[0].SrcIP
	fFeature.Dstip = flow[0].DstIP
	fFeature.Srcport = flow[0].SrcPort
	fFeature.Dstport = flow[0].DstPort
	fFeature.TransportLayer = flow[0].TransportLayer
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

	//psh\urg数据包数量
	var pshNum int64 = 0
	var urgNum int64 = 0

	for i := 0; i < length; i++ {
		packetlen += int64(flow[i].LenPacket)
		headlen += int64(flow[i].LenPacket - flow[i].LenPayload)
		//计算上行时间间隔
		if uptime_pre.IsZero() {
			uppacketlen += int64(flow[i].LenPacket)
			upheadlen += int64(flow[i].LenPacket - flow[i].LenPayload)
			uptime_pre = flow[i].Timestamp
		} else if net.IP.Equal(flow[i].SrcIP, fFeature.Srcip) {
			uppacketlen += int64(flow[i].LenPacket)
			upheadlen += int64(flow[i].LenPacket - flow[i].LenPayload)
			uptime_count++
			one = flow[i].Timestamp.Sub(uptime_pre).Seconds()
			uptime_pre = flow[i].Timestamp
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
		if downtime_pre.IsZero() && net.IP.Equal(flow[i].SrcIP, fFeature.Dstip) {
			downpacketlen += int64(flow[i].LenPacket)
			downheadlen += int64(flow[i].LenPacket - flow[i].LenPayload)
			downtime_pre = flow[i].Timestamp
		} else if bytes.Equal(flow[i].SrcIP, fFeature.Dstip) {
			downpacketlen += int64(flow[i].LenPacket)
			downheadlen += int64(flow[i].LenPacket - flow[i].LenPayload)
			downtime_count++
			one = flow[i].Timestamp.Sub(downtime_pre).Seconds()
			downtime_pre = flow[i].Timestamp
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
			time_pre = flow[i].Timestamp
		} else {
			one = flow[i].Timestamp.Sub(time_pre).Seconds()
			time_pre = flow[i].Timestamp
			time_total += one
			time_var += math.Pow(one, 2)
			if one > time_max {
				time_max = one
			}
			if one < time_min {
				time_min = one
			}
		}
		if len(fFeature.Servername) == 0 && len(flow[i].Servername) != 0 {
			fFeature.Servername = flow[i].Servername
		}
		fFeature.ExtensionNum += flow[i].ExtensionNum

		if flow[i].Psh {
			pshNum++
		}
		if flow[i].Urg {
			urgNum++
		}
	}
	if uptime_min == math.MaxFloat64 {
		fFeature.Uptime_min = 0
	} else {
		fFeature.Uptime_min = uptime_min
	}
	fFeature.Uptime_max = uptime_max
	if uptime_count != 0 {
		fFeature.Uptime_mean = uptime_total / uptime_count
		fFeature.Uptime_std = uptime_var/uptime_count - math.Pow(fFeature.Uptime_mean, 2)
		fFeature.Uptime_std = math.Sqrt(fFeature.Uptime_std)
	}
	fFeature.Downtime_max = downtime_max
	if downtime_min == math.MaxFloat64 {
		fFeature.Downtime_min = 0
	} else {
		fFeature.Downtime_min = downtime_min
	}
	if downtime_count != 0 {
		fFeature.Downtime_mean = downtime_total / downtime_count
		fFeature.Downtime_std = downtime_var/downtime_count - math.Pow(fFeature.Downtime_mean, 2)
		fFeature.Downtime_std = math.Sqrt(fFeature.Downtime_std)
	}

	fFeature.Time_max = time_max
	fFeature.Time_min = time_min
	fFeature.Time_mean = time_total / float64(length-1)
	fFeature.Time_std = time_var/float64(length-1) - math.Pow(fFeature.Time_mean, 2)
	fFeature.Time_std = math.Sqrt(fFeature.Time_std)

	fFeature.Duration = flow[length-1].Timestamp.Sub(flow[0].Timestamp).Seconds()
	fFeature.Uppacketnum = int(math.Floor(uptime_count + 1))
	fFeature.Uppacketnum_minute = float64(fFeature.Uppacketnum) * 60 / fFeature.Duration
	fFeature.Downpacketnum = int(math.Floor(downtime_count + 1))
	fFeature.Downpacketnum_minute = float64(fFeature.Downpacketnum) * 60 / fFeature.Duration
	fFeature.Packetnum = length
	fFeature.Packetnum_minute = float64(fFeature.Packetnum) * 60 / fFeature.Duration
	if fFeature.Uppacketnum == 0 {
		fFeature.Downuppacket_percent = 0
	} else {
		fFeature.Downuppacket_percent = float64(fFeature.Downpacketnum) / float64(fFeature.Uppacketnum)
	}
	if upheadlen == 0 {
		fFeature.Uphead_percent = 0
	} else {
		fFeature.Uphead_percent = float64(upheadlen) / float64(uppacketlen)
	}
	if downpacketlen == 0 {
		fFeature.Downhead_percent = 0
	} else {
		fFeature.Downhead_percent = float64(downheadlen) / float64(downpacketlen)
	}
	fFeature.Psh = float64(pshNum) / float64(length)
	fFeature.Urg = float64(urgNum) / float64(length)
}

// 2022 datacon竞赛特征提取代码
func datacon(flow *[][]packetFeature) []dataconvar {
	result := make([]dataconvar, 0)
	var tmp dataconvar
	for i := 0; i < len(*flow); i++ {
		pktsrc := statistics.Int64{}
		pktdst := statistics.Int64{}
		for j := 0; j < len((*flow)[i]); j++ {
			if net.IP.Equal((*flow)[i][j].SrcIP, net.ParseIP("192.168.60.78")) {
				if (*flow)[i][j].LenPayload != 0 {
					pktsrc = append(pktsrc, (int64)((*flow)[i][j].LenPayload))
				}
			} else {
				if (*flow)[i][j].LenPayload != 0 {
					pktdst = append(pktdst, (int64)((*flow)[i][j].LenPayload))
				}
			}
		}
		tmp.varianceSrc = statistics.Variance(&pktsrc)
		tmp.varianceDst = statistics.Variance(&pktdst)
		if net.IP.Equal((*flow)[i][0].SrcIP, net.ParseIP("192.168.60.78")) {
			tmp.ip = (*flow)[i][0].DstIP
		} else {
			tmp.ip = (*flow)[i][0].SrcIP
		}
		result = append(result, tmp)
	}
	return result
}

func saveKafka(config CONFIG, features []flowFeature) {
	kafkaConfig := sarama.NewConfig()
	client, err := sarama.NewClient([]string{config.KafkaSource}, kafkaConfig)
	if err != nil {
		log.Fatal(err)
	}
	producer, err := sarama.NewAsyncProducerFromClient(client)
	if err != nil {
		log.Fatal(err)
	}
	defer producer.Close()

	type kafkaMessage struct {
		Name    string
		Feature flowFeature
	}

	var wg sync.WaitGroup
	for i := 0; i < len(features); i++ {
		wg.Add(1)
		go func(i0 int) {
			message := kafkaMessage{Name: "test", Feature: features[i0]}
			json, err := json.Marshal(message)
			if err != nil {
				log.Fatal(err)
			}
			producer.Input() <- &sarama.ProducerMessage{
				Topic: config.KafkaTopic,
				Key:   nil,
				/*Value: sarama.StringEncoder(*(*string)(unsafe.Pointer(&json)))*/
				Value: sarama.ByteEncoder(json),
			}
		}(i)
	}
	wg.Wait()
}
