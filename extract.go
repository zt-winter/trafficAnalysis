package main

import (
	"bufio"
	"fmt"
	"log"
	"math"
	"net"
	"os"
	"strconv"
	"time"
	"trafficAnalysis/tool"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

type FlowFeature struct {
	cIP string
	sIP string
	cPort net.IP
	sPort net.IP
	meanPacketLength float64
	varPacketLength float64
	meanTTL int
	meanTimeInterval float64
	duration float64

	packetLengthSequence []int
	cipher []layers.TLSChangeCipherSpecRecord
	handShake []layers.TLSHandshakeRecord
}


type packetFeature struct {
	timestamp time.Time
	lenPacket int
	//ip
	srcIP net.IP
	dstIP net.IP
	flag uint8
	ttl uint8
	//transport
	srcPort uint16
	dstPort uint16
	lenPayload int
	// tcp
	seq uint32
	ack uint32
	win uint16
	//tls
	tlsVersion int
	tlsType int
	handShakeType []int
	handShakeTypeLen []int
	servername string
	data int
}


//按制定筛选规则，过滤流量，并提取流量中特征
func extractFeature(config CONFIG, file string) ([][]packetFeature, []FlowFeature) {
	var packetSource *gopacket.PacketSource	

	//根据配置文件选择在线解析或者离线解析
	//打开pcap数据包
	if config.Method == "offline" {
		handle, err := pcap.OpenOffline(config.PacpFileDir+file)
		if err != nil {
			fmt.Println("open pcapfile error")
			log.Fatal(err)
		} else {
			fmt.Println("open file success\n")
		}
		err = handle.SetBPFFilter(config.Filter)
		if err != nil {
			fmt.Println("setbpffilter error")
			log.Fatal(err)
		} else {
			fmt.Printf("setbpffilter success\n")
		}
		packetSource = gopacket.NewPacketSource(handle, handle.LinkType())
	} else if config.Method == "online" {
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
	}

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
		fmt.Println(packet)
		pFeature := extractPacketFeature(packet)
		packetsToFlow(pFeature, mapAddress, &flows)
		test = test + 1
	}
	fFeatures := make([]FlowFeature, len(flows))
	for i := 0; i < len(flows); i++ {
		flowFeature(&flows[i], &fFeatures[i])
	}
	fmt.Println(len(flows))
	//解析后的结果保存到feature下对应的文件目录
	saveFeature(config, file, &flows)
	

	return flows, fFeatures
}

// 根据数据包的四元组，将数据包分成流
func packetsToFlow(pFeature packetFeature, mapAddress map[string]int,flows *[][]packetFeature) {
	one := new(packetFeature)
	one.srcIP = pFeature.srcIP
	one.dstIP = pFeature.dstIP
	one.srcPort = pFeature.srcPort
	one.dstPort = pFeature.dstPort
	newAddress := tool.CombineIP(one.srcIP, one.dstIP)
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
		feature.srcIP = ip.SrcIP
		feature.dstIP = ip.DstIP
		feature.ttl = ip.TTL
	} else {
		log.Fatal(ip)
	}
	fmt.Println(transportLayer)
	if transportLayer == layers.LayerTypeTCP {
		//tcp层字段提取
		tcpLayer := packet.Layer(layers.LayerTypeTCP)
		tcp, _ := tcpLayer.(*layers.TCP)
		if tcp != nil {
			feature.srcPort = (uint16)(tcp.SrcPort)
			feature.dstPort = (uint16)(tcp.DstPort)
			feature.seq = tcp.Seq
			feature.ack = tcp.Ack
			feature.win = tcp.Window
			feature.lenPayload = len(tcp.LayerPayload())
		} else {
			log.Fatal(tcp)
		}

		//tls层字段提取
		tls := tcp.Payload
		var err error
		totoalLen := len(tls)

		if len(tls) < 6 {
			return feature
		}
		ressemableUDP := false
		for oneLayerLen := 0; oneLayerLen < totoalLen; {
			lengthH := 0
			if oneLayerLen+5 > totoalLen || oneLayerLen < 0 {
				break
			}
			lengthH, err = tool.NetBytesToInt(tls[oneLayerLen+3:oneLayerLen+5], 2)
			if err != nil {
				break
			}
			if lengthH > totoalLen {
				break
			}
			if oneLayerLen + lengthH + 5 > totoalLen {
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
		//udp字段提取
		udpLayer := packet.Layer(layers.LayerTypeUDP)
		udp, _ := udpLayer.(*layers.UDP)
		if udp != nil {
			feature.srcPort = (uint16)(udp.SrcPort)
			feature.dstPort = (uint16)(udp.DstPort)
			feature.lenPacket = len(udp.LayerPayload())
		} else {
			log.Fatal(udp)
		}
	}
	return feature
}

// 提取每一条双向流的特征
func flowFeature(flow *[]packetFeature, fFeature *FlowFeature) {
	length := len(*flow)

	//获取平均包大小
	//获取包方差
	var packetSize uint64
	var varPacketLength float64
	for i := 0; i < length; i++ {
		packetSize = packetSize + uint64((*flow)[i].lenPacket)
		varPacketLength = math.Pow(float64((*flow)[i].lenPacket), 2)
	}
	meanPacketLength := float64(packetSize/uint64(length))
	varPacketLength = varPacketLength/float64(length)
	varPacketLength = meanPacketLength

	
}

func saveFeature(config CONFIG, file string, features *[][]packetFeature) {
	sum := 0
	fmt.Printf("流的种类: %d\n", len(*features))
	for i := 0; i < len(*features); i++ {
		sum += len((*features)[i])
		saveFile := config.SaveFileDir + file
		fHandle, err := os.OpenFile(saveFile + strconv.Itoa(i) + ".txt", os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0666)
		if err != nil {
			fmt.Println("saveFeature file error")
		}
		defer fHandle.Close()
		w := bufio.NewWriter(fHandle)
		for j := 0; j < len((*features)[i]); j++ {
			if (*features)[i][j].lenPayload != 0 {
				time := (*features)[i][j].timestamp
				if j == 0 {
					one := time.Sub(time)
					w.WriteString(strconv.FormatFloat(one.Seconds(), 'f', 4, 64) + "\t")
				} else if j > 0 {
					w.WriteString(strconv.FormatFloat(time.Sub((*features)[i][j-1].timestamp).Seconds(), 'f', 4, 64) + "\t")
				}
				w.WriteString(strconv.Itoa((*features)[i][j].lenPayload) + "\n")
			}
		}
		w.Flush()
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
				default:
					oneExtensionLen, _ = tool.NetBytesToInt(tls[position+2:position+4], 2)
				}
				extensionNum++
				i = i + 4 + oneExtensionLen
				position = position + 4 + oneExtensionLen
			}
		}
		}
	}
}
