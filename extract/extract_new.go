package extract

import (
	"bufio"
	"fmt"
	"log"
	"math"
	"net"
	"os"
	"strconv"
	"time"
	"trafficAnalysis/config"
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
	//tcp
	srcPort uint16
	dstPort uint16
	seq uint32
	ack uint32
	win uint16
	lenPayload int
	//tls
	tlsVersion int
	tlsType int
	handShakeType []int
	handShakeTypeLen []int
	servername string
	data int
}


//按制定筛选规则，过滤流量，并提取流量中特征
func ExtractFeature(config config.CONFIG) ([][]packetFeature, []FlowFeature) {
	var packetSource *gopacket.PacketSource	

	//根据配置文件选择在线解析或者离线解析
	//打开pcap数据包
	if config.Method == "offline" {
		handle, err := pcap.OpenOffline(config.PacpFile)
		if err != nil {
			log.Fatal(err)
		}
		err = handle.SetBPFFilter(config.Filter)
		if err != nil {
			log.Fatal(err)
		}
		packetSource = gopacket.NewPacketSource(handle, handle.LinkType())
	}
	//打开网口
	if config.Method == "online" {
		handle, err := pcap.OpenLive(config.Device, 2048, true, 30*time.Second)
		if err != nil {
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
	flows := make([][]packetFeature, 0) 
	mapAddress := make(map[string]int)

	//遍历数据包，对每个数据包做解析

	test := 1
	for packet := range packets {
		fmt.Println(test)
		pFeature := extractPacketFeature(packet)
		packetsToFlow(pFeature, mapAddress, &flows)
		test = test + 1
		fmt.Println()
	}

	fFeatures := make([]FlowFeature, len(flows))
	for i := 0; i < len(flows); i++ {
		go flowFeature(&flows[i], &fFeatures[i])
	}

	//解析后的结果保存到feature下对应的文件目录
	featureFile, err := os.OpenFile(config.FeatureFile, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0666)
	if err != nil {
		log.Fatal(err)
	}
	saveFeature(featureFile, &flows)
	

	return flows, fFeatures
}

// 根据数据包的四元组，将数据包分成流
func packetsToFlow(pFeature packetFeature, mapAddress map[string]int,flows *[][]packetFeature) {
	newAddress := tool.CombineIPPort(pFeature.srcIP, pFeature.srcPort, pFeature.dstIP, pFeature.dstPort)
	value := tool.SearchAddress(newAddress, mapAddress)
	if value == -1 {
		oneFlow := []packetFeature{pFeature}
		(*flows) = append((*flows), oneFlow)
		nums := len(*flows)
		mapAddress[string(newAddress)] = nums-1
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
	if ip!= nil {
		feature.srcIP = ip.SrcIP
		feature.dstIP = ip.DstIP
		feature.ttl = ip.TTL
	} else {
		log.Fatal(ip)
	}

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
		lengthH, err = tool.NetBytesToInt(tls[oneLayerLen+3:oneLayerLen+5], 2)
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

func saveFeature(file *os.File, features *[][]packetFeature) {
	defer file.Close()
	w := bufio.NewWriter(file)
	for i := 0; i < len(*features); i++ {
		for j := 0; j < len((*features)[i]); j++ {
			w.WriteString((*features)[i][j].srcIP.String() + "\t")
			w.WriteString((*features)[i][j].dstIP.String() + "\t")
			w.WriteString(strconv.Itoa((*features)[i][j].lenPacket) + "\t")
			w.WriteString(strconv.Itoa((*features)[i][j].lenPayload) + "\n")
		}
	}
	w.Flush()
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
			fmt.Println(len(feature.servername))
		}
		}
	}
}
