package extract

import (
	"bufio"
	"strconv"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"

	//"github.com/go-echarts/go-echarts/v2/charts"
	//"github.com/go-echarts/go-echarts/v2/opts"
	"fmt"
	"log"
	"math"
	"os"
)
type FlowFeature struct {
	srcIP string
	dstIP string
	srcPort string
	dstPort string
	meanPacketLength float64
	varPacketLength float64
	meanTTL int
	meanTimeInterval float64
	duration float64
	packetLengthSequence []int
}


type PacketFeature struct {
	//
	lenPacket int
	//ip
	srcIP string
	dstIP string
	flag uint8
	ttl uint8
	//tcp
	srcPort uint16
	dstPort uint16
	seq uint32
	ack uint32
	win uint16
	lenPayload int
}		

//按制定筛选规则，过滤流量，并提取流量中特征
func ExtractFeature(pcapname string, filter string){
		handle, err := pcap.OpenOffline(pcapname)
	if err != nil {
		log.Fatal(err)
	}
	err = handle.SetBPFFilter(filter)
	if err != nil {
		log.Fatal(err)
	}

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	packets := packetSource.Packets()
	flows := make([][]PacketFeature, 0) 
	for packet := range packets {
		pFeature := packetFeature(packet)
		packetsToFlow(pFeature, &flows)
	}
	fmt.Println(len(flows))
	fFeatures := make([]FlowFeature, len(flows))
	for i := 0; i < len(flows); i++ {
		flowFeature(&flows[i], &fFeatures[i])
	}
	/*
	packetsToFlow(packets, &flows)
	for i := 0; i < len(flows); i++ {
		for j := range flows[i] {
			packetFeature(flows[i][j])
		}
	}
	*/
}

// 按照四元组比较两个数据包是否是同一条双向流
func fourTupleEqual(a PacketFeature, b PacketFeature) bool {
	if a.srcIP == b.srcIP && a.dstIP == b.dstIP && 
		a.srcPort == b.srcPort && a.dstPort == b.dstPort {
		return true
	} else if a.srcIP == b.dstIP && a.dstIP == b.srcIP && 
		a.srcPort == b.dstPort && a.dstPort == b.srcPort {
		return true
	} else {
		return false
	}
}

// 根据数据包的四元组，将数据包分成流
func packetsToFlow(pFeature PacketFeature, flows *[][]PacketFeature) {
	f, err := os.OpenFile("/home/zt/code/go/trafficAnalysis/extract/log", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0666)
	if err != nil {
		log.Fatal(err)
		fmt.Println("sdfag")
	}
	defer f.Close()
	w := bufio.NewWriter(f)
	length := len(*flows)
	fmt.Println(len(*flows))
	if length == 0 {
		one := []PacketFeature{pFeature}
		*flows = append(*flows, one)
		w.WriteString("当前无数据，创建新的流")
		w.WriteString(strconv.Itoa(len(*flows)))
		w.WriteString("\n")
	}else{
		for i := 0; i < length; i++ {
			if equal := fourTupleEqual(pFeature, (*flows)[i][0]); equal {
				(*flows)[i] = append((*flows)[i], pFeature)
				w.WriteString("添加到对应的流中: ")
				w.WriteString(strconv.Itoa(i))
				w.WriteString("\t当前的总共有多少条流: ")
				w.WriteString(strconv.Itoa(len(*flows)))
				w.WriteString("\n")
				w.Flush()
				return 
			} 
		}
		one := []PacketFeature{pFeature}
		*flows = append(*flows, one)
		w.WriteString("没有对应的流，创建新的流")
		w.WriteString(strconv.Itoa(len(*flows)))
		w.WriteString("\n")
		w.Flush()
		return 
	}
	w.Flush()
}

// 提取数据包的基本特征
func packetFeature(packet gopacket.Packet) PacketFeature {
	var feature PacketFeature
	feature.lenPacket = len(packet.Data())
	//ip层字段提取
	ipLayer := packet.Layer(layers.LayerTypeIPv4)
	ip, _ := ipLayer.(*layers.IPv4)
	if ip!= nil {
		feature.srcIP = ip.SrcIP.String()
		feature.dstIP = ip.DstIP.String()
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
	return feature
}

// 提取每一条双向流的特征
func flowFeature(flow *[]PacketFeature, fFeature *FlowFeature) {
	length := len(*flow)
	//获取平均包大小
	var packetSize uint64
	for i := 0; i < length; i++ {
		packetSize = packetSize + uint64((*flow)[i].lenPacket)
	}
	//meanPacketLength := float64(packetSize/uint64(length))

	//获取包方差
	var varPacketLength float64
	for i := 0; i < length; i++ {
		varPacketLength = math.Pow(float64((*flow)[i].lenPacket), 2)
	}
	varPacketLength = varPacketLength/float64(length)
	/*
	fmt.Println(length)
	fmt.Println((*flow)[0].srcIP, "\t", (*flow)[0].dstIP)
	fmt.Println(meanPacketLength)
	fmt.Println(varPacketLength)
	fmt.Println("")
	*/
}
