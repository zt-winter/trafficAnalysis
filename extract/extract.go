package extract

import(
	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
	"github.com/google/gopacket/layers"
	//"github.com/go-echarts/go-echarts/v2/charts"
	//"github.com/go-echarts/go-echarts/v2/opts"
	"log"
	"fmt"
	//"os"
)
type FlowFeature struct {
	srcIP string
	dstIP string
	srcPort string
	dstPort string
	meanPacketLength float64
	variancePacketLength float64
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
	/*
	packetsToFlow(packets, &flows)
	for i := 0; i < len(flows); i++ {
		for j := range flows[i] {
			packetFeature(flows[i][j])
		}
	}
	*/
}

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

func packetsToFlow(pFeature PacketFeature, flows *[][]PacketFeature) {
	length := len(*flows)
	if length == 0 {
		one := []PacketFeature{pFeature}
		*flows = append(*flows, one)
		fmt.Println("创建新的流")
	}else{
		for i := 0; i < length; i++ {
			if equal := fourTupleEqual(pFeature, (*flows)[i][0]); equal {
				(*flows)[i] = append((*flows)[i], pFeature)
				fmt.Println("添加到已有流中")
				return 
			}
		}
		one := []PacketFeature{pFeature}
		*flows = append(*flows, one)
		fmt.Println("创建新的流")
	}
}

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
