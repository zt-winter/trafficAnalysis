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
	lenIP uint8
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
	flows := make([][]gopacket.Packet, 0) 
	packetsToFlow(packets, &flows)
	for i := 0; i < len(flows); i++ {
		for j := range flows[i] {
			packetFeature(flows[i][j])
		}
	}
}

func packetsToFlow(packets chan gopacket.Packet, flows *[][]gopacket.Packet) {
	flowsMap := make(map[gopacket.Endpoint]int)
	var number int = 0
	for packet := range packets {
		if ip := packet.Layer(layers.LayerTypeIPv4); ip != nil {
			ip, _ := ip.(*layers.IPv4)
			if value, ok := flowsMap[ip.NetworkFlow().Dst()]; ok {
				(*flows)[value] = append((*flows)[value], packet)
			} else {
				flowsMap[ip.NetworkFlow().Dst()] = number
				one := []gopacket.Packet{packet}
				*flows = append(*flows, one)
				number = number + 1
			}
			fmt.Println("success")
		}
	}
}

func packetFeature(packet gopacket.Packet) {
	var feature PacketFeature
	feature.lenPacket = len(packet.Data())
	//ip层字段提取
	ipLayer := packet.Layer(layers.LayerTypeIPv4)
	ip, _ := ipLayer.(*layers.IPv4)
	if ip!= nil {
		feature.srcIP = ip.SrcIP.String()
		feature.dstIP = ip.DstIP.String()
		feature.ttl = ip.TTL
		feature.lenIP = ip.IHL
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
	if feature.srcIP != "192.168.11.206" {
		feature.lenPayload = - feature.lenPayload
	}
}

