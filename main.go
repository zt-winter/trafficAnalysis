package main

import(
	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
	"github.com/google/gopacket/layers"
	"github.com/go-echarts/go-echarts/v2/charts"
	"github.com/go-echarts/go-echarts/v2/opts"
	"log"
	"fmt"
	"os"
)
type Feature struct {
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

func main() {
	//open a pcap file
	handle, err := pcap.OpenOffline("/home/zt/normal.pcap")
	if err != nil {
		log.Fatal(err)
	}

	// set filter
	var filter string = "host 192.168.11.206"
	err = handle.SetBPFFilter(filter)
	if err != nil {
		log.Fatal(err)
	}

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	packets := packetSource.Packets()
/*
	//test
	for i := 0; i < 5; i++ {
		packet := <- packets
		tcpLayer := packet.Layer(layers.LayerTypeTCP)
		fmt.Println(tcpLayer)
		fmt.Println("length: ", len(tcpLayer.LayerPayload()))
		fmt.Println("\n")
	}
*/
/*
	var features []Feature
	for packet := range packets {
		fmt.Println(reflect.TypeOf(packet))
		features = append(features, packetFeature(packet))
	}
*/
	var features []Feature
	var packet gopacket.Packet
	for i := 0; i < 1000; i++ {
		packet = <- packets
		features = append(features, packetFeature(packet))
	}

	//包长累计变化图
	bar := charts.NewBar()
	bar.SetGlobalOptions(charts.WithTitleOpts(opts.Title{
		Title:		"包长分布图",
	}))
	bar.SetXAxis([]string{"0~50", "50~100", "100~150", "150~200", "200~250", "250~300", "300~350", "350~400", "400~450", "450~500"," <500"}).
		AddSeries("SSH-(aes-gcm-256)-xmr", generateItem(features))
	f, _ := os.Create("bar.html")
	bar.Render(f)
	//包长分布图
		
}

func packetFeature(packet gopacket.Packet) Feature {
	var feature Feature
	fmt.Println(len(packet.Data()))
	feature.lenPacket = len(packet.Data())
	//ip层字段提取
	ipLayer := packet.Layer(layers.LayerTypeIPv4)
	ip, _ := ipLayer.(*layers.IPv4)
	if ip!= nil {
		feature.srcIP = ip.SrcIP.String()
		feature.dstIP = ip.DstIP.String()
		feature.ttl = ip.TTL
		feature.lenIP = ip.IHL
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
	}
	fmt.Println(feature.srcIP)
	if feature.srcIP != "192.168.11.206" {
		feature.lenPayload = - feature.lenPayload
	}
	return feature
}

func generateItem(features []Feature) []opts.BarData {
	items := make([]opts.BarData, 0)
	nums := make([]int, 11)
	for i := 0; i < 11; i++ {
		nums[i] = 0
	}
	var length int
	for i := 0; i < 1000; i++ {
		length = features[i].lenPacket
		switch {
			case length <= 50:
				nums[0] = nums[0] + 1
			case length > 50 && length <= 100:
				nums[1] = nums[1] + 1
			case length > 100 && length <= 150:
				nums[2] = nums[2] + 1
			case length > 150 && length <= 200:
				nums[3] = nums[3] + 1
			case length > 200 && length <= 250:
				nums[4] = nums[4] + 1
			case length > 250 && length <= 300:
				nums[5] = nums[5] + 1
			case length > 300 && length <= 350:
				nums[6] = nums[6] + 1
			case length > 350 && length <= 400:
				nums[7] = nums[7] + 1
			case length > 400 && length <= 450:
				nums[8] = nums[8] + 1
			case length > 450 && length <= 500:
				nums[9] = nums[9] + 1
			case length > 500:
				nums[10] = nums[10] + 1
			default:
		}
	}
	for i := 0; i < 11; i++ {
		items = append(items, opts.BarData{Value: nums[i]})
	}
	return items
}
