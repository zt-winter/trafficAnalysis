package main

import (
	"fmt"
	"log"
	"net"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

var (
	device string = "enp42s0"
	snapshot_len int32 = 1024
	promiscous bool = false
	err error
	timeout time.Duration = 30 * time.Second
	handle *pcap.Handle
	buffer gopacket.SerializeBuffer
	options gopacket.SerializeOptions
)

func main() {
	//获取目标内容
	fHandle, err := pcap.OpenOffline("/home/zt/data/3.26/login.pcap")
	if err != nil {
		log.Fatal(err)
	}
	packetSource := gopacket.NewPacketSource(fHandle, fHandle.LinkType())
	packets := packetSource.Packets()
	packet := <-packets
	tcpLayer := packet.Layer(layers.LayerTypeTCP)
	if tcpLayer != nil {
		fmt.Println(string(tcpLayer.LayerPayload()))
	}

	// open device
	handle, err = pcap.OpenLive(device, snapshot_len, promiscous, timeout)  
	if err != nil {
		defer handle.Close()
	}

	_, err = net.Dial("tcp", "www.baidu.com:80")
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println("connect success")
}
