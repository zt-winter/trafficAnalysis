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
	conn net.Conn
	timeout time.Duration = 30 * time.Second
	handle *pcap.Handle
	buffer gopacket.SerializeBuffer
	options gopacket.SerializeOptions
)

func main() {
	//建立链接
	conn, err = net.Dial("tcp", "51.178.36.149:13333")
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println("connect sucess")

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
	content := tcpLayer.LayerPayload()
	
	_, err = conn.Write(content) 
	if err != nil {
		log.Fatal(err)
		conn.Close()
	}
	buf := make([]byte, 1024)
	_, err = conn.Read(buf)
	conn.Close()
	fmt.Println(string(buf))
}
